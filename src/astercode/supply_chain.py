"""Reproducible, evidence-bounded container supply-chain checks.

The workflow is deliberately separate from ``doctor``.  Detection of a local
binary is not proof that an SBOM was generated, a vulnerability policy passed,
or a trusted signer was verified.  Syft and Trivy are forced to the local
Docker daemon; Trivy database network access is opt-in and every retained
artifact is hashed.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import tempfile
import time
import tomllib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .config import (
    ConfigError,
    ProcessSecurityConfig,
    _normalise_legacy_config,
    load_config,
    validate_strict_project_file,
    validate_strict_workspace_root,
)
from .security import PathAuthorizationError, canonicalize_authorized_path
from .tools.docker_process import (
    DockerSandboxUnavailable,
    _resolve_local_image,
    discover_trusted_docker,
    discover_trusted_image_tool,
)
from .tools.git import GitTools

EvidenceStatus = Literal["passed", "failed", "blocked", "not_verified"]

_ALL_SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_TRIVY_DB_REPOSITORIES = (
    "mirror.gcr.io/aquasec/trivy-db:2",
    "ghcr.io/aquasecurity/trivy-db:2",
)
_MAX_JSON_BYTES = 134_217_728
_MAX_LOG_BYTES = 1_048_576
_MAX_TRIVY_DB_BYTES = 2_147_483_648


class EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CommandEvidence(EvidenceModel):
    argv: list[str]
    exit_code: int | None
    elapsed_seconds: float
    stdout_log: str
    stderr_log: str
    error: str | None = None


class ToolSnapshot(EvidenceModel):
    detected: bool
    executable: str | None = None
    binary_sha256: str | None = None
    version: str | None = None
    version_command: CommandEvidence | None = None
    binary_sha256_before: str | None = None
    binary_sha256_after: str | None = None
    binary_stable: bool = True
    provenance: str = "fixed_location_snapshot_only"


class SbomEvidence(EvidenceModel):
    status: EvidenceStatus
    reason: str
    command: CommandEvidence | None = None
    package_count: int | None = None
    source_digest_bound: bool = False
    spdx_digest_bound: bool = False
    artifacts: dict[str, str] = Field(default_factory=dict)
    artifact_sha256: dict[str, str] = Field(default_factory=dict)


class TrivyDatabaseEvidence(EvidenceModel):
    status: EvidenceStatus
    reason: str
    cache_path: str
    repositories: list[str]
    updated_at: str | None = None
    downloaded_at: str | None = None
    next_update: str | None = None
    age_hours: float | None = None
    max_age_hours: float
    metadata_version: int | None = None
    metadata_sha256: str | None = None
    database_sha256: str | None = None
    database_size_bytes: int | None = None
    provenance_verified: bool = False
    integrity_status: Literal["not_checked", "inventory_only"] = "not_checked"
    update_command: CommandEvidence | None = None


class VulnerabilityEvidence(EvidenceModel):
    status: EvidenceStatus
    reason: str
    command: CommandEvidence | None = None
    database: TrivyDatabaseEvidence
    severities: list[str]
    fail_severities: list[str]
    ignore_unfixed: bool = False
    counts: dict[str, int] = Field(default_factory=dict)
    os_eol: bool | None = None
    image_digest_bound: bool = False
    artifact: str | None = None
    artifact_sha256: str | None = None


class SignatureEvidence(EvidenceModel):
    status: Literal["not_verified"] = "not_verified"
    reason: str
    trust_mode: Literal["none"] = "none"
    identity: str | None = None
    issuer: str | None = None
    key_sha256: str | None = None
    transparency_log_verified: bool = False


class SupplyChainClaims(EvidenceModel):
    content_pinned: bool = False
    sbom_generated: bool = False
    vulnerability_policy_passed: bool = False
    signature_verified: bool = False


class SupplyChainManifest(EvidenceModel):
    schema_version: int = 1
    generated_at: str
    target_commit: str
    working_tree_clean: bool
    version: str
    platform: str
    config_file: str | None = None
    config_sha256: str | None = None
    configured_image: str
    resolved_image_digest: str | None = None
    image_id: str | None = None
    overall_status: Literal["passed", "partial", "failed", "blocked"]
    tools: dict[str, ToolSnapshot]
    sbom: SbomEvidence
    vulnerability_scan: VulnerabilityEvidence
    signature: SignatureEvidence
    claims: SupplyChainClaims
    limitations: list[str]


@dataclass(frozen=True, slots=True)
class SupplyChainRun:
    manifest: SupplyChainManifest
    directory: Path
    manifest_path: Path
    checksums_path: Path
    exit_code: int


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1_048_576), b""):
            digest.update(block)
    return digest.hexdigest()


def _private_mkdir(path: Path, *, parents: bool = False) -> None:
    path.mkdir(parents=parents, exist_ok=False)
    if os.name != "nt":
        path.chmod(0o700)


def _private_file(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o600)


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _private_file(path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _atomic_write_json(path: Path, payload: BaseModel | dict[str, Any]) -> None:
    data = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
    encoded = (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(path, encoded)


def _relative(run_directory: Path, path: Path) -> str:
    return path.relative_to(run_directory).as_posix()


def _truncate_log(path: Path, *, limit: int = _MAX_LOG_BYTES) -> None:
    size = path.stat().st_size
    if size <= limit:
        return
    half = max(1, (limit - 128) // 2)
    with path.open("rb") as stream:
        prefix = stream.read(half)
        stream.seek(max(0, size - half))
        suffix = stream.read(half)
    marker = f"\n...[truncated {size - len(prefix) - len(suffix)} bytes]...\n".encode()
    _atomic_write(path, prefix + marker + suffix)


def _tool_environment(control_directory: Path) -> dict[str, str]:
    """Build a small environment without credentials, proxies or tool overrides."""

    temporary = control_directory / "temp"
    temporary.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        temporary.chmod(0o700)
    environment: dict[str, str] = {}
    if os.name == "nt":
        try:
            import ctypes

            windll = getattr(ctypes, "windll", None)
            if windll is not None:
                buffer = ctypes.create_unicode_buffer(32_768)
                length = windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
                if isinstance(length, int) and 0 < length < len(buffer):
                    system_root = Path(buffer.value)
                    if system_root.is_absolute():
                        environment["SystemRoot"] = str(system_root)
                        environment["WINDIR"] = str(system_root)
                        environment["SystemDrive"] = system_root.drive
        except (AttributeError, OSError, ValueError):
            pass
    home = control_directory / "home"
    config_home = control_directory / "config"
    cache_home = control_directory / "cache"
    for directory in (home, config_home, cache_home):
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            directory.chmod(0o700)
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "XDG_CONFIG_HOME": str(config_home),
            "XDG_CACHE_HOME": str(cache_home),
            "PATH": "",
            "NO_COLOR": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
        }
    )
    return environment


def _run_logged(
    run_directory: Path,
    label: str,
    argv: list[str],
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout: float,
) -> CommandEvidence:
    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", label) is None:
        raise ValueError("invalid evidence command label")
    logs = run_directory / "logs"
    if not logs.exists():
        _private_mkdir(logs)
    elif logs.is_symlink() or bool(getattr(logs, "is_junction", lambda: False)()) or not logs.is_dir():
        raise ValueError("evidence logs path is not a private directory")
    stdout_path = logs / f"{label}.stdout.txt"
    stderr_path = logs / f"{label}.stderr.txt"
    started = time.perf_counter()
    exit_code: int | None = None
    error: str | None = None
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            creationflags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt"
                else 0
            )
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=environment,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                error = f"command exceeded {timeout:.1f} seconds"
                if os.name != "nt":
                    killpg = getattr(os, "killpg", None)
                    sigkill = getattr(signal, "SIGKILL", None)
                    if callable(killpg) and sigkill is not None:
                        try:
                            killpg(process.pid, sigkill)
                        except (OSError, ProcessLookupError):
                            process.kill()
                    else:
                        process.kill()
                else:
                    # Prefer the OS tree terminator so a tool cannot leave a
                    # downloader/helper child behind after the evidence timeout.
                    system_root = environment.get("SystemRoot")
                    taskkill = (
                        Path(system_root) / "System32" / "taskkill.exe"
                        if system_root
                        else None
                    )
                    if taskkill is not None and taskkill.is_file():
                        try:
                            subprocess.run(
                                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                check=False,
                                timeout=5.0,
                                env=environment,
                            )
                        except (OSError, subprocess.TimeoutExpired):
                            process.kill()
                    else:
                        process.kill()
                process.wait(timeout=min(5.0, max(1.0, timeout)))
            exit_code = process.returncode
    except subprocess.TimeoutExpired:
        error = f"command exceeded {timeout:.1f} seconds"
        exit_code = None
    except OSError as exc:
        error = f"command launch failed ({type(exc).__name__})"
        stdout_path.touch(exist_ok=True)
        stderr_path.touch(exist_ok=True)
    elapsed = round(time.perf_counter() - started, 3)
    _truncate_log(stdout_path)
    _truncate_log(stderr_path)
    return CommandEvidence(
        argv=argv,
        exit_code=exit_code,
        elapsed_seconds=elapsed,
        stdout_log=_relative(run_directory, stdout_path),
        stderr_log=_relative(run_directory, stderr_path),
        error=error,
    )


def _read_log(run_directory: Path, relative: str) -> str:
    return (run_directory / relative).read_text(encoding="utf-8", errors="replace")


def _snapshot_tool(
    run_directory: Path,
    name: str,
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout: float,
) -> ToolSnapshot:
    executable = discover_trusted_image_tool(name)
    if executable is None:
        return ToolSnapshot(detected=False)
    try:
        hash_before = _sha256_file(executable)
    except OSError as exc:
        return ToolSnapshot(
            detected=True,
            executable=str(executable),
            binary_stable=False,
            provenance=f"fixed_location_snapshot_failed:{type(exc).__name__}",
        )
    suffix = ["--version"] if name == "trivy" else ["version"]
    command = _run_logged(
        run_directory,
        f"{name}-version",
        [str(executable), *suffix],
        environment=environment,
        cwd=cwd,
        timeout=min(timeout, 30.0),
    )
    version = None
    if command.exit_code == 0:
        version_output = _read_log(run_directory, command.stdout_log).strip()
        if not version_output:
            version_output = _read_log(run_directory, command.stderr_log).strip()
        version = version_output[:8_192] or None
    try:
        hash_after = _sha256_file(executable)
    except OSError:
        hash_after = None
    stable = hash_after is not None and hash_before == hash_after
    if not stable:
        command = command.model_copy(
            update={
                "error": "tool executable changed while its version was inspected"
            }
        )
    return ToolSnapshot(
        detected=True,
        executable=str(executable),
        binary_sha256=hash_after or hash_before,
        version=version,
        version_command=command,
        binary_sha256_before=hash_before,
        binary_sha256_after=hash_after,
        binary_stable=stable,
    )


def _load_bounded_json(path: Path) -> Any:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink() or bool(getattr(absolute, "is_junction", lambda: False)()):
        raise ValueError("JSON artifact cannot be a link or reparse point")
    try:
        resolved = absolute.resolve(strict=True)
        stat = absolute.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("JSON artifact cannot be inspected") from exc
    if resolved != absolute or not absolute.is_file() or stat.st_nlink != 1:
        raise ValueError("JSON artifact must be an independent regular file")
    size = stat.st_size
    if size <= 0 or size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact size is outside 1..{_MAX_JSON_BYTES} bytes")
    with path.open("r", encoding="utf-8", errors="strict") as stream:
        return json.load(stream)


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def _reference_has_digest(value: Any, expected_digest: str) -> bool:
    if not isinstance(value, str) or not expected_digest:
        return False
    candidate = value
    return candidate == expected_digest or (
        "@" in candidate and candidate.rsplit("@", 1)[1] == expected_digest
    )


def _parse_syft_report(payload: Any, expected_digest: str) -> tuple[int, bool]:
    if _DIGEST_RE.fullmatch(expected_digest) is None:
        raise ValueError("expected image digest is invalid")
    if not isinstance(payload, dict):
        raise ValueError("Syft report is not a JSON object")
    artifacts = payload.get("artifacts")
    source = payload.get("source")
    if not isinstance(artifacts, list) or not isinstance(source, dict):
        raise ValueError("Syft report is missing artifacts or source metadata")
    if any(not isinstance(artifact, dict) for artifact in artifacts):
        raise ValueError("Syft report contains a malformed artifact entry")
    if source.get("type") != "image":
        raise ValueError("Syft report source is not a Docker image")
    # Syft's ``source.version`` is the repository digest supplied to the
    # Docker source.  ``source.metadata.manifestDigest`` is a different
    # Docker manifest identity for some engines, so it must not be compared to
    # the configured RepoDigest here.
    digest_bound = _reference_has_digest(source.get("version"), expected_digest)
    if not digest_bound:
        raise ValueError("Syft report is not bound to the expected image digest")
    return len(artifacts), digest_bound


def _parse_spdx_report(
    payload: Any,
    *,
    expected_digest: str,
    expected_reference: str,
) -> bool:
    if _DIGEST_RE.fullmatch(expected_digest) is None:
        raise ValueError("expected image digest is invalid")
    if not isinstance(payload, dict):
        raise ValueError("Syft SPDX report is not a JSON object")
    if not str(payload.get("spdxVersion", "")).startswith("SPDX-"):
        raise ValueError("Syft SPDX artifact is missing a valid SPDX version")
    if payload.get("name") != expected_reference:
        raise ValueError("Syft SPDX artifact is not bound to the configured image reference")
    # SPDX 2.x does not standardise a digest field.  The command supplies the
    # exact reference through Syft's ``--source-name`` and we require that
    # exact value here; a same-repository tag or a separately produced SPDX
    # document is therefore not accepted.
    return _reference_has_digest(payload.get("name"), expected_digest)


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _safe_database_file(path: Path, *, maximum_bytes: int | None = None) -> int:
    """Return a regular, unlinked database file size or raise ``ValueError``."""

    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink() or bool(getattr(absolute, "is_junction", lambda: False)()):
        raise ValueError(f"Trivy database path is a link or reparse point: {absolute}")
    try:
        resolved = absolute.resolve(strict=True)
        stat = absolute.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"Trivy database path cannot be inspected: {absolute}") from exc
    if resolved != absolute or not absolute.is_file() or stat.st_nlink != 1:
        raise ValueError(f"Trivy database path is not an independent regular file: {absolute}")
    if maximum_bytes is not None and not 0 < stat.st_size <= maximum_bytes:
        raise ValueError(f"Trivy database file size is outside the supported bound: {absolute}")
    return stat.st_size


def _stable_database_hash(path: Path, *, maximum_bytes: int) -> str:
    """Hash one DB file only when its metadata is stable across the read."""

    _safe_database_file(path, maximum_bytes=maximum_bytes)
    before = path.stat(follow_symlinks=False)
    digest = _sha256_file(path)
    after = path.stat(follow_symlinks=False)
    signature_before = (before.st_size, before.st_mtime_ns, before.st_nlink)
    signature_after = (after.st_size, after.st_mtime_ns, after.st_nlink)
    if signature_before != signature_after:
        raise ValueError(f"Trivy database file changed while hashing: {path}")
    return digest


def _database_blocked(
    cache_directory: Path,
    *,
    max_age_hours: float,
    update_command: CommandEvidence | None,
    reason: str,
    metadata_version: int | None = None,
    metadata_sha256: str | None = None,
    database_sha256: str | None = None,
    database_size_bytes: int | None = None,
    updated_at: str | None = None,
    downloaded_at: str | None = None,
    next_update: str | None = None,
    age_hours: float | None = None,
) -> TrivyDatabaseEvidence:
    return TrivyDatabaseEvidence(
        status="blocked",
        reason=reason,
        cache_path=str(cache_directory),
        repositories=list(_TRIVY_DB_REPOSITORIES),
        updated_at=updated_at,
        downloaded_at=downloaded_at,
        next_update=next_update,
        age_hours=age_hours,
        max_age_hours=max_age_hours,
        metadata_version=metadata_version,
        metadata_sha256=metadata_sha256,
        database_sha256=database_sha256,
        database_size_bytes=database_size_bytes,
        provenance_verified=False,
        integrity_status="inventory_only"
        if metadata_sha256 is not None or database_sha256 is not None
        else "not_checked",
        update_command=update_command,
    )


def _database_evidence(
    cache_directory: Path,
    *,
    max_age_hours: float,
    update_command: CommandEvidence | None,
) -> TrivyDatabaseEvidence:
    if update_command is not None and update_command.exit_code != 0:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason=update_command.error
            or f"Trivy database update exited with code {update_command.exit_code}",
        )
    metadata_path = cache_directory / "db" / "metadata.json"
    database_path = cache_directory / "db" / "trivy.db"
    try:
        _safe_database_file(metadata_path, maximum_bytes=_MAX_JSON_BYTES)
        database_size = _safe_database_file(
            database_path, maximum_bytes=_MAX_TRIVY_DB_BYTES
        )
        metadata_sha256 = _stable_database_hash(
            metadata_path, maximum_bytes=_MAX_JSON_BYTES
        )
        database_sha256 = _stable_database_hash(
            database_path, maximum_bytes=_MAX_TRIVY_DB_BYTES
        )
    except (OSError, ValueError) as exc:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason=f"Trivy database files are missing or unsafe ({exc})",
        )
    try:
        payload = _load_bounded_json(metadata_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason=f"Trivy database metadata is invalid ({type(exc).__name__})",
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
        )
    if not isinstance(payload, dict):
        payload = {}
    raw_version = payload.get("Version", payload.get("version"))
    metadata_version = raw_version if type(raw_version) is int else None
    if metadata_version != 2:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database metadata must declare supported Version=2",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
        )
    # Current Trivy v0.74 metadata (trivy-db v2) does not emit ``Type``.
    # Older producers may include it, but an explicit value is only accepted
    # when it is the integer type used by the legacy schema.  ``type(...)``
    # deliberately rejects JSON booleans, since ``bool`` subclasses ``int``.
    for type_key in ("Type", "type"):
        if type_key not in payload:
            continue
        raw_type = payload[type_key]
        if type(raw_type) is not int or raw_type != 1:
            return _database_blocked(
                cache_directory,
                max_age_hours=max_age_hours,
                update_command=update_command,
                reason=f"Trivy database metadata optional {type_key} must be integer Type=1",
                metadata_version=metadata_version,
                metadata_sha256=metadata_sha256,
                database_sha256=database_sha256,
                database_size_bytes=database_size,
            )
    raw_updated = payload.get("UpdatedAt") or payload.get("updated_at")
    raw_downloaded = payload.get("DownloadedAt") or payload.get("downloaded_at")
    raw_next_update = payload.get("NextUpdate") or payload.get("next_update")
    if raw_downloaded is None:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database metadata has no DownloadedAt timestamp",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
        )
    updated = _parse_utc(raw_updated)
    downloaded = _parse_utc(raw_downloaded)
    next_update = _parse_utc(raw_next_update)
    if (raw_downloaded is not None and downloaded is None) or (
        raw_next_update is not None and next_update is None
    ):
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database metadata contains an invalid timestamp",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
        )
    if updated is None or next_update is None:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database metadata has invalid UpdatedAt or NextUpdate",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
            downloaded_at=downloaded.isoformat() if downloaded is not None else None,
            next_update=next_update.isoformat() if next_update else None,
        )
    now = datetime.now(UTC)
    # Trivy's bundled/offline DB can use year-one for DownloadedAt.  Treat that
    # field as unverified rather than rejecting an otherwise valid DB solely on
    # the producer's sentinel value; a future timestamp is always invalid.
    downloaded_is_sentinel = downloaded is not None and downloaded.year <= 1
    if update_command is not None and update_command.exit_code == 0 and downloaded_is_sentinel:
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database update returned a sentinel DownloadedAt timestamp",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
            updated_at=updated.isoformat(),
            downloaded_at=downloaded.isoformat() if downloaded is not None else None,
            next_update=next_update.isoformat(),
        )
    if downloaded is not None and not downloaded_is_sentinel and downloaded > now + timedelta(seconds=15):
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database DownloadedAt is in the future",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
            updated_at=updated.isoformat(),
            downloaded_at=downloaded.isoformat() if downloaded is not None else None,
            next_update=next_update.isoformat(),
        )
    if (
        updated > now + timedelta(seconds=15)
        or next_update < now - timedelta(seconds=15)
        or next_update < updated - timedelta(seconds=15)
    ):
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database metadata timestamps are inconsistent",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
            updated_at=updated.isoformat(),
            downloaded_at=downloaded.isoformat() if downloaded is not None else None,
            next_update=next_update.isoformat(),
        )
    if downloaded is not None and not downloaded_is_sentinel and downloaded < updated - timedelta(seconds=15):
        return _database_blocked(
            cache_directory,
            max_age_hours=max_age_hours,
            update_command=update_command,
            reason="Trivy database DownloadedAt precedes UpdatedAt",
            metadata_version=metadata_version,
            metadata_sha256=metadata_sha256,
            database_sha256=database_sha256,
            database_size_bytes=database_size,
            updated_at=updated.isoformat(),
            downloaded_at=downloaded.isoformat() if downloaded is not None else None,
            next_update=next_update.isoformat(),
        )
    age_hours = round((now - updated).total_seconds() / 3_600, 3)
    if age_hours < -0.25:
        status: EvidenceStatus = "blocked"
        reason = "Trivy database UpdatedAt is implausibly in the future"
    elif age_hours > max_age_hours:
        status = "blocked"
        reason = f"Trivy database is stale ({age_hours:.3f}h > {max_age_hours:.3f}h)"
    else:
        status = "passed"
        reason = (
            "Trivy vulnerability database is fresh and its local metadata/database "
            "file inventory was hashed; source provenance remains unverified"
        )
    return TrivyDatabaseEvidence(
        status=status,
        reason=reason,
        cache_path=str(cache_directory),
        repositories=list(_TRIVY_DB_REPOSITORIES),
        updated_at=updated.isoformat(),
        downloaded_at=downloaded.isoformat() if downloaded is not None else None,
        next_update=next_update.isoformat() if next_update else None,
        age_hours=age_hours,
        max_age_hours=max_age_hours,
        metadata_version=metadata_version,
        metadata_sha256=metadata_sha256,
        database_sha256=database_sha256,
        database_size_bytes=database_size,
        provenance_verified=False,
        integrity_status="inventory_only",
        update_command=update_command,
    )


def _database_snapshot_unchanged(
    cache_directory: Path, database: TrivyDatabaseEvidence
) -> bool:
    """Re-hash the two DB files after a scan to detect concurrent replacement."""

    if not database.metadata_sha256 or not database.database_sha256:
        return False
    try:
        metadata_path = cache_directory / "db" / "metadata.json"
        database_path = cache_directory / "db" / "trivy.db"
        _safe_database_file(metadata_path, maximum_bytes=_MAX_JSON_BYTES)
        _safe_database_file(database_path, maximum_bytes=_MAX_TRIVY_DB_BYTES)
        return (
            _stable_database_hash(metadata_path, maximum_bytes=_MAX_JSON_BYTES)
            == database.metadata_sha256
            and _stable_database_hash(
                database_path, maximum_bytes=_MAX_TRIVY_DB_BYTES
            )
            == database.database_sha256
        )
    except (OSError, ValueError):
        return False


def _parse_trivy_report(
    payload: Any,
    *,
    expected_digest: str,
    expected_image_id: str,
    expected_reference: str | None = None,
) -> tuple[dict[str, int], bool, bool]:
    if _DIGEST_RE.fullmatch(expected_digest) is None:
        raise ValueError("expected image digest is invalid")
    if _DIGEST_RE.fullmatch(expected_image_id) is None:
        raise ValueError("expected image ID is missing or invalid")
    if not isinstance(payload, dict):
        raise ValueError("Trivy report is not a JSON object")
    metadata = payload.get("Metadata")
    results = payload.get("Results")
    if not isinstance(metadata, dict) or not isinstance(results, list):
        raise ValueError("Trivy report is missing Metadata or Results")
    if payload.get("SchemaVersion") != 2 or payload.get("ArtifactType") != "container_image":
        raise ValueError("Trivy report is not a SchemaVersion=2 container_image report")
    artifact_name = payload.get("ArtifactName")
    if not isinstance(artifact_name, str) or not _reference_has_digest(
        artifact_name, expected_digest
    ):
        raise ValueError("Trivy report is not bound to the expected image digest")
    if expected_reference is not None and artifact_name != expected_reference:
        raise ValueError("Trivy report ArtifactName is not the configured image reference")
    repo_digests = metadata.get("RepoDigests")
    if not isinstance(repo_digests, list) or not any(
        _reference_has_digest(item, expected_digest) for item in repo_digests
    ):
        raise ValueError("Trivy report RepoDigests are not bound to the expected image digest")
    metadata_image_id = metadata.get("ImageID")
    if not isinstance(metadata_image_id, str) or _DIGEST_RE.fullmatch(metadata_image_id) is None:
        raise ValueError("Trivy report Metadata.ImageID is missing or invalid")
    # Trivy's Metadata.ImageID can be the content/config ID while Docker
    # inspect's Id can be the manifest/index ID.  Record the exact digest
    # binding above and do not confuse those two valid identities.
    digest_bound = True
    counts = {severity: 0 for severity in _ALL_SEVERITIES}
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy Results contains a malformed entry")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy Vulnerabilities field is not an array")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Trivy Vulnerabilities contains a malformed entry")
            severity = vulnerability.get("Severity")
            if not isinstance(severity, str) or severity.upper() not in counts:
                raise ValueError("Trivy report contains an unknown vulnerability severity")
            counts[severity.upper()] += 1
    os_metadata = metadata.get("OS")
    if not isinstance(os_metadata, dict):
        raise ValueError("Trivy report Metadata.OS is missing or malformed")
    raw_os_eol = os_metadata.get("EOSL", False)
    if not isinstance(raw_os_eol, bool):
        raise ValueError("Trivy report OS.EOSL must be a boolean")
    os_eol = raw_os_eol
    return counts, os_eol, digest_bound


def _looks_like_legacy_astercode_config(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    product = payload.get("product")
    versioned = (
        type(payload.get("config_version")) is int
        and payload.get("config_version") == 1
        and str(payload.get("product_name", "")).strip().casefold() == "astercode"
    )
    legacy = (
        isinstance(product, dict)
        and str(product.get("name", "")).strip().casefold() == "astercode"
        and all(isinstance(payload.get(key), dict) for key in ("model", "security"))
    )
    return versioned or legacy


def _discover_supply_config(root: Path) -> Path | None:
    for candidate in (root / "astercode.toml", root / ".astercode" / "config.toml"):
        if candidate.is_symlink() or bool(getattr(candidate, "is_junction", lambda: False)()):
            raise ConfigError(f"project config cannot be a link or junction: {candidate}")
        if candidate.exists():
            return validate_strict_project_file(candidate, root)
    legacy = root / "config.toml"
    if legacy.is_symlink() or bool(getattr(legacy, "is_junction", lambda: False)()):
        raise ConfigError(f"legacy project config cannot be a link or junction: {legacy}")
    if not legacy.is_file():
        return None
    validated_legacy = validate_strict_project_file(legacy, root)
    try:
        if validated_legacy.stat().st_size > 1_048_576:
            raise ConfigError("config exceeds 1 MiB")
    except OSError as exc:
        raise ConfigError(f"cannot inspect legacy project config: {exc}") from exc
    try:
        with validated_legacy.open("rb") as stream:
            payload = tomllib.load(stream)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot inspect legacy project config: {exc}") from exc
    return validated_legacy if _looks_like_legacy_astercode_config(payload) else None


def _configured_image_from_file(path: Path) -> str | None:
    """Extract only the image field from a project file.

    Strict runtime configuration is still loaded separately and replaces all
    project-controlled authorities.  This narrow extractor makes the selected
    image visible to evidence generation without importing network/SSH/path
    settings from an untrusted TOML file.
    """

    try:
        if path.stat().st_size > 1_048_576:
            raise ConfigError("config exceeds 1 MiB")
        with path.open("rb") as stream:
            parsed = tomllib.load(stream)
        normalized = _normalise_legacy_config(parsed)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        raise ConfigError(f"cannot extract configured image: {exc}") from exc
    security = normalized.get("security")
    process = security.get("process") if isinstance(security, dict) else None
    if not isinstance(process, dict) or "container_image" not in process:
        return None
    image = process["container_image"]
    if not isinstance(image, str):
        raise ConfigError("security.process.container_image must be a string")
    try:
        return ProcessSecurityConfig(container_image=image).container_image
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def _tool_ready(snapshot: ToolSnapshot) -> bool:
    return bool(
        snapshot.detected
        and snapshot.executable
        and snapshot.binary_stable
        and (snapshot.version_command is None or snapshot.version_command.exit_code == 0)
    )


def _git_facts(root: Path) -> tuple[str, bool]:
    tools = GitTools([root])
    revision = tools._run("git.rev_parse", str(root), ["rev-parse", "--verify", "HEAD"])
    if revision.status != "completed" or revision.exit_code != 0:
        raise RuntimeError(revision.error or "cannot resolve target Git commit")
    commit = revision.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RuntimeError("Git returned an invalid target commit")
    status = tools._run(
        "git.status_porcelain",
        str(root),
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    if status.status != "completed" or status.exit_code != 0:
        raise RuntimeError(status.error or "cannot inspect Git working tree")
    return commit, not bool(status.stdout.strip())


def _strict_state_directory(root: Path, requested: Path) -> Path:
    try:
        checked = canonicalize_authorized_path(requested, [root], must_exist=False, reject_unc=True)
        checked.revalidate([root], must_exist=False, reject_unc=True)
    except PathAuthorizationError as exc:
        raise ConfigError(str(exc)) from exc
    if checked.absolute != checked.resolved:
        raise ConfigError("supply-chain state path cannot traverse links or reparse points")
    checked.absolute.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        checked.absolute.chmod(0o700)
    if checked.absolute.resolve(strict=True) != checked.absolute:
        raise ConfigError("supply-chain state path changed during creation")
    return checked.absolute


def _write_checksums(run_directory: Path, destination: Path) -> None:
    lines: list[str] = []
    for path in sorted(run_directory.rglob("*")):
        if not path.is_file() or path == destination or path.name.endswith(".tmp"):
            continue
        lines.append(f"{_sha256_file(path)}  {_relative(run_directory, path)}")
    _atomic_write(destination, ("\n".join(lines) + "\n").encode("utf-8"))


def generate_supply_chain_evidence(
    root: Path,
    *,
    config_file: Path | None = None,
    output_directory: Path | None = None,
    update_trivy_db: bool = False,
    max_db_age_hours: float = 48.0,
    timeout_seconds: float = 600.0,
    allow_dirty: bool = False,
    allow_unverified_signature: bool = False,
) -> SupplyChainRun:
    root = validate_strict_workspace_root(root)
    commit, working_tree_clean = _git_facts(root)
    if not working_tree_clean and not allow_dirty:
        raise RuntimeError("working tree is dirty; release evidence requires a clean target commit")
    selected_config = (
        validate_strict_project_file(config_file, root)
        if config_file is not None
        else _discover_supply_config(root)
    )
    config_sha256 = _sha256_file(selected_config) if selected_config is not None else None
    config = load_config(
        selected_config,
        project_root=root,
        environ={},
        strict_workspace=True,
    )
    configured_image = config.security.process.container_image
    if selected_config is not None:
        if _sha256_file(selected_config) != config_sha256:
            raise RuntimeError("selected config changed during supply-chain evidence setup")
        selected_image = _configured_image_from_file(selected_config)
        if _sha256_file(selected_config) != config_sha256:
            raise RuntimeError("selected config changed during image extraction")
        if selected_image is not None:
            configured_image = selected_image
    if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", configured_image) is None:
        raise RuntimeError("supply-chain evidence requires an exact RepoDigest image reference")

    artifact_root = _strict_state_directory(root, root / ".astercode" / "artifacts")
    requested_output = output_directory or artifact_root / "supply-chain"
    requested_candidate = Path(requested_output)
    if not requested_candidate.is_absolute():
        requested_candidate = root / requested_candidate
    requested_absolute = Path(os.path.abspath(requested_candidate))
    try:
        requested_absolute.relative_to(artifact_root)
    except ValueError as exc:
        raise ConfigError("supply-chain output must stay below .astercode/artifacts") from exc
    output_root = _strict_state_directory(root, requested_absolute)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_directory = output_root / f"{commit[:12]}-{timestamp}-{uuid.uuid4().hex[:8]}"
    _private_mkdir(run_directory)
    control_directory = run_directory / "control"
    _private_mkdir(control_directory)
    empty_config = control_directory / "empty.yaml"
    _atomic_write(empty_config, b"{}\n")
    environment = _tool_environment(control_directory)

    tools = {
        name: _snapshot_tool(
            run_directory,
            name,
            environment=environment,
            cwd=run_directory,
            timeout=timeout_seconds,
        )
        for name in ("cosign", "syft", "trivy")
    }

    resolved_image: str | None = None
    image_id: str | None = None
    docker = discover_trusted_docker()
    content_pinned = False
    image_error: str | None = None
    if docker is None:
        image_error = "fixed-location Docker executable was not detected"
    else:
        try:
            resolved_image, image_id = _resolve_local_image(docker, configured_image)
            content_pinned = resolved_image == configured_image
        except DockerSandboxUnavailable as exc:
            image_error = str(exc)

    sbom = SbomEvidence(
        status="blocked",
        reason=image_error or "Syft executable was not detected",
    )
    syft_executable = tools["syft"].executable
    if content_pinned and _tool_ready(tools["syft"]) and syft_executable is not None:
        syft_temporary = run_directory / "sbom.syft.json.tmp"
        spdx_temporary = run_directory / "sbom.spdx.json.tmp"
        command = _run_logged(
            run_directory,
            "syft-sbom",
            [
                syft_executable,
                "-c",
                str(empty_config),
                "scan",
                f"docker:{resolved_image}",
                "--source-name",
                configured_image,
                "-q",
                "-o",
                f"syft-json={syft_temporary}",
                "-o",
                f"spdx-json={spdx_temporary}",
            ],
            environment=environment,
            cwd=run_directory,
            timeout=timeout_seconds,
        )
        if command.exit_code == 0:
            try:
                package_count, digest_bound = _parse_syft_report(
                    _load_bounded_json(syft_temporary),
                    configured_image.rsplit("@", 1)[1],
                )
                spdx_payload = _load_bounded_json(spdx_temporary)
                spdx_digest_bound = _parse_spdx_report(
                    spdx_payload,
                    expected_digest=configured_image.rsplit("@", 1)[1],
                    expected_reference=configured_image,
                )
                if not spdx_digest_bound:
                    raise ValueError(
                        "Syft SPDX artifact has no exact image digest binding"
                    )
                syft_path = run_directory / "sbom.syft.json"
                spdx_path = run_directory / "sbom.spdx.json"
                os.replace(syft_temporary, syft_path)
                os.replace(spdx_temporary, spdx_path)
                artifacts = {
                    "syft_json": _relative(run_directory, syft_path),
                    "spdx_json": _relative(run_directory, spdx_path),
                }
                sbom = SbomEvidence(
                    status="passed",
                    reason="Syft generated digest-bound Syft JSON and SPDX JSON artifacts",
                    command=command,
                    package_count=package_count,
                    source_digest_bound=digest_bound,
                    spdx_digest_bound=spdx_digest_bound,
                    artifacts=artifacts,
                    artifact_sha256={name: _sha256_file(run_directory / path) for name, path in artifacts.items()},
                )
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                sbom = SbomEvidence(
                    status="failed",
                    reason=f"Syft output validation failed ({type(exc).__name__}: {exc})",
                    command=command,
                )
        else:
            sbom = SbomEvidence(
                status="failed",
                reason=command.error or f"Syft exited with code {command.exit_code}",
                command=command,
            )
        syft_temporary.unlink(missing_ok=True)
        spdx_temporary.unlink(missing_ok=True)
    elif content_pinned and not _tool_ready(tools["syft"]):
        sbom.reason = "Syft executable was not ready (missing, failed version check, or changed during inspection)"

    cache_directory = _strict_state_directory(root, root / ".astercode" / "cache" / "trivy")
    database_update: CommandEvidence | None = None
    trivy_repository_args = [
        item
        for repository in _TRIVY_DB_REPOSITORIES
        for item in ("--db-repository", repository)
    ]
    trivy_executable = tools["trivy"].executable
    if update_trivy_db and _tool_ready(tools["trivy"]) and trivy_executable is not None:
        database_update = _run_logged(
            run_directory,
            "trivy-db-update",
            [
                trivy_executable,
                "--config",
                str(empty_config),
                "--cache-dir",
                str(cache_directory),
                *trivy_repository_args,
                "image",
                "--download-db-only",
                "--no-progress",
                "--disable-telemetry",
                "--skip-version-check",
            ],
            environment=environment,
            cwd=run_directory,
            timeout=timeout_seconds,
        )
    database = _database_evidence(
        cache_directory,
        max_age_hours=max_db_age_hours,
        update_command=database_update,
    )
    vulnerability = VulnerabilityEvidence(
        status="blocked",
        reason=image_error
        or (
            "Trivy executable was not ready (missing, failed version check, or changed during inspection)"
            if not _tool_ready(tools["trivy"])
            else database.reason
        ),
        database=database,
        severities=list(_ALL_SEVERITIES),
        fail_severities=["HIGH", "CRITICAL"],
        counts={severity: 0 for severity in _ALL_SEVERITIES},
    )
    if (
        content_pinned
        and _tool_ready(tools["trivy"])
        and trivy_executable is not None
        and database.status == "passed"
    ):
        trivy_temporary = run_directory / "trivy.json.tmp"
        command = _run_logged(
            run_directory,
            "trivy-scan",
            [
                trivy_executable,
                "--config",
                str(empty_config),
                "--cache-dir",
                str(cache_directory),
                *trivy_repository_args,
                "image",
                "--image-src",
                "docker",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-vex-repo-update",
                "--disable-telemetry",
                "--skip-version-check",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--output",
                str(trivy_temporary),
                "--severity",
                ",".join(_ALL_SEVERITIES),
                "--exit-code",
                "0",
                configured_image,
            ],
            environment=environment,
            cwd=run_directory,
            timeout=timeout_seconds,
        )
        if command.exit_code == 0:
            try:
                if not _database_snapshot_unchanged(cache_directory, database):
                    raise ValueError("Trivy database changed during the scan")
                counts, os_eol, digest_bound = _parse_trivy_report(
                    _load_bounded_json(trivy_temporary),
                    expected_digest=configured_image.rsplit("@", 1)[1],
                    expected_image_id=image_id or "",
                    expected_reference=configured_image,
                )
                trivy_path = run_directory / "trivy.json"
                os.replace(trivy_temporary, trivy_path)
                policy_passed = (
                    counts["UNKNOWN"] == 0
                    and counts["HIGH"] == 0
                    and counts["CRITICAL"] == 0
                    and not os_eol
                )
                vulnerability = VulnerabilityEvidence(
                    status="passed" if policy_passed else "failed",
                    reason=(
                        "Trivy scan is digest-bound and the UNKNOWN/HIGH/CRITICAL plus OS-EOL policy passed"
                        if policy_passed
                        else "Trivy scan completed but the HIGH/CRITICAL or OS-EOL policy failed"
                    ),
                    command=command,
                    database=database,
                    severities=list(_ALL_SEVERITIES),
                    fail_severities=["HIGH", "CRITICAL"],
                    counts=counts,
                    os_eol=os_eol,
                    image_digest_bound=digest_bound,
                    artifact=_relative(run_directory, trivy_path),
                    artifact_sha256=_sha256_file(trivy_path),
                )
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                vulnerability = VulnerabilityEvidence(
                    status="failed",
                    reason=f"Trivy output validation failed ({type(exc).__name__}: {exc})",
                    command=command,
                    database=database,
                    severities=list(_ALL_SEVERITIES),
                    fail_severities=["HIGH", "CRITICAL"],
                )
        else:
            vulnerability = VulnerabilityEvidence(
                status="failed",
                reason=command.error or f"Trivy exited with code {command.exit_code}",
                command=command,
                database=database,
                severities=list(_ALL_SEVERITIES),
                fail_severities=["HIGH", "CRITICAL"],
            )
        trivy_temporary.unlink(missing_ok=True)

    signature = SignatureEvidence(
        reason=(
            "Cosign executable detected, but no pre-approved public key or exact certificate identity and issuer policy was supplied"
            if tools["cosign"].detected
            else "Cosign executable was not detected and no trust policy was supplied"
        )
    )
    claims = SupplyChainClaims(
        content_pinned=content_pinned,
        sbom_generated=(
            sbom.status == "passed"
            and sbom.source_digest_bound
            and sbom.spdx_digest_bound
        ),
        vulnerability_policy_passed=(
            vulnerability.status == "passed"
            and vulnerability.image_digest_bound
            and vulnerability.database.provenance_verified
        ),
        signature_verified=False,
    )
    required_statuses = (sbom.status, vulnerability.status)
    if "failed" in required_statuses:
        overall_status: Literal["passed", "partial", "failed", "blocked"] = "failed"
        exit_code = 1
    elif "blocked" in required_statuses or not content_pinned:
        overall_status = "blocked"
        exit_code = 2
    elif not claims.vulnerability_policy_passed:
        overall_status = "blocked"
        exit_code = 2
    elif not claims.signature_verified and not allow_unverified_signature:
        overall_status = "blocked"
        exit_code = 2
    else:
        overall_status = "partial"
        exit_code = 0
    manifest = SupplyChainManifest(
        generated_at=datetime.now(UTC).isoformat(),
        target_commit=commit,
        working_tree_clean=working_tree_clean,
        version=__version__,
        platform=platform.platform(),
        config_file=(
            selected_config.relative_to(root).as_posix()
            if selected_config is not None
            else None
        ),
        config_sha256=config_sha256,
        configured_image=configured_image,
        resolved_image_digest=resolved_image,
        image_id=image_id,
        overall_status=overall_status,
        tools=tools,
        sbom=sbom,
        vulnerability_scan=vulnerability,
        signature=signature,
        claims=claims,
        limitations=[
            "Digest pinning is content addressing, not signer authentication.",
            "Fixed-location WinGet executables are user-owned snapshots; recorded hashes are not an independent package signature.",
            "Docker daemon and local administrator integrity remain outside this application-level evidence.",
            "Cosign signature verification remains NOT VERIFIED until a trust policy and matching evidence are supplied.",
            "Trivy database hashes are a local metadata/file inventory only; they do not establish trusted database provenance, so the vulnerability claim remains false until an approved provenance policy is added.",
            "Tool executable hashes are sampled before and after version inspection; a change marks the tool unusable for this run.",
            "Command timeouts use POSIX process groups or Windows taskkill tree termination when available; OS-level administrator interference remains outside this evidence.",
        ],
    )
    manifest_path = run_directory / "manifest.json"
    _atomic_write_json(manifest_path, manifest)
    checksums_path = run_directory / "SHA256SUMS"
    _write_checksums(run_directory, checksums_path)
    return SupplyChainRun(
        manifest=manifest,
        directory=run_directory,
        manifest_path=manifest_path,
        checksums_path=checksums_path,
        exit_code=exit_code,
    )
