"""Versioned, atomic configuration migration with exact-byte backups."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
import tomllib
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .config import (
    CURRENT_CONFIG_VERSION,
    AppConfig,
    ConfigError,
    _normalise_legacy_config,
)
from .lock import InterProcessFileLock
from .security import contains_probable_secret


class ConfigMigrationError(ConfigError):
    """The source cannot be safely classified, rendered, or replaced."""


class ConfigMigrationConflict(ConfigMigrationError):
    """The source changed after inspection and before the write boundary."""


@dataclass(frozen=True, slots=True)
class ConfigMigrationResult:
    path: str
    from_version: int
    to_version: int
    changed: bool
    written: bool
    source_sha256: str
    output_sha256: str
    deprecated_fields: tuple[str, ...]
    backup_path: str | None = None
    canonical_text: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _legacy_fields(data: Mapping[str, Any]) -> tuple[str, ...]:
    result: set[str] = set()
    for section in ("product", "budgets", "approval"):
        value = data.get(section)
        if isinstance(value, Mapping):
            result.update(f"{section}.{key}" for key in value)
        elif section in data:
            result.add(section)
    security = data.get("security")
    if isinstance(security, Mapping):
        for key in (
            "max_output_bytes",
            "default_command_timeout_seconds",
            "enable_browser_automation",
            "enable_native_desktop_gui",
            "enable_multi_agent",
            "allow_workspace_writes",
        ):
            if key in security:
                result.add(f"security.{key}")
    storage = data.get("storage")
    if isinstance(storage, Mapping):
        for key in ("artifact_dir", "audit_log_path", "wal"):
            if key in storage:
                result.add(f"storage.{key}")
    return tuple(sorted(result))


def _toml_key(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return value
    return json.dumps(value, ensure_ascii=False)


def _toml_scalar(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ConfigMigrationError("non-finite floats cannot be written to config")
        return repr(value)
    if isinstance(value, list):
        if any(isinstance(item, Mapping) for item in value):
            raise ConfigMigrationError("mapping arrays require TOML array-of-table rendering")
        return "[" + ", ".join(_toml_scalar(item) for item in value) + "]"
    raise ConfigMigrationError(f"unsupported config value type: {type(value).__name__}")


def _table_name(path: tuple[str, ...]) -> str:
    return ".".join(_toml_key(item) for item in path)


def _render_table(
    lines: list[str],
    values: Mapping[str, Any],
    path: tuple[str, ...],
    *,
    header: str | None,
) -> None:
    if header is not None:
        if lines and lines[-1] != "":
            lines.append("")
        lines.append(f"{header}{_table_name(path)}{']]' if header == '[[' else ']'}")

    child_tables: list[tuple[str, Mapping[str, Any]]] = []
    child_arrays: list[tuple[str, list[Mapping[str, Any]]]] = []
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, Mapping):
            child_tables.append((key, value))
            continue
        if isinstance(value, list) and value and all(
            isinstance(item, Mapping) for item in value
        ):
            child_arrays.append((key, list(value)))
            continue
        lines.append(f"{_toml_key(key)} = {_toml_scalar(value)}")

    for key, child in child_tables:
        _render_table(lines, child, (*path, key), header="[")
    for key, items in child_arrays:
        for item in items:
            _render_table(lines, item, (*path, key), header="[[")


def render_config_toml(config: AppConfig) -> str:
    """Render the strict typed config without environment-secret values."""

    data = config.model_dump(mode="json", exclude_none=True)
    lines: list[str] = []
    _render_table(lines, data, (), header=None)
    return "\n".join(lines).rstrip() + "\n"


def _parse_source(source: bytes, path: Path) -> dict[str, Any]:
    try:
        parsed = tomllib.loads(source.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigMigrationError(
            f"cannot parse config {path}: {type(exc).__name__}"
        ) from exc
    return dict(parsed)


def _source_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (int(stat.st_dev), int(stat.st_ino), int(stat.st_size), int(stat.st_mtime_ns))


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
        if os.name != "nt":
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def migrate_config_file(
    path: str | Path,
    *,
    project_root: str | Path,
    write: bool = False,
) -> ConfigMigrationResult:
    """Preview or atomically write one config migration.

    Environment overlays are deliberately excluded so a credential or model
    override present in the invoking shell can never be persisted by migrate.
    """

    root = Path(project_root).expanduser().resolve(strict=True)
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    if candidate.is_symlink() or getattr(candidate, "is_junction", lambda: False)():
        raise ConfigMigrationError("config migration refuses symlink or junction sources")
    source_path = candidate.resolve(strict=True)
    try:
        source_path.relative_to(root)
    except ValueError as exc:
        raise ConfigMigrationError("config migration path is outside project_root") from exc
    if not source_path.is_file():
        raise ConfigMigrationError("config migration source must be a regular file")

    source = source_path.read_bytes()
    try:
        source_text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigMigrationError("config migration source must be UTF-8") from exc
    if contains_probable_secret(source_text):
        raise ConfigMigrationError(
            "config contains probable inline secret material; remove it before migration"
        )
    identity = _source_identity(source_path)
    source_hash = _sha256(source)
    raw = _parse_source(source, source_path)
    raw_version = raw.get("config_version")
    from_version = raw_version if isinstance(raw_version, int) and not isinstance(raw_version, bool) else 0
    deprecated = _legacy_fields(raw)
    try:
        normalized = _normalise_legacy_config(raw)
        normalized["project_root"] = str(root)
        config = AppConfig.model_validate(normalized)
    except (OSError, ValueError) as exc:
        raise ConfigMigrationError(str(exc)) from exc
    canonical = render_config_toml(config).encode("utf-8")
    output_hash = _sha256(canonical)
    changed = source != canonical

    if not write or not changed:
        return ConfigMigrationResult(
            path=str(source_path),
            from_version=from_version,
            to_version=CURRENT_CONFIG_VERSION,
            changed=changed,
            written=False,
            source_sha256=source_hash,
            output_sha256=output_hash,
            deprecated_fields=deprecated,
            canonical_text=canonical.decode("utf-8") if not write else None,
        )

    lock = InterProcessFileLock(root / ".astercode" / "config-migrate.lock")
    with lock.held(timeout_seconds=30):
        current = source_path.read_bytes()
        if _source_identity(source_path) != identity or _sha256(current) != source_hash:
            raise ConfigMigrationConflict(
                "config changed after inspection; no backup or replacement was written"
            )
        source_mode = stat.S_IMODE(source_path.stat().st_mode)
        backup = source_path.with_name(
            f"{source_path.name}.v{from_version}.{uuid.uuid4().hex}.bak"
        )
        try:
            with backup.open("xb") as stream:
                stream.write(source)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(backup, source_mode)
            if backup.read_bytes() != source:
                raise ConfigMigrationError("exact-byte migration backup verification failed")
            _atomic_write(source_path, canonical, source_mode)
            if _sha256(source_path.read_bytes()) != output_hash:
                raise ConfigMigrationError("migrated config hash verification failed")
            # Re-parse with no environment overlay before reporting success.
            migrated = _parse_source(source_path.read_bytes(), source_path)
            migrated["project_root"] = str(root)
            AppConfig.model_validate(_normalise_legacy_config(migrated))
        except Exception:
            if backup.is_file():
                _atomic_write(source_path, backup.read_bytes(), source_mode)
            raise

    return ConfigMigrationResult(
        path=str(source_path),
        from_version=from_version,
        to_version=CURRENT_CONFIG_VERSION,
        changed=True,
        written=True,
        source_sha256=source_hash,
        output_sha256=output_hash,
        deprecated_fields=deprecated,
        backup_path=str(backup),
    )


__all__ = [
    "ConfigMigrationConflict",
    "ConfigMigrationError",
    "ConfigMigrationResult",
    "migrate_config_file",
    "render_config_toml",
]
