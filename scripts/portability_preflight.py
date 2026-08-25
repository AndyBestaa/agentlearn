"""Read-only, network-free portability gate for an AsterCode checkout.

This script intentionally uses only the Python standard library so it can run
before ``uv sync``.  The source profile checks repository hygiene.  The demo
profile additionally checks a local Docker Linux engine and the exact pinned
image, but it never pulls an image or contacts a model provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Literal, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fails the version gate
    tomllib = None  # type: ignore[assignment]

Profile = Literal["source", "demo"]
OutputFormat = Literal["text", "json"]
Status = Literal["PASS", "WARN", "FAIL"]
FailureKind = Literal["hygiene", "prerequisite"]

_MAX_TEXT_BYTES = 5 * 1024 * 1024
_REGULAR_GIT_MODES = frozenset({"100644", "100755"})
_BINARY_SUFFIXES = frozenset(
    {
        ".bin",
        ".dll",
        ".dylib",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".otf",
        ".pdf",
        ".png",
        ".pyd",
        ".so",
        ".tar",
        ".ttf",
        ".whl",
        ".woff",
        ".woff2",
        ".zip",
    }
)
_RUNTIME_COMPONENTS = frozenset(
    {
        ".astercode",
        ".langgraph_api",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "venv",
    }
)
_FORBIDDEN_SUFFIXES = (
    ".db",
    ".db-shm",
    ".db-wal",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
)
_IGNORE_SENTINELS = (
    ".astercode/preflight.db",
    ".venv/preflight",
    "__pycache__/preflight.pyc",
    ".pytest_cache/preflight",
    ".mypy_cache/preflight",
    ".ruff_cache/preflight",
    ".langgraph_api/preflight",
    "dist/preflight.whl",
    "build/preflight",
    ".env",
    ".env.local",
    "config.toml",
    "preflight.db",
    "preflight.sqlite",
    "preflight.key",
    "%SystemDrive%/preflight.cache",
)

# This exact value is an intentionally fake assertion sentinel already present
# in a migration unit test.  No directory is skipped and no wildcard is used.
_KNOWN_TEST_SENTINELS = (
    "sk-must-never-be-persisted",
    "https://user:password@api.deepseek.com",
)
_LIVE_SECRET_NAMES = (
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_TOKEN_RES = (
    ("openai_token", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "github_token",
        re.compile(r"\b(?:gh[opusr]|github_pat)_[A-Za-z0-9_]{16,}\b"),
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
    ),
)
_ASSIGNMENT_RE = re.compile(
    r"(?P<name>api[_-]?key|access[_-]?token|auth(?:orization)?|password|passwd|"
    r"secret|private[_-]?key)\s*[=:]\s*(?P<quote>[\"']?)"
    r"(?P<value>[^\s,;\"']{4,})",
    re.IGNORECASE,
)
_CREDENTIAL_URL_RE = re.compile(
    r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    re.IGNORECASE,
)
_WINDOWS_HOME_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/](?:Users|Documents and Settings)"
    r"[\\/][^\\/\s\"'<>:|?*]+",
    re.IGNORECASE,
)
_POSIX_HOME_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s\"'<>]*)?"
)
_PATH_SETTING_RE = re.compile(
    r"^\s*(?:project_root|database_path|audit_jsonl_path|artifacts_dir|download_dir)"
    r"\s*[=:]\s*[\"']?(?P<value>[^\s\"']+)",
    re.IGNORECASE | re.MULTILINE,
)
_PINNED_IMAGE_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    status: Status
    detail: str
    remediation: str | None = None
    failure_kind: FailureKind | None = None


@dataclass(frozen=True, slots=True)
class PreflightReport:
    schema_version: int
    profile: Profile
    passed: bool
    exit_code: int
    commit: str | None
    checks: tuple[CheckResult, ...]
    next_commands: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "commit": self.commit,
            "checks": [asdict(item) for item in self.checks],
            "next_commands": list(self.next_commands),
        }


@dataclass(frozen=True, slots=True)
class _GitEntry:
    mode: str
    object_id: str
    path: str


@dataclass(frozen=True, slots=True)
class _TextItem:
    path: str
    text: str


CommandRunner = Callable[
    [Sequence[str], Path, dict[str, str], bytes | None, float],
    subprocess.CompletedProcess[bytes],
]


def _run_command(
    argv: Sequence[str],
    cwd: Path,
    env: dict[str, str],
    input_bytes: bytes | None,
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run one structured, bounded diagnostic command without a shell."""

    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(list(argv), 127, b"", b"")


def _base_environment() -> dict[str, str]:
    """Return a minimal environment without provider keys or proxy settings."""

    allowed = (
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    )
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _git_environment() -> dict[str, str]:
    environment = _base_environment()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_EXTERNAL_DIFF": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git_argv(git: Path, root: Path, *arguments: str) -> list[str]:
    return [
        str(git),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.excludesFile=",
        "-c",
        "core.preloadindex=false",
        "-C",
        str(root),
        *arguments,
    ]


def _git(
    runner: CommandRunner,
    git: Path,
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[bytes]:
    return runner(
        _git_argv(git, root, *arguments),
        root,
        _git_environment(),
        input_bytes,
        timeout,
    )


def _inside(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _trusted_command(name: str, root: Path) -> Path | None:
    raw = shutil.which(name)
    if raw is None:
        return None
    try:
        candidate = Path(raw).resolve(strict=True)
    except OSError:
        return None
    if not candidate.is_file() or _inside(candidate, root):
        return None
    return candidate


def _same_directory(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.normcase(str(left.resolve(strict=False))) == os.path.normcase(
            str(right.resolve(strict=False))
        )


def _literal_systemdrive_directory_exists(root: Path) -> bool:
    """Check one literal root entry without following or enumerating it."""

    try:
        metadata = os.stat(root / "%SystemDrive%", follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode)


def _parse_git_entries(payload: bytes) -> list[_GitEntry]:
    entries: list[_GitEntry] = []
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            path = os.fsdecode(raw_path)
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Git returned malformed index metadata") from exc
        if stage != "0" or not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
            raise ValueError("Git index contains an unresolved or malformed entry")
        entries.append(_GitEntry(mode=mode, object_id=object_id, path=path))
    return entries


def _read_index_blobs(
    runner: CommandRunner,
    git: Path,
    root: Path,
    entries: Sequence[_GitEntry],
) -> dict[str, bytes]:
    object_ids = tuple(dict.fromkeys(item.object_id for item in entries if item.mode in _REGULAR_GIT_MODES))
    if not object_ids:
        return {}
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in object_ids)
    completed = _git(
        runner,
        git,
        root,
        "cat-file",
        "--batch",
        input_bytes=request,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ValueError("Git could not read locally available tracked blobs")
    cursor = 0
    blobs: dict[str, bytes] = {}
    output = completed.stdout
    for expected in object_ids:
        line_end = output.find(b"\n", cursor)
        if line_end < 0:
            raise ValueError("Git returned a truncated blob header")
        fields = output[cursor:line_end].split()
        if len(fields) != 3:
            raise ValueError("Git returned malformed blob metadata")
        object_id = fields[0].decode("ascii", errors="strict")
        object_type = fields[1]
        try:
            size = int(fields[2])
        except ValueError as exc:
            raise ValueError("Git returned an invalid blob size") from exc
        if object_id != expected or object_type != b"blob" or size < 0:
            raise ValueError("Git returned an unexpected object")
        start = line_end + 1
        end = start + size
        if end >= len(output) or output[end : end + 1] != b"\n":
            raise ValueError("Git returned truncated blob content")
        blobs[object_id] = output[start:end]
        cursor = end + 1
    if cursor != len(output):
        raise ValueError("Git returned unexpected trailing blob data")
    return blobs


def _safe_relative_path(path: str) -> bool:
    value = PurePosixPath(path)
    return bool(path and not value.is_absolute() and ".." not in value.parts and "\x00" not in path)


def _runtime_path(path: str) -> bool:
    parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
    if any(part in _RUNTIME_COMPONENTS for part in parts):
        return True
    name = parts[-1] if parts else ""
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    if name in {".coverage", "config.toml", "coverage.xml"}:
        return True
    return name.endswith(_FORBIDDEN_SUFFIXES)


def _tracked_ignore_coverage(
    runner: CommandRunner,
    git: Path,
    root: Path,
) -> set[str] | None:
    """Return sentinels ignored specifically by the tracked root .gitignore."""

    request = b"".join(os.fsencode(path) + b"\0" for path in _IGNORE_SENTINELS)
    completed = _git(
        runner,
        git,
        root,
        "check-ignore",
        "--verbose",
        "--no-index",
        "--stdin",
        "-z",
        input_bytes=request,
    )
    if completed.returncode not in {0, 1}:
        return None
    fields = completed.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 4:
        return None
    covered: set[str] = set()
    for offset in range(0, len(fields), 4):
        source, _line, _pattern, raw_path = fields[offset : offset + 4]
        if source != b".gitignore":
            continue
        try:
            path = os.fsdecode(raw_path)
        except UnicodeError:
            return None
        if path in _IGNORE_SENTINELS:
            covered.add(path)
    return covered


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _placeholder_assignment(value: str) -> bool:
    normalized = value.strip().strip("<>[]{}()\"'").casefold()
    if not normalized:
        return True
    markers = ("example", "placeholder", "dummy", "fake", "redacted", "replace", "your-")
    return (
        normalized.startswith(".")
        or normalized in {"none", "null", "unset"}
        or any(marker in normalized for marker in markers)
    )


def _literal_secret_assignment(match: re.Match[str]) -> bool:
    value = match.group("value")
    if _placeholder_assignment(value):
        return False
    if match.group("quote"):
        return True
    # Unquoted dotenv/TOML-style values are accepted only when they look like
    # literal material, not Python expressions, identifiers, or prose labels.
    if len(value) < 12 or any(character in value for character in "()[]{}.:`"):
        return False
    if value.casefold() in {
        "api_key",
        "authorization",
        "password",
        "private_key",
        "secret",
        "token",
    }:
        return False
    return True


def _secret_findings(text: str) -> list[tuple[str, int]]:
    sanitized = text
    for sentinel in _KNOWN_TEST_SENTINELS:
        sanitized = sanitized.replace(sentinel, "[KNOWN_TEST_SENTINEL]")
    findings: list[tuple[str, int]] = []
    for match in _PRIVATE_KEY_RE.finditer(sanitized):
        findings.append(("private_key", _line_number(sanitized, match.start())))
    for rule, pattern in _TOKEN_RES:
        for match in pattern.finditer(sanitized):
            findings.append((rule, _line_number(sanitized, match.start())))
    for match in _CREDENTIAL_URL_RE.finditer(sanitized):
        findings.append(("credential_url", _line_number(sanitized, match.start())))
    for match in _ASSIGNMENT_RE.finditer(sanitized):
        if _literal_secret_assignment(match):
            findings.append(("secret_assignment", _line_number(sanitized, match.start())))
    return findings


def _environment_secret_findings(text: str) -> list[tuple[str, int]]:
    """Find an inherited live secret by exact value without displaying it."""

    findings: list[tuple[str, int]] = []
    for name in _LIVE_SECRET_NAMES:
        value = os.environ.get(name)
        if not value or len(value) < 8:
            continue
        start = 0
        while (offset := text.find(value, start)) >= 0:
            findings.append((f"inherited_value:{name}", _line_number(text, offset)))
            start = offset + len(value)
    return findings


def _normalised_spellings(path: Path) -> tuple[str, ...]:
    value = str(path.resolve(strict=False)).rstrip("\\/")
    if len(value) < 4:
        return ()
    return tuple(dict.fromkeys((value, value.replace("\\", "/"), value.replace("/", "\\"))))


def _absolute_setting(value: str) -> bool:
    return bool(
        value.startswith(("/", "\\\\", "//"))
        or re.match(r"^[A-Za-z]:[\\/]", value)
    )


def _machine_path_findings(text: str, root: Path) -> list[int]:
    offsets: set[int] = set()
    for path in (root, Path.home()):
        for spelling in _normalised_spellings(path):
            start = 0
            comparable = text.casefold() if os.name == "nt" else text
            needle = spelling.casefold() if os.name == "nt" else spelling
            while needle and (index := comparable.find(needle, start)) >= 0:
                offsets.add(index)
                start = index + len(needle)
    for pattern in (_WINDOWS_HOME_RE, _POSIX_HOME_RE):
        offsets.update(match.start() for match in pattern.finditer(text))
    return sorted({_line_number(text, offset) for offset in offsets})


def _path_setting_findings(text: str) -> list[int]:
    return [
        _line_number(text, match.start())
        for match in _PATH_SETTING_RE.finditer(text)
        if _absolute_setting(match.group("value"))
    ]


def _decode_text(path: str, payload: bytes) -> tuple[str | None, str | None]:
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix in _BINARY_SUFFIXES:
        return None, None
    if len(payload) > _MAX_TEXT_BYTES:
        return None, "tracked/nonignored text candidate exceeds the 5 MiB scan limit"
    if b"\x00" in payload[:8192]:
        return None, "unclassified binary content has no approved binary suffix"
    try:
        return payload.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "tracked/nonignored text is not UTF-8"


def _read_worktree_item(root: Path, path: str) -> bytes | None:
    if not _safe_relative_path(path):
        raise ValueError("Git returned an unsafe worktree path")
    candidate = root.joinpath(*PurePosixPath(path).parts)
    current = root
    for part in PurePosixPath(path).parts:
        current = current / part
        if current.is_symlink() or bool(getattr(current, "is_junction", lambda: False)()):
            raise ValueError("nonignored worktree content traverses a link or junction")
    if not candidate.exists():
        return None
    resolved = candidate.resolve(strict=True)
    if not _inside(resolved, root) or not resolved.is_file():
        raise ValueError("nonignored worktree content is not one regular in-repository file")
    return resolved.read_bytes()


def _scan_items(
    root: Path,
    tracked_entries: Sequence[_GitEntry],
    index_blobs: dict[str, bytes],
    worktree_paths: Sequence[str],
) -> tuple[list[CheckResult], list[_TextItem]]:
    checks: list[CheckResult] = []
    text_items: list[_TextItem] = []
    decode_errors: list[str] = []
    binary_count = 0
    seen: set[tuple[str, str]] = set()

    def add(path: str, payload: bytes, source: str) -> None:
        nonlocal binary_count
        identity = (path, hashlib.sha256(payload).hexdigest())
        if identity in seen:
            return
        seen.add(identity)
        text, error = _decode_text(path, payload)
        if error is not None:
            decode_errors.append(error)
        elif text is None:
            binary_count += 1
        else:
            text_items.append(_TextItem(path=path, text=text))

    for entry in tracked_entries:
        if entry.mode not in _REGULAR_GIT_MODES:
            continue
        payload = index_blobs.get(entry.object_id)
        if payload is None:
            raise ValueError("tracked blob content is missing")
        add(entry.path, payload, "index")
    for path in worktree_paths:
        payload = _read_worktree_item(root, path)
        if payload is not None:
            add(path, payload, "worktree")

    if decode_errors:
        checks.append(
            CheckResult(
                "content.encoding",
                "FAIL",
                f"{len(decode_errors)} tracked/nonignored files could not be safely text-scanned",
                "convert source text to UTF-8 or use an approved binary suffix",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "content.encoding",
                "PASS",
                f"all text candidates decoded safely; {binary_count} approved binary files skipped",
            )
        )
    return checks, text_items


def _format_locations(findings: Sequence[tuple[str, int, str]]) -> str:
    # Paths are repository-relative. Secret-like filenames are replaced with
    # a content-free hash so the report itself cannot leak a credential.
    labels: list[str] = []
    for path, line, rule in findings[:8]:
        safe_path = path
        if _secret_findings(path):
            safe_path = f"[redacted-path:{hashlib.sha256(path.encode()).hexdigest()[:12]}]"
        labels.append(f"{safe_path}:{line} ({rule})")
    suffix = " ..." if len(findings) > len(labels) else ""
    return ", ".join(labels) + suffix


def _source_checks(
    root: Path,
    git: Path,
    runner: CommandRunner,
    *,
    allow_dirty: bool,
) -> tuple[list[CheckResult], str | None]:
    checks: list[CheckResult] = []

    top = _git(runner, git, root, "rev-parse", "--show-toplevel")
    try:
        observed_root = Path(os.fsdecode(top.stdout.strip())).resolve(strict=True)
    except OSError:
        observed_root = Path("__invalid_repository_root__")
    if top.returncode != 0 or not _same_directory(observed_root, root):
        checks.append(
            CheckResult(
                "repository.identity",
                "FAIL",
                "the requested directory is not the exact Git worktree root",
                "run the preflight from the repository root",
                "prerequisite",
            )
        )
        return checks, None
    checks.append(CheckResult("repository.identity", "PASS", "Git worktree root is exact"))

    if _literal_systemdrive_directory_exists(root):
        checks.append(
            CheckResult(
                "runtime.literal_systemdrive",
                "FAIL",
                "literal %SystemDrive% directory exists at repository root",
                "remove this machine-local expansion artifact before portability acceptance",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "runtime.literal_systemdrive",
                "PASS",
                "literal %SystemDrive% directory is absent",
            )
        )

    revision = _git(runner, git, root, "rev-parse", "--verify", "HEAD")
    raw_commit = revision.stdout.strip().decode("ascii", errors="ignore")
    commit = raw_commit[:12] if revision.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", raw_commit) else None
    if commit is None:
        checks.append(
            CheckResult(
                "repository.commit",
                "FAIL",
                "repository has no valid HEAD commit",
                "create a reviewed baseline commit before portability acceptance",
                "hygiene",
            )
        )
    else:
        checks.append(CheckResult("repository.commit", "PASS", f"HEAD={commit}"))

    status = _git(
        runner,
        git,
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=no",
    )
    if status.returncode != 0:
        checks.append(
            CheckResult(
                "repository.clean",
                "FAIL",
                "Git could not inspect working-tree state",
                "verify the repository and Git installation",
                "prerequisite",
            )
        )
    else:
        dirty_entries = len(tuple(item for item in status.stdout.split(b"\0") if item))
        if dirty_entries and not allow_dirty:
            checks.append(
                CheckResult(
                    "repository.clean",
                    "FAIL",
                    f"working tree has {dirty_entries} changed/untracked entries",
                    "review or commit intended changes, or use --allow-dirty only during development",
                    "hygiene",
                )
            )
        elif dirty_entries:
            checks.append(
                CheckResult(
                    "repository.clean",
                    "PASS",
                    f"development override accepted {dirty_entries} changed/untracked entries",
                )
            )
        else:
            checks.append(CheckResult("repository.clean", "PASS", "working tree is clean"))

    diff_ok = True
    for arguments in (
        ("diff", "--no-ext-diff", "--check"),
        ("diff", "--cached", "--no-ext-diff", "--check"),
    ):
        if _git(runner, git, root, *arguments).returncode != 0:
            diff_ok = False
    checks.append(
        CheckResult(
            "repository.diff_check",
            "PASS" if diff_ok else "FAIL",
            "tracked diffs have no whitespace errors" if diff_ok else "tracked diffs contain whitespace errors",
            None if diff_ok else "run git diff --check and fix every reported line",
            None if diff_ok else "hygiene",
        )
    )

    index = _git(runner, git, root, "ls-files", "--stage", "-z")
    if index.returncode != 0:
        checks.append(
            CheckResult(
                "tracked.hygiene",
                "FAIL",
                "Git could not enumerate tracked files",
                "verify the index before portability acceptance",
                "prerequisite",
            )
        )
        return checks, commit
    try:
        entries = _parse_git_entries(index.stdout)
    except ValueError:
        checks.append(
            CheckResult(
                "tracked.hygiene",
                "FAIL",
                "Git index metadata is malformed or unresolved",
                "resolve index conflicts before portability acceptance",
                "hygiene",
            )
        )
        return checks, commit

    invalid_entries = [
        item
        for item in entries
        if item.mode not in _REGULAR_GIT_MODES
        or not _safe_relative_path(item.path)
        or _runtime_path(item.path)
    ]
    if invalid_entries:
        checks.append(
            CheckResult(
                "tracked.hygiene",
                "FAIL",
                f"{len(invalid_entries)} tracked entries are runtime, credential, link, or special-file content",
                "remove generated/runtime material from Git and add an exact ignore rule",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "tracked.hygiene",
                "PASS",
                f"{len(entries)} tracked entries contain no prohibited runtime or special-file state",
            )
        )

    ignore_coverage = _tracked_ignore_coverage(runner, git, root)
    missing_ignores = list(_IGNORE_SENTINELS) if ignore_coverage is None else [
        sentinel for sentinel in _IGNORE_SENTINELS if sentinel not in ignore_coverage
    ]
    if missing_ignores:
        checks.append(
            CheckResult(
                "runtime.ignore",
                "FAIL",
                f"{len(missing_ignores)} required runtime/credential sentinel paths are not ignored",
                "add narrow .gitignore rules for AsterCode, caches, local config, databases, and key files",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "runtime.ignore",
                "PASS",
                f"all {len(_IGNORE_SENTINELS)} runtime/credential sentinels are covered by tracked .gitignore rules",
            )
        )

    changed = _git(
        runner,
        git,
        root,
        "ls-files",
        "-z",
        "--modified",
        "--deleted",
        "--others",
        "--exclude-standard",
    )
    if changed.returncode != 0:
        checks.append(
            CheckResult(
                "content.scan",
                "FAIL",
                "Git could not enumerate changed/nonignored content",
                "verify the worktree before portability acceptance",
                "prerequisite",
            )
        )
        return checks, commit
    worktree_paths = [os.fsdecode(item) for item in changed.stdout.split(b"\0") if item]
    try:
        blobs = _read_index_blobs(runner, git, root, entries)
        scan_checks, text_items = _scan_items(root, entries, blobs, worktree_paths)
    except (OSError, ValueError):
        checks.append(
            CheckResult(
                "content.scan",
                "FAIL",
                "tracked/nonignored content could not be read safely",
                "remove links/special files and verify the Git object database",
                "hygiene",
            )
        )
        return checks, commit
    checks.extend(scan_checks)

    secret_locations: list[tuple[str, int, str]] = []
    machine_locations: list[tuple[str, int, str]] = []
    for item in text_items:
        secret_locations.extend(
            (item.path, line, rule) for rule, line in _secret_findings(item.text)
        )
        secret_locations.extend(
            (item.path, line, rule)
            for rule, line in _environment_secret_findings(item.text)
        )
        secret_locations.extend(
            (item.path, 0, f"filename_{rule}")
            for rule, _line in _secret_findings(item.path)
        )
        machine_locations.extend(
            (item.path, line, "machine_home")
            for line in _machine_path_findings(item.text, root)
        )
        if PurePosixPath(item.path).suffix.casefold() in {".json", ".toml", ".yaml", ".yml"}:
            machine_locations.extend(
                (item.path, line, "absolute_config_path")
                for line in _path_setting_findings(item.text)
            )

    if secret_locations:
        checks.append(
            CheckResult(
                "content.secrets",
                "FAIL",
                f"probable secret material detected at {_format_locations(secret_locations)}; values were not displayed",
                "remove and rotate the credential, then inspect Git history before publishing",
                "hygiene",
            )
        )
    else:
        checks.append(CheckResult("content.secrets", "PASS", "no probable secret material detected"))
    if machine_locations:
        checks.append(
            CheckResult(
                "content.machine_paths",
                "FAIL",
                f"machine-specific paths detected at {_format_locations(machine_locations)}; values were not displayed",
                "replace local paths with repository-relative values or explicit placeholders",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "content.machine_paths",
                "PASS",
                "no user-home, checkout-root, or absolute tracked config paths detected",
            )
        )

    tracked_paths = {item.path for item in entries}
    required_files = ("pyproject.toml", "uv.lock")
    missing_files = [name for name in required_files if name not in tracked_paths]
    if missing_files:
        checks.append(
            CheckResult(
                "dependencies.manifest",
                "FAIL",
                f"{len(missing_files)} required dependency manifest/lock files are not tracked",
                "track pyproject.toml and the exact uv.lock before portability acceptance",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "dependencies.manifest",
                "PASS",
                "pyproject.toml and uv.lock are tracked",
            )
        )
    handoff_files = (
        ".gitignore",
        "AGENTS.md",
        "HANDOFF.md",
        "README.md",
        "docs/implementation-plan.md",
        "docs/threat-model.md",
        "docs/release-checklist.md",
    )
    missing_handoff = [name for name in handoff_files if name not in tracked_paths]
    if missing_handoff:
        checks.append(
            CheckResult(
                "handoff.manifest",
                "FAIL",
                f"{len(missing_handoff)} required handoff files are not tracked",
                "track the AGENTS, HANDOFF, README, implementation, threat-model, and release-checklist files",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "handoff.manifest",
                "PASS",
                "all required AI-agent handoff documents are tracked",
            )
        )
    return checks, commit


def _python_check() -> CheckResult:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    # This pre-install script may be launched before the package metadata is enforced.
    if sys.version_info < (3, 12):  # noqa: UP036
        return CheckResult(
            "python.version",
            "FAIL",
            f"Python {version} is below the required 3.12",
            "install Python 3.12+ and rerun this script",
            "prerequisite",
        )
    return CheckResult("python.version", "PASS", f"Python {version} satisfies >=3.12")


def _uv_check(root: Path, *, required: bool) -> CheckResult:
    candidate = _trusted_command("uv", root)
    if candidate is not None:
        return CheckResult("uv.available", "PASS", "uv is available outside the repository")
    return CheckResult(
        "uv.available",
        "FAIL" if required else "WARN",
        "uv is not available from an external executable path",
        "install uv, then run: uv sync --extra dev --extra browser --frozen",
        "prerequisite" if required else None,
    )


def _pinned_image(root: Path) -> str | None:
    config = root / "config.example.toml"
    if tomllib is None or not config.is_file():
        return None
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
        image = data["security"]["process"]["container_image"]
    except (KeyError, OSError, TypeError, UnicodeError, tomllib.TOMLDecodeError):
        return None
    return image if isinstance(image, str) and _PINNED_IMAGE_RE.fullmatch(image) else None


def _docker_checks(
    root: Path,
    runner: CommandRunner,
) -> list[CheckResult]:
    image = _pinned_image(root)
    checks: list[CheckResult] = []
    if image is None:
        checks.append(
            CheckResult(
                "docker.pinned_image_config",
                "FAIL",
                "config.example.toml has no valid RepoDigest-pinned container image",
                "configure image@sha256:<64 lowercase hex> before the demo",
                "hygiene",
            )
        )
    else:
        checks.append(
            CheckResult(
                "docker.pinned_image_config",
                "PASS",
                f"container image is pinned to sha256:{image.rsplit(':', 1)[-1][:12]}...",
            )
        )

    docker = _trusted_command("docker", root)
    if docker is None:
        checks.append(
            CheckResult(
                "docker.engine",
                "FAIL",
                "Docker CLI is unavailable from an external executable path",
                "install/start Docker Desktop or a local Linux Docker engine",
                "prerequisite",
            )
        )
        checks.append(
            CheckResult(
                "docker.image_present",
                "FAIL",
                "pinned image presence cannot be checked without a local Docker engine",
                "start Docker, then explicitly pull the configured RepoDigest outside this preflight",
                "prerequisite",
            )
        )
        return checks

    endpoint = "npipe:////./pipe/docker_engine" if os.name == "nt" else "unix:///var/run/docker.sock"
    environment = _base_environment()
    environment["DOCKER_HOST"] = endpoint
    version = runner(
        [str(docker), "--host", endpoint, "version", "--format", "{{.Server.Os}}"],
        root,
        environment,
        None,
        12,
    )
    engine_os = version.stdout.strip().decode("ascii", errors="ignore").casefold()
    if version.returncode != 0 or engine_os != "linux":
        checks.append(
            CheckResult(
                "docker.engine",
                "FAIL",
                "the forced local Docker endpoint is unavailable or is not a Linux engine",
                "start Docker in Linux-container mode; remote Docker contexts are intentionally ignored",
                "prerequisite",
            )
        )
        checks.append(
            CheckResult(
                "docker.image_present",
                "FAIL",
                "pinned image presence cannot be verified without the local Linux engine",
                "restore the local engine before checking the configured RepoDigest",
                "prerequisite",
            )
        )
        return checks
    checks.append(
        CheckResult(
            "docker.engine",
            "PASS",
            "forced local Docker endpoint reports a Linux engine",
        )
    )
    if image is None:
        checks.append(
            CheckResult(
                "docker.image_present",
                "FAIL",
                "pinned image presence cannot be checked because config is invalid",
                "fix the RepoDigest configuration first",
                "hygiene",
            )
        )
        return checks

    inspect = runner(
        [
            str(docker),
            "--host",
            endpoint,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image,
        ],
        root,
        environment,
        None,
        12,
    )
    image_id = inspect.stdout.strip().decode("ascii", errors="ignore")
    if inspect.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        checks.append(
            CheckResult(
                "docker.image_present",
                "PASS",
                f"exact pinned image is present locally as sha256:{image_id[7:19]}...",
            )
        )
    else:
        checks.append(
            CheckResult(
                "docker.image_present",
                "FAIL",
                "exact pinned image is not present in the local engine",
                "explicitly pull the RepoDigest before going offline; this preflight never pulls",
                "prerequisite",
            )
        )
    return checks


def run_preflight(
    root: Path,
    *,
    profile: Profile = "source",
    allow_dirty: bool = False,
    runner: CommandRunner = _run_command,
) -> PreflightReport:
    """Evaluate one checkout without writing files or contacting the network."""

    checks: list[CheckResult] = [_python_check()]
    try:
        workspace = root.expanduser().resolve(strict=True)
    except OSError:
        workspace = root.expanduser().resolve(strict=False)
    if not workspace.is_dir():
        checks.append(
            CheckResult(
                "repository.identity",
                "FAIL",
                "requested root is not an existing directory",
                "pass the exact repository root with --root",
                "prerequisite",
            )
        )
        return _report(profile, checks, None)

    git = _trusted_command("git", workspace)
    if git is None:
        checks.append(
            CheckResult(
                "git.available",
                "FAIL",
                "Git is unavailable from an external executable path",
                "install system Git and rerun from a cloned repository",
                "prerequisite",
            )
        )
        checks.append(_uv_check(workspace, required=profile == "demo"))
        if profile == "demo":
            checks.extend(_docker_checks(workspace, runner))
        return _report(profile, checks, None)
    checks.append(CheckResult("git.available", "PASS", "system Git is available outside the repository"))

    source_checks, commit = _source_checks(
        workspace,
        git,
        runner,
        allow_dirty=allow_dirty,
    )
    checks.extend(source_checks)
    checks.append(_uv_check(workspace, required=profile == "demo"))
    if profile == "demo":
        checks.extend(_docker_checks(workspace, runner))
    return _report(profile, checks, commit)


def _report(
    profile: Profile,
    checks: Sequence[CheckResult],
    commit: str | None,
) -> PreflightReport:
    prerequisite_failure = any(
        item.status == "FAIL" and item.failure_kind == "prerequisite"
        for item in checks
    )
    hygiene_failure = any(item.status == "FAIL" for item in checks)
    exit_code = 2 if prerequisite_failure else 1 if hygiene_failure else 0
    return PreflightReport(
        schema_version=1,
        profile=profile,
        passed=exit_code == 0,
        exit_code=exit_code,
        commit=commit,
        checks=tuple(checks),
        next_commands=(
            "uv sync --extra dev --extra browser --frozen",
            "uv run astercode doctor --root .",
            "uv run python scripts/resume_demo.py --backend docker --cleanup",
        ),
    )


def render_report(report: PreflightReport, output_format: OutputFormat) -> str:
    if output_format == "json":
        return json.dumps(
            report.as_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    outcome = "PASS" if report.passed else "FAIL"
    lines = [f"AsterCode portability preflight [{report.profile}]: {outcome}"]
    if report.commit is not None:
        lines.append(f"commit: {report.commit}")
    for item in report.checks:
        lines.append(f"[{item.status}] {item.check_id}: {item.detail}")
        if item.remediation is not None:
            lines.append(f"  fix: {item.remediation}")
    lines.append("next commands:")
    lines.extend(f"  {command}" for command in report.next_commands)
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", choices=("source", "demo"), default="source")
    parser.add_argument("--format", dest="output_format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="development-only: allow changed/untracked files while retaining every content scan",
    )
    arguments = parser.parse_args(argv)
    report = run_preflight(
        arguments.root,
        profile=arguments.profile,
        allow_dirty=arguments.allow_dirty,
    )
    print(render_report(report, arguments.output_format))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
