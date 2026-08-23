"""Host-enforced security helpers.

Nothing in this module treats a model/tool supplied label as authoritative.
Callers pass the concrete path or action that will actually be executed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

REDACTED = "[REDACTED]"
GENESIS_AUDIT_HASH = "0" * 64


class SecurityError(RuntimeError):
    """Base class for fail-closed security validation errors."""


class PathAuthorizationError(SecurityError):
    """A path cannot be proven to stay inside an authorized root."""


class PathChangedError(PathAuthorizationError):
    """A validated path or ancestor changed before the side effect."""


class SecretDetectedError(SecurityError):
    """Secret-looking material was supplied where only references are allowed."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int

    @classmethod
    def capture(cls, path: Path) -> FileIdentity:
        stat = path.stat(follow_symlinks=True)
        return cls(
            device=stat.st_dev,
            inode=stat.st_ino,
            mode=stat.st_mode,
            size=stat.st_size,
            modified_ns=stat.st_mtime_ns,
        )


@dataclass(frozen=True, slots=True)
class AuthorizedPath:
    requested: str
    absolute: Path
    resolved: Path
    root: Path
    exists: bool
    identity_path: Path
    identity: FileIdentity

    def revalidate(
        self,
        authorized_roots: Iterable[str | Path],
        *,
        must_exist: bool | None = None,
        reject_unc: bool = True,
    ) -> AuthorizedPath:
        """Resolve again immediately before use and detect an ancestor swap."""

        checked = canonicalize_authorized_path(
            self.absolute,
            authorized_roots,
            must_exist=self.exists if must_exist is None else must_exist,
            reject_unc=reject_unc,
        )
        if _path_key(checked.resolved) != _path_key(self.resolved):
            raise PathChangedError("resolved path changed after policy validation")
        if _path_key(checked.root) != _path_key(self.root):
            raise PathChangedError("authorized root binding changed")
        if (
            _path_key(checked.identity_path) != _path_key(self.identity_path)
            or checked.identity != self.identity
        ):
            raise PathChangedError("target or nearest existing ancestor changed")
        return checked


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((_path_key(candidate), _path_key(root)))
    except ValueError:
        return False
    return common == _path_key(root)


def _reject_windows_special_path(raw: str) -> None:
    normal = raw.replace("/", "\\")
    if normal.startswith(("\\\\", "\\?\\", "\\.\\", "GLOBALROOT\\")):
        raise PathAuthorizationError("UNC and Windows device paths are not authorized")
    path = Path(raw)
    if path.drive and not path.is_absolute():
        raise PathAuthorizationError("drive-relative Windows paths are ambiguous")
    for index, part in enumerate(path.parts):
        if ":" in part and not (index == 0 and re.fullmatch(r"[A-Za-z]:\\?", part)):
            raise PathAuthorizationError("alternate data streams are not authorized")


def _nearest_existing(path: Path) -> Path:
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            raise PathAuthorizationError("no existing ancestor can anchor the path")
        current = parent
    try:
        return current.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathAuthorizationError(f"cannot resolve existing ancestor: {exc}") from exc


def canonicalize_authorized_path(
    requested: str | Path,
    authorized_roots: Iterable[str | Path],
    *,
    cwd: str | Path | None = None,
    must_exist: bool = False,
    reject_unc: bool = True,
) -> AuthorizedPath:
    """Canonicalize a path and prove its resolved location is authorized.

    For a new file, the closest existing ancestor is resolved so symlink,
    junction and mount-point escapes are caught.  The returned identity is
    intended to be checked again immediately before a side effect.
    """

    raw = os.fspath(requested)
    if not raw or "\x00" in raw:
        raise PathAuthorizationError("path is blank or contains NUL")
    if os.name == "nt" and reject_unc:
        _reject_windows_special_path(raw)

    roots: list[Path] = []
    for root_value in authorized_roots:
        try:
            root = Path(root_value).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PathAuthorizationError(f"cannot resolve authorized root: {exc}") from exc
        if not root.is_dir():
            raise PathAuthorizationError(f"authorized root is not a directory: {root}")
        roots.append(root)
    if not roots:
        raise PathAuthorizationError("no authorized roots are configured")

    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        base = Path(cwd).expanduser() if cwd is not None else roots[0]
        if not base.is_absolute():
            base = roots[0] / base
        candidate = base / candidate
    try:
        absolute = Path(os.path.abspath(candidate))
        resolved = absolute.resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise PathAuthorizationError(f"cannot resolve path: {exc}") from exc

    if must_exist and not resolved.exists():
        raise PathAuthorizationError(f"required path does not exist: {resolved}")
    matching = [root for root in roots if _is_within(resolved, root)]
    if not matching:
        raise PathAuthorizationError("resolved path is outside all authorized roots")
    # Bind to the most specific nested root.
    root = max(matching, key=lambda value: len(_path_key(value)))
    anchor = resolved if resolved.exists() else _nearest_existing(absolute)
    if not _is_within(anchor, root):
        raise PathAuthorizationError("nearest existing ancestor escapes authorized root")
    try:
        identity = FileIdentity.capture(anchor)
    except OSError as exc:
        raise PathAuthorizationError(f"cannot stat resolved path anchor: {exc}") from exc
    return AuthorizedPath(
        requested=raw,
        absolute=absolute,
        resolved=resolved,
        root=root,
        exists=resolved.exists(),
        identity_path=anchor,
        identity=identity,
    )


def assert_authorized_paths(
    paths: Iterable[str | Path],
    authorized_roots: Iterable[str | Path],
    *,
    cwd: str | Path | None = None,
    must_exist: bool = False,
    reject_unc: bool = True,
) -> list[AuthorizedPath]:
    return [
        canonicalize_authorized_path(
            path,
            authorized_roots,
            cwd=cwd,
            must_exist=must_exist,
            reject_unc=reject_unc,
        )
        for path in paths
    ]


_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_TOKEN_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[opusr]|github_pat)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
)
_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?:api[_-]?key|access[_-]?token|auth(?:orization)?|password|passwd|"
    r"secret|private[_-]?key)\s*[=:]\s*[\"']?)"
    r"(?P<value>[^\s,;\"']{4,})",
    re.IGNORECASE,
)
_CREDENTIAL_URL = re.compile(
    r"(?P<prefix>[a-z][a-z0-9+.-]*://[^\s/:@]+:)(?P<password>[^\s/@]+)(?=@)",
    re.IGNORECASE,
)
_SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:api_?key|access_?token|refresh_?token|authorization|password|passwd|"
    r"secret|private_?key|cookie)(?:$|_)",
    re.IGNORECASE,
)
_PROMPT_INJECTION = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous|disregard\s+(?:the\s+)?(?:system|user)\s+instruction|上传(?:密钥|token|密码)|upload\s+(?:the\s+)?(?:api|ssh)\s+key|disable\s+(?:host[- ]key|security|audit)|关闭(?:校验|审计)|approve\s+(?:this|the)\s+command)",
    re.IGNORECASE,
)


def _sensitive_mapping_key(key: object) -> bool:
    text = str(key)
    if text.lower().endswith(("_env", "_ref", "_name")):
        return False
    return bool(_SENSITIVE_KEY.search(text))


class SecretRedactor:
    """Redact common credentials from text and nested structured data."""

    def __init__(self, replacement: str = REDACTED) -> None:
        if not replacement:
            raise ValueError("replacement cannot be empty")
        self.replacement = replacement

    def redact_text(self, value: str) -> str:
        redacted = (
            _PRIVATE_KEY.sub(self.replacement, value)
            if "PRIVATE KEY" in value.upper()
            else value
        )
        for pattern in _TOKEN_PATTERNS:
            redacted = pattern.sub(self.replacement, redacted)
        lowered = redacted.lower()
        if any(
            marker in lowered
            for marker in (
                "api_key",
                "api-key",
                "apikey",
                "access_token",
                "access-token",
                "authorization",
                "password",
                "passwd",
                "secret",
                "private_key",
                "private-key",
            )
        ):
            redacted = _ASSIGNMENT.sub(
                lambda match: f"{match.group('prefix')}{self.replacement}", redacted
            )
        if "://" in redacted and "@" in redacted:
            redacted = _CREDENTIAL_URL.sub(
                lambda match: f"{match.group('prefix')}{self.replacement}", redacted
            )
        return redacted

    def redact(self, value: Any) -> Any:
        return self._redact(value, seen=set())

    def _redact(self, value: Any, *, seen: set[int]) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bytes):
            return self.redact_text(value.decode("utf-8", errors="replace"))
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in seen:
                return "[REDACTED:CYCLE]"
            seen.add(identity)
            result = {
                str(key): (
                    self.replacement
                    if _sensitive_mapping_key(key)
                    else self._redact(item, seen=seen)
                )
                for key, item in value.items()
            }
            seen.remove(identity)
            return result
        if isinstance(value, (list, tuple, set, frozenset)):
            identity = id(value)
            if identity in seen:
                return ["[REDACTED:CYCLE]"]
            seen.add(identity)
            result_list = [self._redact(item, seen=seen) for item in value]
            seen.remove(identity)
            return result_list
        return value


def redact_secrets(value: Any, replacement: str = REDACTED) -> Any:
    return SecretRedactor(replacement).redact(value)


def contains_probable_secret(value: Any) -> bool:
    marker = "__ASTER_SECRET_MARKER__"
    return SecretRedactor(marker).redact(value) != value


def contains_prompt_injection(value: Any) -> bool:
    """Detect common control-text patterns in untrusted tool/page content."""
    if isinstance(value, Mapping):
        return any(contains_prompt_injection(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_prompt_injection(item) for item in value)
    return isinstance(value, str) and bool(_PROMPT_INJECTION.search(value))


def require_secret_reference(name: str, value: str) -> str:
    """Accept an environment/keychain reference and reject inline material."""

    if not value or any(char.isspace() for char in value) or "=" in value:
        raise SecretDetectedError(f"{name} must be a secret reference, not a value")
    if contains_probable_secret(value):
        raise SecretDetectedError(f"{name} looks like inline secret material")
    return value


def _normalise_for_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _normalise_for_json(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalise_for_json(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalised = [_normalise_for_json(item) for item in value]
        return sorted(normalised, key=lambda item: canonical_json(item))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return _normalise_for_json(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not canonical")
        return value.isoformat(timespec="microseconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite floats are not canonical")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        _normalise_for_json(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def normalize_action(action: Mapping[str, Any]) -> dict[str, Any]:
    normalised = _normalise_for_json(action)
    if not isinstance(normalised, dict):
        raise TypeError("an action must normalise to an object")
    return normalised


def action_hash(action: Mapping[str, Any]) -> str:
    return sha256_hex(f"astercode-action-v1\n{canonical_json(normalize_action(action))}")


def generate_nonce() -> str:
    return secrets.token_urlsafe(32)


def secure_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def audit_entry_hash(
    *,
    previous_hash: str,
    audit_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    created_at: datetime,
    session_id: str | None = None,
    action_id: str | None = None,
) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", previous_hash):
        raise ValueError("previous audit hash is malformed")
    body = {
        "action_id": action_id,
        "audit_id": audit_id,
        "created_at": created_at,
        "event_type": event_type,
        "payload": normalize_action(payload),
        "previous_hash": previous_hash,
        "session_id": session_id,
    }
    return sha256_hex(f"astercode-audit-v1\n{canonical_json(body)}")


def is_forbidden_network_address(value: str) -> bool:
    """Return true for loopback/private/link-local/multicast/metadata targets."""

    try:
        address = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    metadata = {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
    return bool(
        address in metadata
        or address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def protected_path_reason(path: str | Path, authorized_roots: Iterable[str | Path]) -> str | None:
    """Return a reason when a filesystem path is runtime state or a secret.

    Git metadata is intentionally handled only by the Git adapter; raw fs
    tools must not expose or mutate it.  ``.env.example`` remains usable as a
    documentation file, while real dotenv files and common key material are
    always protected.
    """
    try:
        candidate = Path(path).expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return "path cannot be resolved"
    # Use every component, case-insensitively on all hosts.  This protects
    # nested repositories and remains effective if authorized roots overlap.
    parts = {os.path.normcase(part).casefold() for part in candidate.parts}
    if ".astercode" in parts:
        return "protected runtime directory: .astercode"
    if ".git" in parts:
        return "protected runtime directory: .git"
    name = os.path.normcase(candidate.name).casefold()
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "dotenv files are protected"
    if name in {"id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys"} or name.endswith((".pem", ".key", ".p12", ".pfx")):
        return "credential/key material is protected"
    return None


__all__ = [
    "AuthorizedPath",
    "FileIdentity",
    "GENESIS_AUDIT_HASH",
    "PathAuthorizationError",
    "PathChangedError",
    "REDACTED",
    "SecretDetectedError",
    "SecretRedactor",
    "SecurityError",
    "action_hash",
    "assert_authorized_paths",
    "audit_entry_hash",
    "canonical_json",
    "canonicalize_authorized_path",
    "contains_probable_secret",
    "contains_prompt_injection",
    "generate_nonce",
    "is_forbidden_network_address",
    "normalize_action",
    "protected_path_reason",
    "redact_secrets",
    "require_secret_reference",
    "secure_equal",
    "sha256_hex",
]
