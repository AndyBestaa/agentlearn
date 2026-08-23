"""Restricted SSH/SFTP tools with an offline deterministic backend.

The production default is deliberately *disabled*.  ``SSHTools`` accepts an
injected backend so security and orchestration code can be tested without a
socket, private key, SSH agent, or real host.  A real transport must implement
the small protocols below and still pass the same allowlist, known_hosts and
fingerprint checks; this module does not provide an arbitrary shell fallback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import posixpath
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, cast

from ..config import SSHHostConfig
from .base import ToolResult, ToolSpec, new_action_id, timed_result


class SSHUnavailable(RuntimeError):
    """Raised by a transport that is not enabled or cannot be reached."""


class SSHHostKeyError(SSHUnavailable):
    """Raised when the peer key is absent, changed, or not allowlisted."""


@dataclass(frozen=True)
class RemoteStat:
    """Minimal remote metadata used for transfer verification."""

    size: int
    sha256: str
    mode: int = 0o644
    owner: str | None = None


@dataclass(frozen=True)
class RemoteExec:
    """A transport-independent command result."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = 0
    status: str = "completed"
    side_effects: tuple[str, ...] = ("remote_process",)
    metadata: Mapping[str, Any] = field(default_factory=dict)


class SSHSession(Protocol):
    """Narrow operations needed by the host adapter."""

    @property
    def fingerprint(self) -> str: ...

    def exec(self, command: str, timeout: float) -> RemoteExec: ...

    def start(self, command: str) -> str: ...

    def poll(self, handle: str) -> RemoteExec: ...

    def stop(self, handle: str) -> bool: ...

    def upload(self, remote_path: str, data: bytes) -> RemoteStat: ...

    def download(self, remote_path: str) -> bytes: ...

    def stat(self, remote_path: str) -> RemoteStat: ...

    def close(self) -> None: ...


class SSHBackend(Protocol):
    """Injectable transport boundary.

    Implementations must not silently disable host-key verification.  The
    adapter verifies ``session.fingerprint`` before any operation.
    """

    def connect(self, host: SSHHostConfig) -> SSHSession: ...


class DisabledSSHBackend:
    """Safe default: never opens a network connection."""

    def connect(self, host: SSHHostConfig) -> SSHSession:
        del host
        raise SSHUnavailable("LIVE SSH NOT VERIFIED: no SSH transport is enabled")


def _normalise_remote_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("remote path must be a non-empty string without NUL")
    # Remote paths are not local filesystem authorities.  Still reject an
    # escape from a POSIX root-like namespace rather than passing ambiguous
    # traversal to an injected backend.
    path = posixpath.normpath(value.strip().replace("\\", "/"))
    if path == ".." or path.startswith("../"):
        raise PermissionError("remote path cannot escape its root")
    return path


def _normalise_fingerprint(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("sha256:"):
        return "sha256:" + value[7:].rstrip("=")
    if len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value):
        return value.lower()
    return value


def _key_blob_fingerprint(key_type: str, encoded_key: str) -> str | None:
    """Derive OpenSSH's SHA256 fingerprint from a known_hosts key field."""

    del key_type  # the encoded blob already includes the key type structure
    try:
        blob = base64.b64decode(encoded_key.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        return None
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "sha256:" + digest


def _known_hosts_fingerprints(path: Path, host: SSHHostConfig) -> set[str]:
    """Read only exact host entries from a known_hosts file.

    Hashed host names cannot be safely matched without the original host-key
    salt, so they are ignored and the caller fails closed.  A test fixture may
    put a literal fingerprint in the key field; accepting that form makes the
    offline backend deterministic while retaining exact hostname matching.
    """

    result: set[str] = set()
    expected_names = {host.hostname.lower(), f"[{host.hostname.lower()}]:{host.port}"}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SSHHostKeyError(f"cannot read strict known_hosts: {type(exc).__name__}") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 2:
            continue
        names = fields[0].split(",")
        if not any(name.lower() in expected_names for name in names):
            continue
        # Some deterministic test fixtures use ``host SHA256:...``.  A normal
        # OpenSSH line has host, key type, and base64 key blob.
        for field_value in fields[1:]:
            candidate = _normalise_fingerprint(field_value)
            if candidate.startswith("sha256:") or len(candidate) == 64:
                result.add(candidate)
        if len(fields) >= 3:
            derived = _key_blob_fingerprint(fields[1], fields[2])
            if derived:
                result.add(derived)
    return result


def verify_host_key(host: SSHHostConfig, actual_fingerprint: str) -> str:
    """Verify one peer key against config and strict ``known_hosts``.

    A mismatch is a hard failure.  The normalized value is returned for
    logging and deterministic tests; callers must not downgrade this check to
    a warning or silently accept a changed key.
    """

    if host.known_hosts is None or not host.known_hosts.is_file() or host.known_hosts.is_symlink():
        raise SSHHostKeyError("strict known_hosts file is required")
    configured = _normalise_fingerprint(host.host_key_fingerprint)
    actual = _normalise_fingerprint(actual_fingerprint)
    if actual != configured:
        raise SSHHostKeyError("SSH host key changed or does not match configured fingerprint")
    known = _known_hosts_fingerprints(host.known_hosts, host)
    if configured not in known or actual not in known:
        raise SSHHostKeyError("SSH host key fingerprint is not present in strict known_hosts")
    return actual


def _inside_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


@dataclass(frozen=True)
class FakeCommand:
    """Deterministic command behavior for tests and replay fixtures."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = 0
    delay: float = 0.0
    polls_until_complete: int = 0
    never_complete: bool = False


@dataclass
class _FakeProcess:
    command: FakeCommand
    polls: int = 0
    stopped: bool = False


@dataclass
class FakeSSHHost:
    """In-memory host state; no sockets or credentials are used."""

    fingerprint: str
    files: dict[str, bytes] = field(default_factory=dict)
    commands: dict[str, FakeCommand | Mapping[str, Any] | Callable[[str], Any]] = field(default_factory=dict)


def _coerce_fake_files(values: Mapping[str, bytes | str]) -> dict[str, bytes]:
    return {
        _normalise_remote_path(key): (value.encode("utf-8") if isinstance(value, str) else bytes(value))
        for key, value in values.items()
    }


def _coerce_fake_command(value: FakeCommand | Mapping[str, Any] | Callable[[str], Any], command: str) -> FakeCommand:
    if isinstance(value, FakeCommand):
        return value
    if callable(value):
        value = value(command)
    if isinstance(value, Mapping):
        return FakeCommand(
            stdout=str(value.get("stdout", "")),
            stderr=str(value.get("stderr", "")),
            exit_code=value.get("exit_code", 0),
            delay=float(value.get("delay", 0.0)),
            polls_until_complete=int(value.get("polls_until_complete", 0)),
            never_complete=bool(value.get("never_complete", False)),
        )
    return FakeCommand(stdout=str(value))


class FakeSSHSession:
    def __init__(self, state: FakeSSHHost) -> None:
        self.state = state
        self._processes: dict[str, _FakeProcess] = {}
        self._closed = False
        self._counter = 0

    @property
    def fingerprint(self) -> str:
        return self.state.fingerprint

    def _ensure_open(self) -> None:
        if self._closed:
            raise SSHUnavailable("SSH session is closed")

    def _command(self, command: str) -> FakeCommand:
        configured = self.state.commands.get(command)
        if configured is not None:
            return _coerce_fake_command(configured, command)
        if command.startswith("echo "):
            return FakeCommand(stdout=command[5:] + "\n")
        if command.startswith("printf "):
            return FakeCommand(stdout=command[7:].strip("'\"") )
        return FakeCommand(stderr=f"command not found: {command}\n", exit_code=127)

    @staticmethod
    def _result(command: FakeCommand, *, timeout: float | None = None, polls: int = 0) -> RemoteExec:
        if timeout is not None and (command.never_complete or command.delay > timeout):
            raise TimeoutError(f"remote command exceeded {timeout}s")
        if command.never_complete or polls < command.polls_until_complete:
            return RemoteExec(stdout="", stderr="", exit_code=None, status="running")
        return RemoteExec(stdout=command.stdout, stderr=command.stderr, exit_code=command.exit_code, status="completed")

    def exec(self, command: str, timeout: float) -> RemoteExec:
        self._ensure_open()
        return self._result(self._command(command), timeout=timeout)

    def start(self, command: str) -> str:
        self._ensure_open()
        self._counter += 1
        handle = f"fake-ssh-process-{self._counter}"
        self._processes[handle] = _FakeProcess(self._command(command))
        return handle

    def poll(self, handle: str) -> RemoteExec:
        self._ensure_open()
        process = self._processes.get(handle)
        if process is None:
            raise KeyError("unknown remote process handle")
        if process.stopped:
            return RemoteExec(stderr="remote process stopped\n", exit_code=None, status="cancelled")
        process.polls += 1
        result = self._result(process.command, polls=process.polls)
        if result.status == "completed":
            self._processes.pop(handle, None)
        return result

    def stop(self, handle: str) -> bool:
        self._ensure_open()
        process = self._processes.get(handle)
        if process is None:
            return False
        process.stopped = True
        self._processes.pop(handle, None)
        return True

    def upload(self, remote_path: str, data: bytes) -> RemoteStat:
        self._ensure_open()
        path = _normalise_remote_path(remote_path)
        self.state.files[path] = bytes(data)
        return self.stat(path)

    def download(self, remote_path: str) -> bytes:
        self._ensure_open()
        path = _normalise_remote_path(remote_path)
        try:
            return bytes(self.state.files[path])
        except KeyError as exc:
            raise FileNotFoundError(path) from exc

    def stat(self, remote_path: str) -> RemoteStat:
        self._ensure_open()
        path = _normalise_remote_path(remote_path)
        try:
            data = self.state.files[path]
        except KeyError as exc:
            raise FileNotFoundError(path) from exc
        return RemoteStat(size=len(data), sha256=hashlib.sha256(data).hexdigest())

    def close(self) -> None:
        self._closed = True
        self._processes.clear()


class FakeSSHBackend:
    """Deterministic in-memory SSH backend for offline tests.

    ``hosts`` may map host IDs to :class:`FakeSSHHost` instances or plain
    dictionaries.  The convenience constructor also accepts one host via
    ``host_id``/``fingerprint``.
    """

    def __init__(
        self,
        hosts: Mapping[str, FakeSSHHost | Mapping[str, Any]] | None = None,
        *,
        host_id: str | None = None,
        fingerprint: str | None = None,
        files: Mapping[str, bytes | str] | None = None,
        commands: Mapping[str, FakeCommand | Mapping[str, Any] | Callable[[str], Any]] | None = None,
    ) -> None:
        self.hosts: dict[str, FakeSSHHost] = {}
        for item_id, value in (hosts or {}).items():
            self.add_host(item_id, value)
        if host_id is not None:
            if fingerprint is None:
                raise ValueError("fingerprint is required with host_id")
            self.add_host(host_id, fingerprint=fingerprint, files=files, commands=commands)

    def add_host(
        self,
        host_id: str,
        state: FakeSSHHost | Mapping[str, Any] | None = None,
        *,
        fingerprint: str | None = None,
        files: Mapping[str, bytes | str] | None = None,
        commands: Mapping[str, FakeCommand | Mapping[str, Any] | Callable[[str], Any]] | None = None,
    ) -> FakeSSHHost:
        if isinstance(state, FakeSSHHost):
            host = state
        elif isinstance(state, Mapping):
            host = FakeSSHHost(
                fingerprint=str(state.get("fingerprint", fingerprint or "")),
                files=_coerce_fake_files(cast(Mapping[str, bytes | str], state.get("files") or files or {})),
                commands=dict(state.get("commands") or commands or {}),
            )
        else:
            if fingerprint is None:
                raise ValueError("fingerprint is required")
            host = FakeSSHHost(fingerprint=fingerprint, files=_coerce_fake_files(cast(Mapping[str, bytes | str], files or {})), commands=dict(commands or {}))
        host.files = _coerce_fake_files(cast(Mapping[str, bytes | str], host.files))
        self.hosts[host_id] = host
        return host

    def set_fingerprint(self, host_id: str, fingerprint: str) -> None:
        self.hosts[host_id].fingerprint = fingerprint

    def connect(self, host: SSHHostConfig) -> SSHSession:
        try:
            state = self.hosts[host.host_id]
        except KeyError as exc:
            raise SSHUnavailable("fake host is not registered") from exc
        return FakeSSHSession(state)


FakeSSHServer = FakeSSHBackend


class SSHTools:
    """Host adapter enforcing allowlist, known_hosts, and transfer hashes."""

    specs: tuple[ToolSpec, ...] = (
        ToolSpec("ssh.test_connection", "Test an explicitly allowlisted SSH host.", "ssh.read", ("network",), "P3", idempotent=True, schema={"type": "object", "properties": {"host_id": {"type": "string"}}, "required": ["host_id"], "additionalProperties": False}),
        ToolSpec("ssh.exec", "Run one approved command on an allowlisted SSH host.", "ssh.exec", ("remote_process",), "P3", idempotent=False, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "command": {"type": "string"}, "timeout": {"type": "number", "minimum": 0.1}}, "required": ["host_id", "command", "timeout"], "additionalProperties": False}),
        ToolSpec("ssh.start", "Start one approved long-running command and return a remote handle.", "ssh.exec", ("remote_process",), "P3", idempotent=False, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "command": {"type": "string"}}, "required": ["host_id", "command"], "additionalProperties": False}),
        ToolSpec("ssh.poll", "Poll a remote process handle created by this agent.", "ssh.read", ("remote_process",), "P3", idempotent=True, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "handle": {"type": "string"}, "action_id": {"type": "string"}}, "required": ["host_id"], "anyOf": [{"required": ["handle"]}, {"required": ["action_id"]}], "additionalProperties": False}),
        ToolSpec("ssh.stop", "Stop a remote process handle created by this agent.", "ssh.stop", ("remote_process",), "P3", idempotent=False, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "handle": {"type": "string"}, "action_id": {"type": "string"}}, "required": ["host_id"], "anyOf": [{"required": ["handle"]}, {"required": ["action_id"]}], "additionalProperties": False}),
        ToolSpec("ssh.upload", "Upload an authorized local file after exact approval.", "ssh.write", ("remote_write", "network"), "P3", idempotent=False, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "local_path": {"type": "string"}, "remote_path": {"type": "string"}}, "required": ["host_id", "local_path", "remote_path"], "additionalProperties": False}),
        ToolSpec("ssh.download", "Download a remote file into an authorized local path.", "ssh.read", ("network",), "P3", idempotent=False, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "remote_path": {"type": "string"}, "local_path": {"type": "string"}}, "required": ["host_id", "remote_path", "local_path"], "additionalProperties": False}),
        ToolSpec("ssh.stat", "Read remote file metadata and SHA-256.", "ssh.read", ("network",), "P3", idempotent=True, schema={"type": "object", "properties": {"host_id": {"type": "string"}, "remote_path": {"type": "string"}}, "required": ["host_id", "remote_path"], "additionalProperties": False}),
        ToolSpec("ssh.close", "Close an SSH session and its remote handles.", "ssh.close", ("network",), "P3", idempotent=True, schema={"type": "object", "properties": {"host_id": {"type": "string"}}, "required": ["host_id"], "additionalProperties": False}),
    )

    def __init__(self, hosts: Iterable[SSHHostConfig], authorized_roots: Iterable[str | Path], *, backend: SSHBackend | None = None, max_output: int = 32_000) -> None:
        self.roots = tuple(Path(root).expanduser().resolve() for root in authorized_roots)
        normalized_hosts: dict[str, SSHHostConfig] = {}
        for host in hosts:
            known_hosts = host.known_hosts
            if known_hosts is not None and not known_hosts.is_absolute() and self.roots:
                known_hosts = self.roots[0] / known_hosts
                host = host.model_copy(update={"known_hosts": known_hosts})
            normalized_hosts[host.host_id] = host
        self.hosts = normalized_hosts
        self.backend: SSHBackend = backend or DisabledSSHBackend()
        self.max_output = max(1, max_output)
        self._sessions: dict[str, SSHSession] = {}
        self._handles: dict[tuple[str, str], SSHSession] = {}

    def _result(self, tool: str, args: Mapping[str, Any], host_id: str | None = None) -> ToolResult:
        result = timed_result(tool, new_action_id(tool, args))
        result.host = host_id or "local"
        return result

    def _blocked(self, tool: str, args: Mapping[str, Any], reason: str, *, host_id: str | None = None, status: str = "failed") -> ToolResult:
        result = self._result(tool, args, host_id)
        result.status = status
        result.error = reason
        result.metadata["blocked"] = True
        return result.finish()

    def _host(self, host_id: str, tool: str, args: Mapping[str, Any]) -> SSHHostConfig | ToolResult:
        if not self.hosts:
            return self._blocked(tool, args, "real SSH is disabled: authorized host allowlist is empty", host_id=host_id)
        host = self.hosts.get(host_id)
        if host is None:
            return self._blocked(tool, args, "SSH host is not explicitly allowlisted", host_id=host_id)
        if host.known_hosts is None or not host.known_hosts.is_file():
            return self._blocked(tool, args, "strict known_hosts file is required", host_id=host_id)
        if not host.host_key_fingerprint.strip():
            return self._blocked(tool, args, "host key fingerprint is required", host_id=host_id)
        return host

    def _connect(self, host_id: str, tool: str, args: Mapping[str, Any]) -> SSHSession | ToolResult:
        host = self._host(host_id, tool, args)
        if isinstance(host, ToolResult):
            return host
        session = self._sessions.get(host_id)
        try:
            if session is None:
                session = self.backend.connect(host)
                self._sessions[host_id] = session
            verify_host_key(host, str(session.fingerprint))
            return session
        except Exception as exc:
            self._sessions.pop(host_id, None)
            try:
                if session is not None:
                    session.close()
            except Exception:
                pass
            return self._blocked(tool, args, str(exc), host_id=host_id)

    def _local_path(self, raw: str, *, must_exist: bool) -> Path:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            if not self.roots:
                raise PermissionError("no authorized local root is configured")
            candidate = self.roots[0] / candidate
        # Resolve the parent even for a new download target to catch symlinked
        # directories.  Existing symlink targets are rejected outright.
        is_junction = getattr(candidate, "is_junction", lambda: False)()
        if candidate.is_symlink() or is_junction:
            raise PermissionError("symbolic-link local transfer paths are not permitted")
        resolved = candidate.resolve(strict=must_exist)
        if not _inside_roots(resolved, self.roots):
            raise PermissionError("local transfer path is outside authorized roots")
        if must_exist and not resolved.is_file():
            raise FileNotFoundError(str(resolved))
        if not must_exist and not _inside_roots(resolved.parent, self.roots):
            raise PermissionError("local transfer parent is outside authorized roots")
        return resolved

    @staticmethod
    def _validate_timeout(timeout: float) -> float:
        value = float(timeout)
        if not math.isfinite(value) or value <= 0 or value > 86_400:
            raise ValueError("timeout must be finite and between 0 and 86400 seconds")
        return value

    def test_connection(self, host_id: str) -> ToolResult:
        args = {"host_id": host_id}
        session = self._connect(host_id, "ssh.test_connection", args)
        if isinstance(session, ToolResult):
            return session
        result = self._result("ssh.test_connection", args, host_id)
        result.stdout = "host key verified"
        result.metadata.update({"host_id": host_id, "fingerprint": _normalise_fingerprint(str(session.fingerprint)), "known_hosts_verified": True})
        return result.finish()

    def exec(self, host_id: str, command: str, timeout: float = 30) -> ToolResult:
        args = {"host_id": host_id, "command": command, "timeout": timeout}
        result = self._result("ssh.exec", args, host_id)
        try:
            if not isinstance(command, str) or not command.strip() or "\x00" in command:
                raise ValueError("remote command is blank or contains NUL")
            value = self._validate_timeout(timeout)
            session = self._connect(host_id, "ssh.exec", args)
            if isinstance(session, ToolResult):
                return session
            response = session.exec(command, value)
            result.stdout, result.stderr, result.exit_code = response.stdout, response.stderr, response.exit_code
            result.status = response.status
            result.side_effects = list(response.side_effects)
            result.metadata.update(dict(response.metadata))
            if response.status not in {"completed", "running"}:
                result.error = f"remote command ended with status {response.status}"
        except TimeoutError as exc:
            # A remote command may have started before the timeout.  Never
            # retry it automatically and do not claim that it was rolled back.
            result.status = "unknown"
            result.error = f"timeout; remote side effect state is unknown ({exc})"
            result.side_effects = ["remote_process"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.bounded(self.max_output).finish()

    def start(self, host_id: str, command: str) -> ToolResult:
        args = {"host_id": host_id, "command": command}
        result = self._result("ssh.start", args, host_id)
        try:
            if not isinstance(command, str) or not command.strip() or "\x00" in command:
                raise ValueError("remote command is blank or contains NUL")
            session = self._connect(host_id, "ssh.start", args)
            if isinstance(session, ToolResult):
                return session
            handle = session.start(command)
            self._handles[(host_id, handle)] = session
            result.stdout = handle
            result.metadata["handle"] = handle
            # ``action_id`` is retained as a compatibility alias for callers
            # that use the local process-tool convention for remote handles.
            result.metadata["action_id"] = handle
            result.side_effects = ["remote_process"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def poll(self, host_id: str, handle: str | None = None, *, action_id: str | None = None) -> ToolResult:
        handle = handle or action_id
        args = {"host_id": host_id, "handle": handle}
        result = self._result("ssh.poll", args, host_id)
        try:
            checked_host = self._host(host_id, "ssh.poll", args)
            if isinstance(checked_host, ToolResult):
                return checked_host
            if not isinstance(handle, str) or not handle.strip() or "\x00" in handle:
                raise ValueError("remote process handle is invalid")
            session = self._handles.get((host_id, handle))
            if session is None:
                raise KeyError("unknown remote process handle")
            # Revalidate the peer key before polling a long-lived channel.
            checked = self._connect(host_id, "ssh.poll", args)
            if isinstance(checked, ToolResult):
                return checked
            response = session.poll(handle)
            result.stdout, result.stderr, result.exit_code = response.stdout, response.stderr, response.exit_code
            result.status = response.status
            result.side_effects = list(response.side_effects)
            result.metadata.update(dict(response.metadata))
            if response.status == "completed":
                self._handles.pop((host_id, handle), None)
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.bounded(self.max_output).finish()

    def stop(self, host_id: str, handle: str | None = None, *, action_id: str | None = None) -> ToolResult:
        handle = handle or action_id
        args = {"host_id": host_id, "handle": handle}
        result = self._result("ssh.stop", args, host_id)
        checked_host = self._host(host_id, "ssh.stop", args)
        if isinstance(checked_host, ToolResult):
            return checked_host
        if not isinstance(handle, str) or not handle.strip() or "\x00" in handle:
            result.status, result.error = "failed", "remote process handle is invalid"
            return result.finish()
        session = self._handles.get((host_id, handle))
        if session is None:
            result.status, result.error = "failed", "unknown remote process handle"
            return result.finish()
        try:
            checked = self._connect(host_id, "ssh.stop", args)
            if isinstance(checked, ToolResult):
                return checked
            if not session.stop(handle):
                result.status, result.error = "unknown", "remote process stop could not be confirmed"
            else:
                result.stdout, result.side_effects = handle, ["remote_process_stop"]
                self._handles.pop((host_id, handle), None)
        except Exception as exc:
            result.status, result.error = "unknown", f"remote stop state is unknown ({exc})"
        return result.finish()

    def upload(self, host_id: str, local_path: str, remote_path: str) -> ToolResult:
        args = {"host_id": host_id, "local_path": local_path, "remote_path": remote_path}
        result = self._result("ssh.upload", args, host_id)
        try:
            local = self._local_path(local_path, must_exist=True)
            remote = _normalise_remote_path(remote_path)
            data = local.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            session = self._connect(host_id, "ssh.upload", args)
            if isinstance(session, ToolResult):
                return session
            remote_stat = session.upload(remote, data)
            if remote_stat.size != len(data) or _normalise_fingerprint(remote_stat.sha256) != digest:
                raise OSError("remote upload size or SHA-256 verification failed")
            result.stdout = json.dumps({"remote_path": remote, "size": len(data), "sha256": digest}, sort_keys=True)
            result.metadata.update({"remote_path": remote, "size": len(data), "sha256": digest, "remote_size": remote_stat.size, "remote_sha256": remote_stat.sha256})
            result.side_effects = ["remote_write", "file_transfer"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def download(self, host_id: str, remote_path: str, local_path: str) -> ToolResult:
        args = {"host_id": host_id, "remote_path": remote_path, "local_path": local_path}
        result = self._result("ssh.download", args, host_id)
        temp_name: str | None = None
        try:
            remote = _normalise_remote_path(remote_path)
            local = self._local_path(local_path, must_exist=False)
            session = self._connect(host_id, "ssh.download", args)
            if isinstance(session, ToolResult):
                return session
            expected = session.stat(remote)
            data = session.download(remote)
            digest = hashlib.sha256(data).hexdigest()
            if expected.size != len(data) or _normalise_fingerprint(expected.sha256) != digest:
                raise OSError("remote download size or SHA-256 verification failed")
            # Atomic replacement prevents a partial download from becoming a
            # visible workspace file.  Existing symlink targets were rejected
            # by _local_path before this point.
            local.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=local.parent, prefix=f".{local.name}.", suffix=".part", delete=False) as handle:
                temp_name = handle.name
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            written = Path(temp_name)
            if written.stat().st_size != len(data) or hashlib.sha256(written.read_bytes()).hexdigest() != digest:
                raise OSError("local download size or SHA-256 verification failed")
            os.replace(written, local)
            temp_name = None
            result.stdout = json.dumps({"local_path": str(local), "size": len(data), "sha256": digest}, sort_keys=True)
            result.metadata.update({"remote_path": remote, "local_path": str(local), "size": len(data), "sha256": digest, "remote_size": expected.size, "remote_sha256": expected.sha256})
            result.side_effects = ["file_transfer"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        finally:
            if temp_name:
                try:
                    Path(temp_name).unlink(missing_ok=True)
                except OSError:
                    pass
        return result.finish()

    def stat(self, host_id: str, remote_path: str) -> ToolResult:
        args = {"host_id": host_id, "remote_path": remote_path}
        result = self._result("ssh.stat", args, host_id)
        try:
            remote = _normalise_remote_path(remote_path)
            session = self._connect(host_id, "ssh.stat", args)
            if isinstance(session, ToolResult):
                return session
            value = session.stat(remote)
            result.stdout = json.dumps({"path": remote, "size": value.size, "sha256": value.sha256, "mode": value.mode, "owner": value.owner}, sort_keys=True)
            result.metadata.update({"remote_path": remote, "size": value.size, "sha256": value.sha256, "mode": value.mode, "owner": value.owner})
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def close(self, host_id: str) -> ToolResult:
        args = {"host_id": host_id}
        result = self._result("ssh.close", args, host_id)
        checked_host = self._host(host_id, "ssh.close", args)
        if isinstance(checked_host, ToolResult):
            return checked_host
        stopped, uncertain = self._stop_host_handles(host_id)
        if stopped:
            result.metadata["stopped_handles"] = stopped
            result.side_effects = ["remote_process_stop"]
        if uncertain:
            result.status = "unknown"
            result.error = "remote process stop could not be confirmed before SSH close"
            result.metadata["unknown_handles"] = uncertain
            # Keep both the session and handle registrations available for an
            # explicit poll/stop retry. Silently forgetting them would make a
            # potentially live remote process impossible to reconcile.
            return result.finish()
        session = self._sessions.pop(host_id, None)
        if session is None:
            result.stdout = "no open session"
            return result.finish()
        try:
            session.close()
            result.stdout = "closed"
        except Exception as exc:
            result.status, result.error = "unknown", f"SSH close state is unknown ({exc})"
        return result.finish()

    def _stop_host_handles(self, host_id: str) -> tuple[list[str], list[str]]:
        """Best-effort stop of handles on one verified peer.

        Only a positive acknowledgement is reported as stopped.  Failed or
        ambiguous stops remain registered so callers cannot mistake a lost
        channel for successful termination.
        """

        handles = [handle for candidate, handle in self._handles if candidate == host_id]
        if not handles:
            return [], []
        checked = self._connect(host_id, "ssh.stop", {"host_id": host_id})
        if isinstance(checked, ToolResult):
            return [], handles
        stopped: list[str] = []
        uncertain: list[str] = []
        for handle in handles:
            session = self._handles.get((host_id, handle))
            if session is None:
                uncertain.append(handle)
                continue
            try:
                confirmed = session.stop(handle)
            except Exception:
                confirmed = False
            if confirmed:
                self._handles.pop((host_id, handle), None)
                stopped.append(handle)
            else:
                uncertain.append(handle)
        return stopped, uncertain

    def stop_all(self) -> list[str]:
        """Stop every registered remote handle without false confirmation."""

        stopped: list[str] = []
        for host_id in sorted({item[0] for item in self._handles}):
            confirmed, _uncertain = self._stop_host_handles(host_id)
            stopped.extend(f"{host_id}:{handle}" for handle in confirmed)
        return stopped

    def close_all(self) -> None:
        for host_id in list(self._sessions):
            self.close(host_id)


_FAKE_SSH_READ_ONLY = {"ssh.test_connection", "ssh.poll", "ssh.stat", "ssh.close"}


class FakeSSHTools(SSHTools):
    """Explicit test-only SSH namespace which never opens a socket."""

    specs: tuple[ToolSpec, ...] = tuple(
        replace(
            spec,
            capability="ssh.fake.offline",
            side_effects=("offline_fixture_read",) if spec.name in _FAKE_SSH_READ_ONLY else ("offline_side_effect_simulation",),
            risk="P0" if spec.name in _FAKE_SSH_READ_ONLY else "P1",
        )
        for spec in SSHTools.specs
    )

    def __init__(
        self,
        hosts: Iterable[SSHHostConfig],
        authorized_roots: Iterable[str | Path],
        *,
        backend: FakeSSHBackend,
        max_output: int = 32_000,
    ) -> None:
        super().__init__(hosts, authorized_roots, backend=backend, max_output=max_output)

    def stop_all(self) -> list[str]:
        """Best-effort kill-switch hook for remote handles created here."""

        return super().stop_all()


__all__ = [
    "DisabledSSHBackend",
    "FakeCommand",
    "FakeSSHBackend",
    "FakeSSHHost",
    "FakeSSHServer",
    "FakeSSHTools",
    "RemoteExec",
    "RemoteStat",
    "SSHBackend",
    "SSHHostKeyError",
    "SSHSession",
    "SSHUnavailable",
    "SSHTools",
    "verify_host_key",
]
