"""Strict system-OpenSSH transport for explicitly allowlisted hosts.

This module deliberately provides only command channels.  File transfer and
remote filesystem operations remain disabled until the staged backup/verify/
rollback workflow has a separately reviewed implementation.

The transport never invokes a shell locally.  Every OpenSSH option is a
separate argv element and user/system configuration files are disabled with
``-F none``.  Authentication is non-interactive and may use an existing SSH
agent/keychain only; private-key paths and passwords are never accepted.
"""

from __future__ import annotations

import hashlib
import math
import os
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, cast

from ..config import SSHHostConfig
from .ssh import (
    RemoteExec,
    RemoteStat,
    SSHHostKeyError,
    SSHSession,
    SSHUnavailable,
    _known_hosts_fingerprints,
)

PopenFactory = Callable[..., subprocess.Popen[bytes]]


def resolve_system_ssh() -> Path:
    """Return a trusted absolute OpenSSH client path without repository PATH lookup."""

    candidates: list[Path] = []
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if system_root:
            candidates.append(Path(system_root) / "System32" / "OpenSSH" / "ssh.exe")
    else:
        candidates.extend((Path("/usr/bin/ssh"), Path("/bin/ssh")))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and not resolved.is_symlink():
            return resolved
    # ``which`` is diagnostic only here: accepting a repository-controlled PATH
    # would reintroduce exactly the executable-shadowing boundary this adapter
    # is intended to enforce.
    discovered = shutil.which("ssh")
    detail = "system OpenSSH client is unavailable"
    if discovered:
        detail += " at a trusted operating-system path"
    raise SSHUnavailable(detail)


def _live_fingerprint(value: str) -> str:
    """Require the standard SHA256 marker for a live transport trust anchor."""

    candidate = value.strip()
    if not candidate.startswith("SHA256:") and not candidate.startswith("sha256:"):
        raise SSHHostKeyError("live SSH requires a SHA256 host-key fingerprint")
    encoded = candidate.split(":", 1)[1].rstrip("=")
    # An SHA-256 digest is 43 unpadded base64 characters.  Restricting the
    # alphabet also prevents control text from entering diagnostics or argv.
    if len(encoded) != 43 or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" for char in encoded):
        raise SSHHostKeyError("live SSH host-key fingerprint is malformed")
    return "sha256:" + encoded


def _strict_known_hosts(host: SSHHostConfig) -> Path:
    path = host.known_hosts
    if path is None or not path.is_absolute():
        raise SSHHostKeyError("live SSH requires an absolute strict known_hosts path")
    if any(char in str(path) for char in ("\x00", "\r", "\n")):
        raise SSHHostKeyError("strict known_hosts path contains control characters")
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise SSHHostKeyError("strict known_hosts cannot be a symbolic link or junction")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SSHHostKeyError("strict known_hosts file is unavailable") from exc
    if not resolved.is_file():
        raise SSHHostKeyError("strict known_hosts file is required")
    return resolved


def _require_dedicated_host_key(
    path: Path, host: SSHHostConfig, configured_fingerprint: str
) -> None:
    """Require one exact, unhashed key entry and no alternate matching rules."""

    try:
        entries = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeError) as exc:
        raise SSHHostKeyError("strict known_hosts cannot be parsed as UTF-8") from exc
    expected_name = host.hostname if host.port == 22 else f"[{host.hostname}]:{host.port}"
    if len(entries) != 1:
        raise SSHHostKeyError(
            "live SSH requires a dedicated known_hosts file with exactly one key entry"
        )
    fields = entries[0].split()
    if len(fields) != 3 or fields[0].lower() != expected_name.lower():
        raise SSHHostKeyError(
            "live SSH known_hosts entry must bind the exact configured host and port"
        )
    known_fingerprints = _known_hosts_fingerprints(path, host)
    if known_fingerprints != {configured_fingerprint}:
        raise SSHHostKeyError(
            "configured SSH fingerprint does not match the dedicated known_hosts key"
        )


def _clean_ssh_environment() -> dict[str, str]:
    """Keep only OS loader and agent variables; never inherit prompts/proxies."""

    allowed = ("SystemRoot", "WINDIR", "SSH_AUTH_SOCK", "LANG", "LC_ALL")
    environment = {name: os.environ[name] for name in allowed if os.environ.get(name)}
    environment["SSH_ASKPASS_REQUIRE"] = "never"
    # Git-for-Windows/OpenSSH may otherwise consult a graphical askpass helper.
    environment.pop("DISPLAY", None)
    environment.pop("SSH_ASKPASS", None)
    return environment


class OpenSSHSession(SSHSession):
    """One allowlisted target backed by independent system ``ssh`` processes."""

    def __init__(
        self,
        host: SSHHostConfig,
        executable: Path,
        *,
        popen_factory: PopenFactory = subprocess.Popen,
        connect_timeout: float = 15.0,
    ) -> None:
        self.host = host
        self.executable = executable
        self._known_hosts = _strict_known_hosts(host)
        self._known_hosts_sha256 = hashlib.sha256(self._known_hosts.read_bytes()).digest()
        self._fingerprint = _live_fingerprint(host.host_key_fingerprint)
        _require_dedicated_host_key(self._known_hosts, host, self._fingerprint)
        self._popen_factory = popen_factory
        self._connect_timeout = _finite_timeout(connect_timeout)
        self._processes: dict[str, subprocess.Popen[bytes]] = {}
        self._lock = threading.RLock()
        self._closed = False

    @property
    def fingerprint(self) -> str:
        # The actual peer key is enforced independently by OpenSSH against the
        # exact known_hosts file.  This value is the separately configured
        # fingerprint which SSHTools also binds into approvals.
        return self._fingerprint

    def base_argv(self) -> tuple[str, ...]:
        """Build the complete immutable client boundary as structured argv."""

        return (
            str(self.executable),
            "-F",
            "none",
            "-T",
            "-n",
            "-x",
            "-a",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "GSSAPIAuthentication=no",
            "-o",
            "HostbasedAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "IdentityFile=none",
            "-o",
            "CertificateFile=none",
            "-o",
            "AddKeysToAgent=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "LocalCommand=none",
            "-o",
            "KnownHostsCommand=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self._known_hosts}",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "CheckHostIP=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "StdinNull=yes",
            "-o",
            "EnableEscapeCommandline=no",
            "-o",
            "Tunnel=no",
            "-p",
            str(self.host.port),
            "-l",
            self.host.user,
            "--",
            self.host.hostname,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise SSHUnavailable("SSH session is closed")

    def _assert_trust_unchanged(self) -> None:
        try:
            current = _strict_known_hosts(self.host)
            digest = hashlib.sha256(current.read_bytes()).digest()
        except OSError as exc:
            raise SSHHostKeyError("strict known_hosts changed before SSH execution") from exc
        if current != self._known_hosts or digest != self._known_hosts_sha256:
            raise SSHHostKeyError("strict known_hosts changed before SSH execution")

    def _spawn(self, command: str) -> subprocess.Popen[bytes]:
        self._ensure_open()
        self._assert_trust_unchanged()
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise ValueError("remote command is blank or contains NUL")
        argv = [*self.base_argv(), command]
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "env": _clean_ssh_environment(),
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        try:
            return self._popen_factory(argv, **kwargs)
        except OSError as exc:
            raise SSHUnavailable("system OpenSSH client could not be started") from exc

    @staticmethod
    def _terminate_channel(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass

    @staticmethod
    def _completed(process: subprocess.Popen[bytes], stdout: bytes, stderr: bytes) -> RemoteExec:
        return RemoteExec(
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            exit_code=process.returncode,
            status="completed",
            metadata={"transport": "system-openssh", "host_key_policy": "strict"},
        )

    def _run(self, command: str, timeout: float) -> RemoteExec:
        process = self._spawn(command)
        try:
            stdout, stderr = process.communicate(timeout=_finite_timeout(timeout))
        except subprocess.TimeoutExpired as exc:
            self._terminate_channel(process)
            raise TimeoutError("OpenSSH command channel timed out; remote state is unknown") from exc
        return self._completed(process, stdout, stderr)

    def probe(self) -> None:
        result = self._run("exit 0", self._connect_timeout)
        if result.exit_code != 0:
            # stderr may contain an untrusted banner or sensitive agent/path
            # diagnostics, so the connection error never embeds it.
            raise SSHUnavailable(f"strict OpenSSH connection probe failed (exit {result.exit_code})")

    def exec(self, command: str, timeout: float) -> RemoteExec:
        return self._run(command, timeout)

    def start(self, command: str) -> str:
        process = self._spawn(command)
        handle = "openssh-" + uuid.uuid4().hex
        with self._lock:
            self._processes[handle] = process
        return handle

    def poll(self, handle: str) -> RemoteExec:
        with self._lock:
            process = self._processes.get(handle)
        if process is None:
            raise KeyError("unknown remote process handle")
        if process.poll() is None:
            return RemoteExec(
                exit_code=None,
                status="running",
                metadata={"transport": "system-openssh", "host_key_policy": "strict"},
            )
        stdout, stderr = process.communicate()
        with self._lock:
            self._processes.pop(handle, None)
        return self._completed(process, stdout, stderr)

    def stop(self, handle: str) -> bool:
        with self._lock:
            process = self._processes.get(handle)
        if process is None:
            return False
        if process.poll() is not None:
            process.communicate()
            with self._lock:
                self._processes.pop(handle, None)
            return True
        self._terminate_channel(process)
        # Closing the SSH channel does not prove that a remote child process
        # exited.  Preserve the handle and force the adapter to report unknown.
        return False

    def upload(self, remote_path: str, data: bytes) -> RemoteStat:
        del remote_path, data
        raise SSHUnavailable("live SSH file upload is disabled pending atomic rollback workflow")

    def download(self, remote_path: str) -> bytes:
        del remote_path
        raise SSHUnavailable("live SSH file download is disabled pending transfer isolation")

    def stat(self, remote_path: str) -> RemoteStat:
        del remote_path
        raise SSHUnavailable("live SSH remote stat is disabled pending a structured file adapter")

    def close(self) -> None:
        with self._lock:
            processes = list(self._processes.values())
        for process in processes:
            self._terminate_channel(process)
        self._closed = True


class OpenSSHBackend:
    """Mature system-client backend; construction alone never opens a socket."""

    def __init__(
        self,
        *,
        executable: Path | None = None,
        connect_timeout: float = 15.0,
        popen_factory: PopenFactory = subprocess.Popen,
    ) -> None:
        selected = executable.resolve(strict=True) if executable is not None else resolve_system_ssh()
        if not selected.is_file() or selected.is_symlink():
            raise SSHUnavailable("OpenSSH executable must be a regular non-symlink file")
        self.executable = selected
        self.connect_timeout = _finite_timeout(connect_timeout)
        self._popen_factory = popen_factory

    def connect(self, host: SSHHostConfig) -> SSHSession:
        session = OpenSSHSession(
            host,
            self.executable,
            popen_factory=self._popen_factory,
            connect_timeout=self.connect_timeout,
        )
        session.probe()
        return cast(SSHSession, session)


def _finite_timeout(value: float) -> float:
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 86_400:
        raise ValueError("SSH timeout must be finite and between 0 and 86400 seconds")
    return timeout


__all__ = ["OpenSSHBackend", "OpenSSHSession", "resolve_system_ssh"]
