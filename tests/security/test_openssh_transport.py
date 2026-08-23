from __future__ import annotations

import base64
import hashlib
import os
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from astercode.config import AppConfig, SSHHostConfig
from astercode.runtime import build_registry
from astercode.tools.openssh import OpenSSHBackend, OpenSSHSession
from astercode.tools.ssh import (
    DisabledSSHBackend,
    SSHHostKeyError,
    SSHTools,
    SSHUnavailable,
)

KEY_TYPE = b"ssh-ed25519"
KEY_BLOB_BYTES = (
    struct.pack(">I", len(KEY_TYPE))
    + KEY_TYPE
    + struct.pack(">I", 32)
    + (b"A" * 32)
)
KEY_BLOB = base64.b64encode(KEY_BLOB_BYTES).decode("ascii")
FINGERPRINT = "SHA256:" + base64.b64encode(
    hashlib.sha256(KEY_BLOB_BYTES).digest()
).decode("ascii").rstrip("=")


class _FakeProcess:
    def __init__(
        self,
        argv: list[str],
        kwargs: dict[str, Any],
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        exit_code: int = 0,
        running: bool = False,
    ) -> None:
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = stdout
        self.stderr = stderr
        self._exit_code = exit_code
        self.returncode: int | None = None if running else exit_code
        self.terminated = False
        self.killed = False

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        del timeout
        self.returncode = self._exit_code
        return self.stdout, self.stderr

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.argv, 0)
        return self.returncode


class _ProcessFactory:
    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self.responses = list(responses or [])
        self.processes: list[_FakeProcess] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        response = self.responses.pop(0) if self.responses else {}
        process = _FakeProcess(list(argv), dict(kwargs), **response)
        self.processes.append(process)
        return process


def _host(tmp_path: Path) -> SSHHostConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        f"[example.test]:2222 ssh-ed25519 {KEY_BLOB}\n", encoding="utf-8"
    )
    return SSHHostConfig(
        host_id="dev",
        hostname="example.test",
        port=2222,
        user="tester",
        host_key_fingerprint=FINGERPRINT,
        known_hosts=known_hosts,
    )


def _executable(tmp_path: Path) -> Path:
    executable = tmp_path / ("ssh.exe" if os.name == "nt" else "ssh")
    executable.write_bytes(b"offline process fixture")
    return executable


def test_openssh_uses_fixed_structured_argv_and_clean_environment(
    tmp_path: Path,
) -> None:
    factory = _ProcessFactory()
    backend = OpenSSHBackend(
        executable=_executable(tmp_path), popen_factory=factory, connect_timeout=5
    )
    tools = SSHTools([_host(tmp_path)], [tmp_path], backend=backend)
    command = "printf '%s' '$() ; powershell -Command ignored-locally'"

    result = tools.exec("dev", command, timeout=10)

    assert result.status == "completed"
    assert len(factory.processes) == 2  # strict connection probe, then command
    argv = factory.processes[-1].argv
    assert argv[-2:] == ["example.test", command]
    assert argv.count(command) == 1
    assert argv[1:3] == ["-F", "none"]
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "ClearAllForwardings=yes" in argv
    assert "ForwardAgent=no" in argv
    assert "ForwardX11=no" in argv
    assert "ControlMaster=no" in argv
    assert "ProxyCommand=none" in argv
    assert "ProxyJump=none" in argv
    assert "KnownHostsCommand=none" in argv
    assert "IdentityFile=none" in argv
    assert "PasswordAuthentication=no" in argv
    assert argv[argv.index("-l") + 1] == "tester"
    assert argv[argv.index("-p") + 1] == "2222"
    invocation = factory.processes[-1].kwargs
    assert invocation["shell"] is False
    assert invocation["stdin"] is subprocess.DEVNULL
    assert invocation["env"]["SSH_ASKPASS_REQUIRE"] == "never"
    assert "PATH" not in invocation["env"]
    assert "HOME" not in invocation["env"]
    assert not any(name.endswith("API_KEY") for name in invocation["env"])


def test_live_transport_rejects_remote_file_operations(tmp_path: Path) -> None:
    factory = _ProcessFactory()
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)
    session = backend.connect(_host(tmp_path))

    with pytest.raises(SSHUnavailable, match="upload is disabled"):
        session.upload("/tmp/value", b"value")
    with pytest.raises(SSHUnavailable, match="download is disabled"):
        session.download("/tmp/value")
    with pytest.raises(SSHUnavailable, match="stat is disabled"):
        session.stat("/tmp/value")


def test_live_stop_kills_local_channel_but_reports_remote_state_unknown(
    tmp_path: Path,
) -> None:
    factory = _ProcessFactory([{}, {"running": True}])
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)
    tools = SSHTools([_host(tmp_path)], [tmp_path], backend=backend)

    started = tools.start("dev", "long-running-command")
    handle = str(started.metadata["handle"])
    stopped = tools.stop("dev", handle)

    assert stopped.status == "unknown"
    assert "could not be confirmed" in str(stopped.error)
    assert factory.processes[-1].terminated is True
    assert ("dev", handle) in tools._handles


def test_connection_failure_does_not_echo_untrusted_stderr(tmp_path: Path) -> None:
    marker = "untrusted-banner-do-not-echo"
    factory = _ProcessFactory([{"stderr": marker.encode(), "exit_code": 255}])
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)
    tools = SSHTools([_host(tmp_path)], [tmp_path], backend=backend)

    result = tools.test_connection("dev")

    assert result.status == "failed"
    assert marker not in str(result.error)
    assert "exit 255" in str(result.error)


def test_known_hosts_bytes_are_pinned_for_the_session(tmp_path: Path) -> None:
    factory = _ProcessFactory()
    host = _host(tmp_path)
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)
    session = backend.connect(host)
    assert host.known_hosts is not None
    host.known_hosts.write_text(
        f"[example.test]:2222 ssh-ed25519 {KEY_BLOB}\n# changed after probe\n",
        encoding="utf-8",
    )

    with pytest.raises(SSHHostKeyError, match="known_hosts changed"):
        session.exec("exit 0", 5)

    assert len(factory.processes) == 1


def test_configured_fingerprint_must_be_the_only_key_for_exact_host_port(
    tmp_path: Path,
) -> None:
    host = _host(tmp_path)
    other_blob_bytes = KEY_BLOB_BYTES[:-1] + b"B"
    other_blob = base64.b64encode(other_blob_bytes).decode("ascii")
    assert host.known_hosts is not None
    with host.known_hosts.open("a", encoding="utf-8") as handle:
        handle.write(f"[example.test]:2222 ssh-ed25519 {other_blob}\n")
    factory = _ProcessFactory()
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)

    with pytest.raises(SSHHostKeyError, match="exactly one key entry"):
        backend.connect(host)

    assert factory.processes == []


def test_configured_fingerprint_must_derive_from_dedicated_key_blob(
    tmp_path: Path,
) -> None:
    host = _host(tmp_path).model_copy(
        update={"host_key_fingerprint": "SHA256:" + ("B" * 43)}
    )
    factory = _ProcessFactory()
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)

    with pytest.raises(SSHHostKeyError, match="does not match"):
        backend.connect(host)

    assert factory.processes == []


def test_empty_allowlist_never_spawns_system_openssh(tmp_path: Path) -> None:
    factory = _ProcessFactory()
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)
    tools = SSHTools([], [tmp_path], backend=backend)

    result = tools.test_connection("absent")

    assert result.status == "failed"
    assert "allowlist is empty" in str(result.error)
    assert factory.processes == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "-oProxyCommand=bad"),
        ("hostname", "host.test\n-oProxyCommand=bad"),
        ("user", "-Fbad"),
        ("user", "person@other-host"),
    ],
)
def test_host_config_rejects_option_like_target_fields(
    tmp_path: Path, field: str, value: str
) -> None:
    data = _host(tmp_path).model_dump()
    data[field] = value

    with pytest.raises(ValidationError):
        SSHHostConfig.model_validate(data)


def test_runtime_requires_config_and_network_attestation_together(
    app_config: AppConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _host(tmp_path)
    data = app_config.model_dump()
    data["security"]["authorized_ssh_hosts"] = [host.model_dump(mode="python")]
    data["security"]["ssh"]["enabled"] = True
    config = AppConfig.model_validate(data)
    registry = build_registry(config, verified_ssh_network_policy=False)
    disabled = next(
        provider for provider in registry.providers() if isinstance(provider, SSHTools)
    )
    assert isinstance(disabled.backend, DisabledSSHBackend)

    sentinel = object()
    monkeypatch.setattr("astercode.runtime.OpenSSHBackend", lambda **_kwargs: sentinel)
    attested_registry = build_registry(config, verified_ssh_network_policy=True)
    enabled = next(
        provider
        for provider in attested_registry.providers()
        if isinstance(provider, SSHTools)
    )
    assert enabled.backend is sentinel


def test_constructing_backend_and_session_does_not_open_a_process(tmp_path: Path) -> None:
    factory = _ProcessFactory()
    backend = OpenSSHBackend(executable=_executable(tmp_path), popen_factory=factory)

    OpenSSHSession(_host(tmp_path), backend.executable, popen_factory=factory)

    assert factory.processes == []
