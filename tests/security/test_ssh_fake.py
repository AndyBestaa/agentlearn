from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from astercode.config import AppConfig, SSHHostConfig
from astercode.policy import PolicyEngine
from astercode.runtime import build_registry
from astercode.tools.ssh import FakeCommand, FakeSSHBackend, FakeSSHTools, SSHTools


def _host(tmp_path: Path, *, fingerprint: str = "SHA256:offline-test-fingerprint") -> SSHHostConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"example.test {fingerprint}\n", encoding="utf-8")
    return SSHHostConfig(
        host_id="dev",
        hostname="example.test",
        user="tester",
        host_key_fingerprint=fingerprint,
        known_hosts=known_hosts,
    )


def _tools(tmp_path: Path, *, fingerprint: str = "SHA256:offline-test-fingerprint") -> tuple[SSHTools, FakeSSHBackend]:
    host = _host(tmp_path, fingerprint=fingerprint)
    backend = FakeSSHBackend(
        host_id="dev",
        fingerprint=fingerprint,
        files={"/remote/readme.txt": b"remote contents"},
        commands={
            "uname -a": {"stdout": "fake-linux\n"},
            "sleep forever": FakeCommand(delay=99),
            "long job": FakeCommand(stdout="done\n", polls_until_complete=2),
        },
    )
    return SSHTools([host], [tmp_path], backend=backend), backend


def _config_with_host(app_config: AppConfig, host: SSHHostConfig) -> AppConfig:
    data = app_config.model_dump()
    data["security"]["authorized_ssh_hosts"] = [host.model_dump(mode="python")]
    return AppConfig.model_validate(data)


def _fake_spec(name: str):
    return next(spec for spec in FakeSSHTools.specs if spec.name == name)


def test_empty_allowlist_rejects_even_with_fake_backend(tmp_path: Path) -> None:
    backend = FakeSSHBackend(host_id="dev", fingerprint="SHA256:offline-test-fingerprint")
    tools = SSHTools([], [tmp_path], backend=backend)

    result = tools.test_connection("dev")

    assert result.status == "failed"
    assert "allowlist is empty" in str(result.error)


def test_fake_ssh_full_read_exec_process_and_transfer_flow(tmp_path: Path) -> None:
    tools, _backend = _tools(tmp_path)
    source = tmp_path / "upload.txt"
    source.write_bytes(b"upload payload")

    assert tools.test_connection("dev").status == "completed"
    command = tools.exec("dev", "uname -a")
    assert command.status == "completed"
    assert command.stdout == "fake-linux\n"

    started = tools.start("dev", "long job")
    handle = started.metadata["handle"]
    first = tools.poll("dev", handle)
    assert first.status == "running"
    second = tools.poll("dev", handle)
    assert second.status == "completed"
    assert second.stdout == "done\n"

    uploaded = tools.upload("dev", str(source), "/remote/upload.txt")
    assert uploaded.status == "completed"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert uploaded.metadata["sha256"] == digest
    assert tools.stat("dev", "/remote/upload.txt").metadata["sha256"] == digest

    target = tmp_path / "download.txt"
    downloaded = tools.download("dev", "/remote/readme.txt", str(target))
    assert downloaded.status == "completed"
    assert target.read_bytes() == b"remote contents"
    assert downloaded.metadata["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert tools.close("dev").status == "completed"


def test_host_key_change_hard_stops_before_command(tmp_path: Path) -> None:
    tools, backend = _tools(tmp_path)
    assert tools.test_connection("dev").status == "completed"

    backend.set_fingerprint("dev", "SHA256:changed-host-key")
    result = tools.exec("dev", "uname -a")

    assert result.status == "failed"
    assert "changed" in str(result.error) or "fingerprint" in str(result.error)


def test_timeout_is_unknown_and_not_retried(tmp_path: Path) -> None:
    tools, backend = _tools(tmp_path)
    result = tools.exec("dev", "sleep forever", timeout=1)

    assert result.status == "unknown"
    assert "unknown" in str(result.error)
    # The fake backend has no retry counter and the command remains untouched;
    # a second call is a new explicit action rather than an automatic retry.
    assert backend.hosts["dev"].commands["sleep forever"]


def test_ssh_approval_binds_configured_target_and_known_hosts_bytes(
    app_config: AppConfig, tmp_path: Path
) -> None:
    host = _host(tmp_path)
    config = _config_with_host(app_config, host)
    arguments = {"host_id": "dev", "command": "uname -a", "timeout": 5}

    first = PolicyEngine(config).evaluate(
        "ssh.exec",
        arguments,
        host="dev",
        cwd=str(tmp_path),
        declared=_fake_spec("ssh.exec"),
    )

    assert first.decision == "approval_required"
    assert first.approval is not None
    target = first.normalized_action["ssh_target"]
    assert target["hostname"] == "example.test"
    assert target["port"] == 22
    assert target["user"] == "tester"
    assert target["configured_fingerprint"] == "sha256:offline-test-fingerprint"
    assert target["known_hosts_sha256"] == hashlib.sha256(
        host.known_hosts.read_bytes()  # type: ignore[union-attr]
    ).hexdigest()
    assert first.approval.port == 22
    assert first.approval.user == "tester"
    assert first.approval.host_fingerprint == "sha256:offline-test-fingerprint"
    assert first.approval.network_destination == "ssh://example.test:22"

    changed_port = PolicyEngine(
        _config_with_host(app_config, host.model_copy(update={"port": 2222}))
    ).evaluate(
        "ssh.exec",
        arguments,
        host="dev",
        cwd=str(tmp_path),
        declared=_fake_spec("ssh.exec"),
    )
    changed_hostname = PolicyEngine(
        _config_with_host(app_config, host.model_copy(update={"hostname": "other.test"}))
    ).evaluate(
        "ssh.exec",
        arguments,
        host="dev",
        cwd=str(tmp_path),
        declared=_fake_spec("ssh.exec"),
    )
    changed_user = PolicyEngine(
        _config_with_host(app_config, host.model_copy(update={"user": "other"}))
    ).evaluate(
        "ssh.exec",
        arguments,
        host="dev",
        cwd=str(tmp_path),
        declared=_fake_spec("ssh.exec"),
    )
    changed_fingerprint = PolicyEngine(
        _config_with_host(
            app_config,
            host.model_copy(update={"host_key_fingerprint": "SHA256:changed-fingerprint"}),
        )
    ).evaluate(
        "ssh.exec",
        arguments,
        host="dev",
        cwd=str(tmp_path),
        declared=_fake_spec("ssh.exec"),
    )

    assert changed_port.action_hash != first.action_hash
    assert changed_hostname.action_hash != first.action_hash
    assert changed_user.action_hash != first.action_hash
    assert changed_fingerprint.action_hash != first.action_hash

    assert host.known_hosts is not None
    host.known_hosts.write_text(
        "example.test SHA256:offline-test-fingerprint\n# trust file changed\n",
        encoding="utf-8",
    )
    changed_trust_file = PolicyEngine(config).evaluate(
        "ssh.exec",
        arguments,
        host="dev",
        cwd=str(tmp_path),
        declared=_fake_spec("ssh.exec"),
    )
    assert changed_trust_file.action_hash != first.action_hash


def test_stop_all_reports_only_confirmed_remote_stops(tmp_path: Path) -> None:
    tools, _backend = _tools(tmp_path)
    first = tools.start("dev", "long job")
    second = tools.start("dev", "long job")
    first_handle = str(first.metadata["handle"])
    second_handle = str(second.metadata["handle"])

    stopped = tools.stop_all()

    assert set(stopped) == {f"dev:{first_handle}", f"dev:{second_handle}"}
    assert tools.poll("dev", first_handle).status == "failed"
    assert tools.poll("dev", second_handle).status == "failed"


def test_close_stops_confirmed_remote_handles_before_closing(tmp_path: Path) -> None:
    tools, _backend = _tools(tmp_path)
    started = tools.start("dev", "long job")
    handle = str(started.metadata["handle"])

    closed = tools.close("dev")

    assert closed.status == "completed"
    assert closed.metadata["stopped_handles"] == [handle]
    assert closed.side_effects == ["remote_process_stop"]
    assert ("dev", handle) not in tools._handles


def test_close_keeps_unconfirmed_remote_handle_for_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools, _backend = _tools(tmp_path)
    started = tools.start("dev", "long job")
    handle = str(started.metadata["handle"])
    session = tools._handles[("dev", handle)]
    monkeypatch.setattr(session, "stop", lambda _handle: False)

    assert tools.stop_all() == []
    closed = tools.close("dev")

    assert closed.status == "unknown"
    assert closed.metadata["unknown_handles"] == [handle]
    assert ("dev", handle) in tools._handles


def test_local_transfer_path_cannot_escape_authorized_root(tmp_path: Path) -> None:
    tools, _backend = _tools(tmp_path)
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("secret", encoding="utf-8")

    result = tools.upload("dev", str(outside), "/remote/leak.txt")

    assert result.status == "failed"
    assert "outside authorized roots" in str(result.error)


def test_runtime_registers_ssh_contract_but_empty_policy_stays_fail_closed(app_config: AppConfig) -> None:
    registry = build_registry(app_config)

    names = {item.name for item in registry.specs()}
    assert {"ssh.test_connection", "ssh.exec", "ssh.start", "ssh.poll", "ssh.stop", "ssh.upload", "ssh.download", "ssh.stat", "ssh.close"} <= names
