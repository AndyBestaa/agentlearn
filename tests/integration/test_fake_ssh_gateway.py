from __future__ import annotations

import pytest

from astercode.config import AppConfig, SSHHostConfig
from astercode.gateway import LocalToolGateway
from astercode.models import ApprovalDecision, ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine
from astercode.tools.registry import ToolRegistry
from astercode.tools.ssh import FakeSSHBackend, FakeSSHTools


@pytest.mark.asyncio
async def test_fake_ssh_runs_through_policy_gateway_without_network(
    app_config: AppConfig, storage, tmp_path
) -> None:
    fingerprint = "SHA256:offline-gateway-fingerprint"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"example.test {fingerprint}\n", encoding="utf-8")
    host = SSHHostConfig(
        host_id="dev",
        hostname="example.test",
        user="tester",
        host_key_fingerprint=fingerprint,
        known_hosts=known_hosts,
    )
    config_data = app_config.model_dump()
    config_data["security"]["authorized_ssh_hosts"] = [host.model_dump(mode="python")]
    config = AppConfig.model_validate(config_data)
    backend = FakeSSHBackend(
        host_id="dev",
        fingerprint=fingerprint,
        commands={"uname -a": {"stdout": "offline-linux\n"}},
    )
    registry = ToolRegistry()
    registry.register_provider(FakeSSHTools([host], [tmp_path], backend=backend))
    session_id = "session-fake-ssh-gateway"
    storage.create_session(str(tmp_path), "offline ssh", session_id=session_id)
    gateway = LocalToolGateway(
        registry,
        PolicyEngine(config, storage),
        storage,
        auto_approve=True,
    )
    context = GatewayContext(
        session_id=session_id,
        turn_id="turn-fake-ssh-gateway",
        goal="exercise the offline SSH fixture",
        phase="POLICY_CHECK",
    )
    call = ToolCall(
        tool="ssh.exec",
        arguments={"host_id": "dev", "command": "uname -a", "timeout": 5},
        host="dev",
        cwd=str(tmp_path),
    )

    authorization = await gateway.authorize(call, context)
    result = await gateway.execute(call, context)

    assert authorization.outcome == "allow"
    assert authorization.risk.value == "P1"
    assert result.status.value == "completed"
    assert result.stdout == "offline-linux\n"

    start_call = ToolCall(
        tool="ssh.start",
        arguments={"host_id": "dev", "command": "long job"},
        host="dev",
        cwd=str(tmp_path),
    )
    start_authorization = await gateway.authorize(start_call, context)
    start_result = await gateway.execute(start_call, context)
    verification = await gateway.verify(start_result, context)

    assert start_authorization.outcome == "allow"
    assert start_result.status.value == "completed"
    assert verification["verified"] is False
    assert verification["running"] is True


@pytest.mark.asyncio
async def test_known_hosts_change_invalidates_pending_ssh_approval(
    app_config: AppConfig, storage, tmp_path
) -> None:
    fingerprint = "SHA256:offline-gateway-fingerprint"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"example.test {fingerprint}\n", encoding="utf-8")
    host = SSHHostConfig(
        host_id="dev",
        hostname="example.test",
        user="tester",
        host_key_fingerprint=fingerprint,
        known_hosts=known_hosts,
    )
    config_data = app_config.model_dump()
    config_data["security"]["authorized_ssh_hosts"] = [host.model_dump(mode="python")]
    config = AppConfig.model_validate(config_data)
    backend = FakeSSHBackend(
        host_id="dev",
        fingerprint=fingerprint,
        commands={"uname -a": {"stdout": "offline-linux\n"}},
    )
    registry = ToolRegistry()
    registry.register_provider(FakeSSHTools([host], [tmp_path], backend=backend))
    session_id = "session-ssh-trust-change"
    storage.create_session(str(tmp_path), "bind SSH trust file", session_id=session_id)
    gateway = LocalToolGateway(registry, PolicyEngine(config, storage), storage)
    context = GatewayContext(
        session_id=session_id,
        turn_id="turn-ssh-trust-change",
        goal="verify exact SSH approval binding",
        phase="POLICY_CHECK",
    )
    call = ToolCall(
        tool="ssh.exec",
        arguments={"host_id": "dev", "command": "uname -a", "timeout": 5},
        host="dev",
        cwd=str(tmp_path),
    )

    pending = await gateway.authorize(call, context)
    assert pending.outcome == "require_approval"
    assert pending.approval_request is not None
    request = pending.approval_request
    decision = ApprovalDecision(
        approval_id=request.approval_id,
        action_id=request.action_id,
        action_hash=request.action_hash,
        nonce=request.nonce,
        approved=True,
    )
    known_hosts.write_text(
        f"example.test {fingerprint}\n# changed after approval\n", encoding="utf-8"
    )

    authorization = await gateway.authorize(call, context, decision)

    assert authorization.outcome == "deny"
    assert "changed" in authorization.reason
