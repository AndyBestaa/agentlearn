from __future__ import annotations

import sys

import pytest

from astercode.config import AppConfig
from astercode.gateway import LocalToolGateway
from astercode.models import ApprovalDecision, ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine, RuntimePolicyCapabilities
from astercode.runtime import build_registry


@pytest.mark.asyncio
async def test_agent_process_is_persisted_and_cancelled_as_a_tree(
    app_config: AppConfig, storage, tmp_path
) -> None:
    config_data = app_config.model_dump()
    config_data["security"]["process"]["allow_unsandboxed_process"] = True
    config = AppConfig.model_validate(config_data)
    session_id = "session-process-registry"
    storage.create_session(str(tmp_path), "start then cancel", session_id=session_id)
    gateway = LocalToolGateway(
        build_registry(
            config,
            verified_process_sandbox=True,
            verified_process_network_policy=True,
        ),
        PolicyEngine(
            config,
            storage,
            RuntimePolicyCapabilities(
                process_sandbox_enforced=True,
                process_network_policy_enforced=True,
            ),
        ),
        storage,
    )
    script = tmp_path / "sleep_long.py"
    script.write_text("import time\ntime.sleep(120)\n", encoding="utf-8")
    call = ToolCall(
        tool="process.start",
        arguments={
            "argv": [sys.executable, str(script)],
            "cwd": str(tmp_path),
        },
        cwd=str(tmp_path),
    )
    context = GatewayContext(
        session_id=session_id,
        turn_id="turn-process-registry",
        goal="start a test process",
        phase="POLICY_CHECK",
    )
    pending = await gateway.authorize(call, context)
    assert pending.approval_request is not None
    request = pending.approval_request
    accepted = await gateway.authorize(
        call,
        context,
        ApprovalDecision(
            approval_id=request.approval_id,
            action_id=request.action_id,
            action_hash=request.action_hash,
            nonce=request.nonce,
            approved=True,
            actor="security-test",
        ),
    )
    assert accepted.outcome == "allow"

    started = await gateway.execute(call, context)
    try:
        assert started.status.value == "completed"
        active = storage.list_active_processes(session_id=session_id)
        assert len(active) == 1
        assert active[0]["identity_token"]

        await gateway.cancel(session_id)

        assert storage.list_active_processes(session_id=session_id) == []
    finally:
        await gateway.cancel(session_id)
