from __future__ import annotations

import sys
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.gateway import LocalToolGateway
from astercode.models import ApprovalDecision, ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine, RuntimePolicyCapabilities
from astercode.runtime import build_registry
from astercode.storage import Storage


@pytest.mark.asyncio
async def test_explicit_unsandboxed_process_approval_is_narrow(app_config: AppConfig, tmp_path: Path) -> None:
    data = app_config.model_dump()
    data["security"]["process"]["allow_unsandboxed_process"] = True
    config = AppConfig.model_validate(data)
    storage = Storage(config.storage)
    storage.initialize()
    storage.create_session(str(tmp_path), "approved local process test", session_id="s")
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
    script = tmp_path / "print_ok.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    call = ToolCall(tool="process.exec", arguments={"argv": [sys.executable, str(script)], "cwd": str(tmp_path), "timeout": 10}, cwd=str(tmp_path))
    context = GatewayContext(session_id="s", turn_id="t", goal="run a test", phase="POLICY_CHECK")
    pending = await gateway.authorize(call, context)
    assert pending.approval_request is not None
    request = pending.approval_request
    decision = ApprovalDecision(approval_id=request.approval_id, action_id=request.action_id, action_hash=request.action_hash, nonce=request.nonce, approved=True)
    accepted = await gateway.authorize(call, context, decision)
    assert accepted.outcome == "allow"
    result = await gateway.execute(call, context)
    assert result.status.value == "completed"
    assert result.stdout.strip() == "ok"


@pytest.mark.asyncio
async def test_approved_send_input_and_stop_do_not_receive_launch_only_flag(
    app_config: AppConfig, tmp_path: Path
) -> None:
    data = app_config.model_dump()
    data["security"]["process"]["allow_unsandboxed_process"] = True
    config = AppConfig.model_validate(data)
    storage = Storage(config.storage)
    storage.initialize()
    storage.create_session(str(tmp_path), "control process", session_id="process-control")
    capabilities = RuntimePolicyCapabilities(
        process_sandbox_enforced=True,
        process_network_policy_enforced=True,
    )
    gateway = LocalToolGateway(
        build_registry(
            config,
            verified_process_sandbox=True,
            verified_process_network_policy=True,
        ),
        PolicyEngine(config, storage, capabilities),
        storage,
    )
    context = GatewayContext(
        session_id="process-control",
        turn_id="turn-control",
        goal="control one approved process",
        phase="POLICY_CHECK",
    )

    async def approve_and_execute(call: ToolCall):
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
            ),
        )
        assert accepted.outcome == "allow"
        return await gateway.execute(call, context)

    script = tmp_path / "wait_for_input.py"
    script.write_text(
        "import sys\nimport time\nprint(sys.stdin.readline().strip(), flush=True)\ntime.sleep(120)\n",
        encoding="utf-8",
    )
    started = await approve_and_execute(
        ToolCall(
            tool="process.start",
            arguments={
                "argv": [sys.executable, str(script)],
                "cwd": str(tmp_path),
            },
            cwd=str(tmp_path),
        )
    )
    assert started.status.value == "completed", started.error
    handle = started.stdout.strip()
    try:
        sent = await approve_and_execute(
            ToolCall(
                tool="process.send_input",
                arguments={"action_id": handle, "input": "hello\n"},
                cwd=str(tmp_path),
            )
        )
        assert sent.status.value == "completed", sent.error

        stopped = await approve_and_execute(
            ToolCall(
                tool="process.stop",
                arguments={"action_id": handle},
                cwd=str(tmp_path),
            )
        )
        assert stopped.status.value == "completed", stopped.error
        assert storage.list_active_processes(session_id="process-control") == []
    finally:
        await gateway.cancel("process-control")
