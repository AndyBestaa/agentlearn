from __future__ import annotations

from pathlib import Path

import pytest

from astercode.gateway import LocalToolGateway
from astercode.models import ApprovalDecision, ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry


@pytest.mark.asyncio
async def test_exact_p1_session_grant_cannot_reuse_a_changed_path_state(
    app_config, storage, tmp_path: Path
) -> None:
    session_id = "session-grant-test"
    storage.create_session(str(tmp_path), "session grant", session_id=session_id)
    gateway = LocalToolGateway(build_registry(app_config), PolicyEngine(app_config, storage), storage)
    context = GatewayContext(
        session_id=session_id,
        turn_id="turn-grant-test",
        goal="create exact directory",
        phase="POLICY_CHECK",
    )
    first = ToolCall(tool="fs.mkdir", arguments={"path": "same"}, cwd=str(tmp_path))
    pending = await gateway.authorize(first, context)
    assert pending.approval_request is not None
    request = pending.approval_request
    approved = await gateway.authorize(
        first,
        context,
        ApprovalDecision(
            approval_id=request.approval_id,
            action_id=request.action_id,
            action_hash=request.action_hash,
            nonce=request.nonce,
            approved=True,
            scope="session",
        ),
    )
    assert approved.outcome == "allow"
    assert (await gateway.execute(first, context)).status.value == "completed"

    repeated = ToolCall(tool="fs.mkdir", arguments={"path": "same"}, cwd=str(tmp_path))
    reused = await gateway.authorize(repeated, context)
    assert reused.outcome == "deny"
    assert "policy validation failed" in reused.reason

    grant = storage.list_session_grants(session_id)[0]
    storage.revoke_session_grant(grant["grant_id"])

    changed = ToolCall(tool="fs.mkdir", arguments={"path": "different"}, cwd=str(tmp_path))
    changed_auth = await gateway.authorize(changed, context)
    assert changed_auth.outcome == "require_approval"


@pytest.mark.asyncio
async def test_dry_run_never_executes_workspace_handler(app_config, storage, tmp_path: Path) -> None:
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["preview directory creation"],
                "message": "preview",
                "tool_calls": [
                    {
                        "tool": "fs.mkdir",
                        "arguments": {"path": "must-not-exist"},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "dry-run preview",
                    }
                ],
                "outcome": "continue",
            },
            {"plan": [], "message": "previewed", "tool_calls": [], "outcome": "completed"},
        ]
    )
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        dry_run=True,
    )

    result = await orchestrator.run("preview a directory creation")
    await orchestrator.close()

    assert result["status"] == "partial"
    assert not (tmp_path / "must-not-exist").exists()
    assert result["tool_results"][0]["metadata"]["dry_run"] is True
    assert result["test_status"][0]["verified"] is False
