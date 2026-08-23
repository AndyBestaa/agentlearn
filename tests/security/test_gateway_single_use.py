from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.gateway import LocalToolGateway
from astercode.models import ApprovalDecision, ToolCall, ToolError
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine
from astercode.runtime import build_registry
from astercode.storage import Storage


@pytest.mark.asyncio
async def test_gateway_approval_lease_is_single_use(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    storage.create_session(str(tmp_path), "single-use approval test", session_id="session_test")
    gateway = LocalToolGateway(
        build_registry(app_config),
        PolicyEngine(app_config, storage),
        storage,
    )
    call = ToolCall(
        tool="fs.mkdir",
        arguments={"path": "once"},
        cwd=str(tmp_path),
    )
    context = GatewayContext(
        session_id="session_test",
        turn_id="turn_test",
        goal="create one directory",
        phase="POLICY_CHECK",
    )
    pending = await gateway.authorize(call, context)
    assert pending.approval_request is not None
    request = pending.approval_request
    with sqlite3.connect(app_config.storage.database_path) as connection:
        requested_events = connection.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE event_type='approval.requested' AND action_id=?",
            (call.action_id,),
        ).fetchone()[0]
    assert requested_events == 1
    decision = ApprovalDecision(
        approval_id=request.approval_id,
        action_id=request.action_id,
        action_hash=request.action_hash,
        nonce=request.nonce,
        approved=True,
        actor="security-test",
    )
    accepted = await gateway.authorize(call, context, decision)
    assert accepted.outcome == "allow"

    first = await gateway.execute(call, context)
    second = await gateway.execute(call, context)

    assert first.status.value == "completed"
    assert second.status.value == "failed"
    assert isinstance(second.error, ToolError)
    assert second.error.code == "policy_denied"


@pytest.mark.asyncio
async def test_valid_denial_is_persisted_and_cannot_be_reapproved(
    app_config, storage, tmp_path: Path
) -> None:
    gateway = LocalToolGateway(build_registry(app_config), PolicyEngine(app_config, storage), storage)
    call = ToolCall(tool="fs.mkdir", arguments={"path": "denied"}, cwd=str(tmp_path))
    context = GatewayContext(session_id="s-deny", turn_id="t-deny", goal="deny", phase="POLICY_CHECK")
    pending = await gateway.authorize(call, context)
    request = pending.approval_request
    assert request is not None
    decision = ApprovalDecision(
        approval_id=request.approval_id,
        action_id=request.action_id,
        action_hash=request.action_hash,
        nonce=request.nonce,
        approved=False,
        reason="not now",
    )
    denied = await gateway.authorize(call, context, decision)
    assert denied.outcome == "deny"
    assert storage.get_approval(request.approval_id)["status"] == "denied"
