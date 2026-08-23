from __future__ import annotations

import json
import os
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


def _decision(request) -> ApprovalDecision:
    return ApprovalDecision(
        approval_id=request.approval_id,
        action_id=request.action_id,
        action_hash=request.action_hash,
        nonce=request.nonce,
        approved=True,
        actor="precondition-test",
    )


def _gateway(
    app_config: AppConfig,
    storage: Storage,
) -> LocalToolGateway:
    return LocalToolGateway(
        build_registry(app_config),
        PolicyEngine(app_config, storage),
        storage,
    )


def _context() -> GatewayContext:
    return GatewayContext(
        session_id="session-precondition",
        turn_id="turn-precondition",
        goal="delete exactly the approved test file",
        phase="POLICY_CHECK",
    )


@pytest.mark.asyncio
async def test_replacing_a_file_invalidates_its_pending_delete_approval(
    app_config: AppConfig,
    storage: Storage,
    tmp_path: Path,
) -> None:
    target = tmp_path / "victim.txt"
    target.write_text("same bytes\n", encoding="utf-8")
    gateway = _gateway(app_config, storage)
    call = ToolCall(
        tool="fs.delete",
        arguments={"path": str(target), "recursive": False},
        cwd=str(tmp_path),
    )
    pending = await gateway.authorize(call, _context())
    request = pending.approval_request
    assert request is not None
    assert request.normalized_action["path_preconditions"][0]["sha256"]

    replacement = tmp_path / "replacement.txt"
    replacement.write_text("same bytes\n", encoding="utf-8")
    os.replace(replacement, target)
    denied = await gateway.authorize(call, _context(), _decision(request))

    assert denied.outcome == "deny"
    assert "changed" in denied.reason
    assert storage.get_approval(request.approval_id)["status"] == "revoked"
    assert target.read_text(encoding="utf-8") == "same bytes\n"


@pytest.mark.asyncio
async def test_in_place_content_change_invalidates_pending_delete_approval(
    app_config: AppConfig,
    storage: Storage,
    tmp_path: Path,
) -> None:
    target = tmp_path / "victim.txt"
    target.write_text("original-A\n", encoding="utf-8")
    original_mtime = target.stat().st_mtime_ns
    gateway = _gateway(app_config, storage)
    call = ToolCall(
        tool="fs.delete",
        arguments={"path": str(target), "recursive": False},
        cwd=str(tmp_path),
    )
    pending = await gateway.authorize(call, _context())
    request = pending.approval_request
    assert request is not None

    target.write_text("changed--B\n", encoding="utf-8")
    os.utime(target, ns=(original_mtime, original_mtime))
    denied = await gateway.authorize(call, _context(), _decision(request))

    assert denied.outcome == "deny"
    assert target.read_text(encoding="utf-8") == "changed--B\n"


@pytest.mark.asyncio
async def test_replacement_after_approval_is_not_deleted_during_execute(
    app_config: AppConfig,
    storage: Storage,
    tmp_path: Path,
) -> None:
    storage.create_session(
        str(tmp_path),
        "delete exactly the approved test file",
        session_id="session-precondition",
    )
    target = tmp_path / "victim.txt"
    target.write_text("approved\n", encoding="utf-8")
    gateway = _gateway(app_config, storage)
    call = ToolCall(
        tool="fs.delete",
        arguments={"path": str(target), "recursive": False},
        cwd=str(tmp_path),
    )
    pending = await gateway.authorize(call, _context())
    request = pending.approval_request
    assert request is not None
    accepted = await gateway.authorize(call, _context(), _decision(request))
    assert accepted.outcome == "allow"

    replacement = tmp_path / "replacement.txt"
    replacement.write_text("replacement\n", encoding="utf-8")
    os.replace(replacement, target)
    result = await gateway.execute(call, _context())

    assert result.status.value == "failed"
    assert isinstance(result.error, ToolError)
    assert result.error.code == "approval_binding_mismatch"
    assert target.read_text(encoding="utf-8") == "replacement\n"
    with sqlite3.connect(app_config.storage.database_path) as connection:
        persisted = connection.execute(
            "SELECT status, result_json FROM tool_calls WHERE call_id=?",
            (call.call_id,),
        ).fetchone()
    assert persisted is not None
    assert persisted[0] == "failed"
    assert json.loads(persisted[1])["error"]["code"] == "approval_binding_mismatch"
