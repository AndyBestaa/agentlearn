from __future__ import annotations

import pytest

from astercode.runtime import Orchestrator


def test_reconcile_compares_pre_action_hash_without_replaying(
    app_config, storage, tmp_path
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("before\n", encoding="utf-8")
    session_id = "session-reconcile"
    storage.create_session(str(tmp_path), "reconcile file", session_id=session_id)
    orchestrator = Orchestrator(app_config, storage=storage)
    before = orchestrator.gateway._path_evidence([str(target)])
    storage.save_checkpoint(
        {
            "session_id": session_id,
            "turn_id": "turn-reconcile",
            "phase": "PRE_TOOL_CALL",
            "action_id": "action-reconcile",
            "state": {
                "tool": "fs.apply_patch",
                "status": "unknown",
                "pre_evidence": before,
            },
        }
    )
    target.write_text("after\n", encoding="utf-8")

    result = orchestrator.reconcile(session_id)

    assert result["status"] == "blocked"
    assert result["reconcile"]["phase"] == "PRE_TOOL_CALL"
    assert result["reconcile"]["paths_changed"] is True
    assert result["reconcile"]["pre_evidence"][0]["sha256"] != result["reconcile"]["current_evidence"][0]["sha256"]
    assert target.read_text(encoding="utf-8") == "after\n"


def test_reconcile_never_reads_a_checkpoint_path_outside_authorized_roots(
    app_config, storage, tmp_path, monkeypatch
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-secret.txt"
    outside.write_text("EXTERNAL_SECRET_PROOF", encoding="utf-8")
    session_id = "session-reconcile-untrusted-path"
    storage.create_session(str(tmp_path), "reconcile safely", session_id=session_id)
    storage.save_checkpoint(
        {
            "session_id": session_id,
            "turn_id": "turn-reconcile-untrusted-path",
            "phase": "PRE_TOOL_CALL",
            "action_id": "action-reconcile-untrusted-path",
            "state": {
                "tool": "fs.apply_patch",
                "status": "unknown",
                "pre_evidence": [{"path": str(outside), "exists": True}],
            },
        }
    )
    path_open = type(outside).open

    def guarded_open(path, *args, **kwargs):
        if path == outside:
            raise AssertionError("reconcile attempted to open an external path")
        return path_open(path, *args, **kwargs)

    monkeypatch.setattr(type(outside), "open", guarded_open)
    try:
        result = Orchestrator(app_config, storage=storage).reconcile(session_id)
    finally:
        outside.unlink(missing_ok=True)

    evidence = result["reconcile"]["current_evidence"][0]
    assert evidence["kind"] == "blocked"
    assert evidence["error"] == "outside_authorized_roots"
    assert "sha256" not in evidence


@pytest.mark.asyncio
async def test_resume_refuses_a_crash_interrupted_session(
    app_config, storage, tmp_path
) -> None:
    session_id = "session-crash-cannot-resume"
    storage.create_session(str(tmp_path), "do not replay", session_id=session_id)
    storage.update_session(
        session_id,
        status="running",
        state={"session_id": session_id, "status": "running"},
    )
    storage.save_checkpoint(
        {
            "session_id": session_id,
            "turn_id": "turn-crash-cannot-resume",
            "phase": "PRE_TOOL_CALL",
            "action_id": "action-crash-cannot-resume",
            "state": {
                "status": "unknown",
                "pre_evidence": [],
            },
        }
    )
    orchestrator = Orchestrator(app_config, storage=storage)
    try:
        result = await orchestrator.resume(session_id, {})
    finally:
        await orchestrator.close()

    assert result["status"] == "blocked"
    assert "read-only reconciliation" in result["blockers"][0]
