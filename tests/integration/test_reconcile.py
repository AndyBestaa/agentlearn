from __future__ import annotations

from astercode.gateway import LocalToolGateway
from astercode.runtime import Orchestrator


def test_reconcile_compares_pre_action_hash_without_replaying(
    app_config, storage, tmp_path
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("before\n", encoding="utf-8")
    session_id = "session-reconcile"
    storage.create_session(str(tmp_path), "reconcile file", session_id=session_id)
    before = LocalToolGateway._path_evidence([str(target)])
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

    result = Orchestrator(app_config, storage=storage).reconcile(session_id)

    assert result["status"] == "blocked"
    assert result["reconcile"]["phase"] == "PRE_TOOL_CALL"
    assert result["reconcile"]["paths_changed"] is True
    assert result["reconcile"]["pre_evidence"][0]["sha256"] != result["reconcile"]["current_evidence"][0]["sha256"]
    assert target.read_text(encoding="utf-8") == "after\n"
