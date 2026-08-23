from __future__ import annotations

from typing import cast

from astercode.models import utc_now
from astercode.orchestrator import AgentState, AsterCodeOrchestrator


def test_checkpoint_compaction_preserves_required_state_and_recent_evidence() -> None:
    results: list[dict[str, object]] = [
        {
            "call_id": f"call-{index}",
            "action_id": f"action-{index}",
            "tool": "fs.read",
            "host": "local",
            "cwd": "workspace",
            "status": "completed",
            "exit_code": 0,
            "stdout": "x" * 10_000,
            "stderr": "",
            "artifacts": [],
            "truncated": False,
            "side_effects": [],
            "error": None,
        }
        for index in range(12)
    ]
    state = cast(
        AgentState,
        {
            "goal": "compact safely",
            "assumptions": ["offline"],
            "completed": ["read files"],
            "pending": ["verify"],
            "active_files": ["a.py"],
            "tool_results": results,
            "test_status": [{"verified": True}],
            "approvals": [],
            "blockers": [],
            "next_action": "verify",
        },
    )

    snapshot = AsterCodeOrchestrator._checkpoint_state(state)

    assert snapshot["goal"] == "compact safely"
    assert snapshot["pending"] == ["verify"]
    assert snapshot["tool_results"][0]["compacted"] is True
    assert "stdout" not in snapshot["tool_results"][0]
    assert snapshot["tool_results"][-1]["stdout"].endswith("[checkpoint compacted]")
    assert snapshot["compaction"]["tool_results_total"] == 12


def test_provider_context_bounds_repeated_tool_output() -> None:
    orchestrator = object.__new__(AsterCodeOrchestrator)
    orchestrator.max_model_result_chars = 4_096
    orchestrator.max_model_context_chars = 8_192
    orchestrator.memory_lookup = None
    results: list[dict[str, object]] = [
        {
            "call_id": f"call-{index}",
            "action_id": f"action-{index}",
            "tool": "fs.list",
            "host": "local",
            "cwd": "workspace",
            "status": "completed",
            "exit_code": 0,
            "stdout": str(index) * 10_000,
            "stderr": "",
            "artifacts": [],
            "truncated": False,
            "side_effects": [],
            "error": None,
        }
        for index in range(6)
    ]
    state = cast(
        AgentState,
        {
            "goal": "inspect without resending every listing",
            "tool_results": results,
        },
    )

    context = orchestrator._provider_context(state)
    model_results = context["tool_results"]

    assert len(model_results) == 6
    assert all(item["compacted"] is True for item in model_results[:4])
    assert all("stdout" not in item for item in model_results[:4])
    assert sum(len(item.get("stdout", "")) + len(item.get("stderr", "")) for item in model_results) <= 8_192
    assert model_results[-1]["stdout"].startswith("5")
    assert model_results[-1]["truncated"] is True


def test_completion_evidence_must_match_latest_tool_call() -> None:
    now = utc_now().isoformat()
    result: dict[str, object] = {
        "call_id": "call-latest",
        "action_id": "action-same",
        "tool": "fs.read",
        "host": "local",
        "cwd": "workspace",
        "started_at": now,
        "ended_at": now,
        "status": "completed",
        "exit_code": None,
        "stdout": "ok",
        "stderr": "",
        "artifacts": [],
        "truncated": False,
        "side_effects": [],
        "error": None,
        "metadata": {},
    }
    mismatched = cast(
        AgentState,
        {
            "tool_results": [result],
            "test_status": [
                {
                    "call_id": "call-older",
                    "action_id": "action-same",
                    "status": "completed",
                    "verified": True,
                }
            ],
        },
    )
    matched = cast(
        AgentState,
        {
            "tool_results": [result],
            "test_status": [
                {
                    "call_id": "call-latest",
                    "action_id": "action-same",
                    "status": "completed",
                    "verified": True,
                }
            ],
        },
    )

    assert AsterCodeOrchestrator._completion_evidence(mismatched) is False
    assert AsterCodeOrchestrator._completion_evidence(matched) is True
