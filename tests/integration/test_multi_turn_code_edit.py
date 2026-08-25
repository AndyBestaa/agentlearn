from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry


def _read_call(root: Path, purpose: str) -> dict[str, object]:
    return {
        "tool": "fs.read",
        "arguments": {"path": "calculator.py", "start_line": 1, "end_line": None},
        "host": "local",
        "cwd": str(root),
        "purpose": purpose,
    }


def _patch_call(root: Path) -> dict[str, object]:
    patch = """*** Begin Patch
*** Update File: calculator.py
-    return left - right
+    return left + right
*** End Patch"""
    return {
        "tool": "fs.apply_patch",
        "arguments": {"patch": patch},
        "host": "local",
        "cwd": str(root),
        "purpose": "fix the calculator implementation",
    }


def _approve(request: dict[str, object]) -> dict[str, object]:
    return {
        key: request[key]
        for key in ("approval_id", "action_id", "action_hash", "nonce")
    } | {"approved": True, "scope": "once", "actor": "integration-test"}


@pytest.mark.asyncio
async def test_multi_turn_code_edit_keeps_session_context_and_verified_state(
    app_config, storage, tmp_path: Path
) -> None:
    """A chat-like session can edit a file, then answer a follow-up from state.

    The scripted provider models the host loop rather than bypassing it: the
    first turn observes, pauses for an exact P1 approval, verifies the edit,
    and completes; the second turn observes the changed file and completes in
    the same persisted session.
    """

    target = tmp_path / "calculator.py"
    target.write_text(
        "def add(left, right):\n    return left - right\n", encoding="utf-8"
    )
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["inspect", "fix"],
                "message": "I found the arithmetic bug.",
                "tool_calls": [_read_call(tmp_path, "inspect the implementation")],
                "outcome": "continue",
            },
            {
                "plan": ["fix", "verify"],
                "message": "I need permission to apply the minimal fix.",
                "tool_calls": [_patch_call(tmp_path)],
                "outcome": "continue",
            },
            {
                "plan": ["verify"],
                "message": "The fix is applied; I am checking the file.",
                "tool_calls": [_read_call(tmp_path, "verify the applied fix")],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The first turn is complete.",
                "tool_calls": [],
                "outcome": "completed",
            },
            {
                "plan": ["inspect current state"],
                "message": "The follow-up sees the corrected implementation.",
                "tool_calls": [_read_call(tmp_path, "answer the follow-up")],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The follow-up is complete.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    events: list[dict[str, Any]] = []

    def capture_event(event: Mapping[str, Any]) -> None:
        events.append(dict(event))

    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        event_sink=capture_event,
    )
    try:
        first = await orchestrator.run("Find and fix the bug in calculator.py")
        assert first["status"] == "waiting_approval"
        resumed = await orchestrator.resume(first["session_id"], _approve(first["approval_request"]))
        assert resumed["status"] == "completed"
        assert target.read_text(encoding="utf-8").endswith("return left + right\n")
        assert [item["tool"] for item in resumed["tool_results"]] == [
            "fs.read",
            "fs.apply_patch",
            "fs.read",
        ]
        assert all(item["verified"] is True for item in resumed["test_status"])

        second = await orchestrator.run(
            "What changed in calculator.py?", session_id=first["session_id"]
        )
    finally:
        await orchestrator.close()

    assert second["status"] == "completed"
    assert second["session_id"] == first["session_id"]
    assert len(second["tool_results"]) == 1
    assert second["tool_results"][0]["tool"] == "fs.read"
    assert "return left + right" in second["tool_results"][0]["stdout"]
    assert second["test_status"][0]["verified"] is True

    tool_events = [
        event
        for event in events
        if event.get("event") in {"tool.started", "tool.completed"}
    ]
    assert [
        (event["event"], event["tool"], event.get("status"))
        for event in tool_events
    ] == [
        ("tool.started", "fs.read", None),
        ("tool.completed", "fs.read", "completed"),
        ("tool.started", "fs.apply_patch", None),
        ("tool.completed", "fs.apply_patch", "completed"),
        ("tool.started", "fs.read", None),
        ("tool.completed", "fs.read", "completed"),
        ("tool.started", "fs.read", None),
        ("tool.completed", "fs.read", "completed"),
    ]
    started = [event for event in tool_events if event["event"] == "tool.started"]
    completed = [
        event for event in tool_events if event["event"] == "tool.completed"
    ]
    assert [(event["call_id"], event["tool"]) for event in started] == [
        (event["call_id"], event["tool"]) for event in completed
    ]

    with sqlite3.connect(app_config.storage.database_path) as connection:
        turn_rows = connection.execute(
            "SELECT turn_id, role, content_json FROM turns WHERE session_id=? ORDER BY rowid",
            (first["session_id"],),
        ).fetchall()
    assert [row[0] for row in turn_rows] == [first["turn_id"], second["turn_id"]]
    assert [row[1] for row in turn_rows] == ["user", "user"]
    assert [request.turn_id for request in provider.requests] == [
        first["turn_id"],
        first["turn_id"],
        first["turn_id"],
        first["turn_id"],
        second["turn_id"],
        second["turn_id"],
    ]
    follow_up_context = provider.requests[-2].context["conversation"]
    assert follow_up_context == [
        {"role": "user", "content": "Find and fix the bug in calculator.py"},
        {"role": "assistant", "content": "I found the arithmetic bug."},
        {"role": "assistant", "content": "I need permission to apply the minimal fix."},
        {"role": "assistant", "content": "The fix is applied; I am checking the file."},
        {"role": "assistant", "content": "The first turn is complete."},
        {"role": "user", "content": "What changed in calculator.py?"},
    ]
