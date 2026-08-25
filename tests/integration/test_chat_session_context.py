from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry


@pytest.mark.asyncio
async def test_reused_session_includes_prior_user_and_assistant_context(
    app_config, storage
) -> None:
    provider = DeterministicFakeProvider(
        [
            {
                "plan": [],
                "message": "The first answer.",
                "tool_calls": [],
                "outcome": "completed",
            },
            {
                "plan": [],
                "message": "The follow-up answer.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    try:
        first = await orchestrator.run("Remember that the color is blue.")
        second = await orchestrator.run(
            "What color did I mention?", session_id=first["session_id"]
        )
    finally:
        await orchestrator.close()

    assert second["session_id"] == first["session_id"]
    with sqlite3.connect(app_config.storage.database_path) as connection:
        turn_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT turn_id FROM turns WHERE session_id=? ORDER BY rowid",
                (first["session_id"],),
            )
        ]
    assert turn_ids == [first["turn_id"], second["turn_id"]]
    assert [request.turn_id for request in provider.requests] == turn_ids
    conversation = provider.requests[1].context["conversation"]
    assert conversation == [
        {"role": "user", "content": "Remember that the color is blue."},
        {"role": "assistant", "content": "The first answer."},
        {"role": "user", "content": "What color did I mention?"},
    ]


@pytest.mark.asyncio
async def test_long_internal_turn_keeps_user_anchor_for_follow_up(
    app_config, storage
) -> None:
    """Internal model rounds must not evict the original user request."""

    provider = DeterministicFakeProvider(
        [
            {
                "plan": [],
                "message": f"internal round {index}",
                "tool_calls": [],
                "outcome": "continue",
            }
            for index in range(18)
        ]
        + [
            {
                "plan": [],
                "message": "The first conversation is complete.",
                "tool_calls": [],
                "outcome": "completed",
            },
            {
                "plan": [],
                "message": "The follow-up is complete.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    try:
        first = await orchestrator.run("What is the parser task?")
        assert first["status"] == "completed"
        second = await orchestrator.run(
            "What did I ask you to remember?", session_id=first["session_id"]
        )
    finally:
        await orchestrator.close()

    assert second["status"] == "completed"
    follow_up_context = provider.requests[-1].context["conversation"]
    assert {item["content"] for item in follow_up_context if item["role"] == "user"} == {
        "What is the parser task?",
        "What did I ask you to remember?",
    }
    assert len(follow_up_context) <= 16


@pytest.mark.asyncio
async def test_natural_language_cannot_replace_a_pending_approval(
    app_config, storage, tmp_path: Path
) -> None:
    target = tmp_path / "approval.txt"
    target.write_text("old\n", encoding="utf-8")
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["edit"],
                "message": "Requesting an exact edit.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {
                            "patch": "*** Begin Patch\n*** Update File: approval.txt\n-old\n+new\n*** End Patch"
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "update the fixture",
                    }
                ],
                "outcome": "continue",
            }
        ]
    )
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    try:
        paused = await orchestrator.run("Update approval.txt")
        repeated = await orchestrator.run(
            "yes, please do it", session_id=paused["session_id"]
        )
    finally:
        await orchestrator.close()

    assert paused["status"] == "waiting_approval"
    assert repeated["status"] == "waiting_approval"
    assert repeated["approval_request"] == paused["approval_request"]
    assert len(provider.requests) == 1
    assert target.read_text(encoding="utf-8") == "old\n"


@pytest.mark.asyncio
async def test_natural_language_cannot_overwrite_a_crash_interrupted_action(
    app_config, storage
) -> None:
    session = storage.create_session(str(app_config.project_root), "interrupted")
    session_id = session["session_id"]
    storage.update_session(
        session_id,
        status="running",
        state={
            "session_id": session_id,
            "status": "running",
            "blockers": [],
        },
    )
    storage.save_checkpoint(
        {
            "session_id": session_id,
            "turn_id": "turn_interrupted",
            "phase": "PRE_TOOL_CALL",
            "action_id": "action_interrupted",
            "state": {
                "tool": "fs.apply_patch",
                "status": "unknown",
                "pre_evidence": [],
            },
        }
    )
    provider = DeterministicFakeProvider()
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    try:
        result = await orchestrator.run(
            "continue and do it again", session_id=session_id
        )
    finally:
        await orchestrator.close()

    assert result["status"] == "blocked"
    assert result["reconcile"]["read_only"] is True
    assert "cannot resume or overwrite" in result["blockers"][-1]
    assert provider.requests == []
