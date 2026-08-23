from __future__ import annotations

import json

import pytest
import typer

from astercode.cli import _run_task_async


def _script() -> list[dict[str, object]]:
    return [
        {
            "plan": ["read"],
            "message": "read fixture",
            "tool_calls": [
                {
                    "tool": "fs.read",
                    "arguments": {"path": "sample.txt", "start_line": 1, "end_line": None},
                    "host": "local",
                    "cwd": None,
                    "purpose": "offline replay",
                }
            ],
            "outcome": "continue",
        },
        {"plan": [], "message": "done", "tool_calls": [], "outcome": "completed"},
    ]


@pytest.mark.asyncio
async def test_cli_replay_runs_without_api_key_or_network(tmp_path) -> None:
    (tmp_path / "sample.txt").write_text("offline replay contents\n", encoding="utf-8")
    fixture = tmp_path / "replay.json"
    fixture.write_text(json.dumps(_script()), encoding="utf-8")

    result = await _run_task_async(
        "read the sample",
        root=tmp_path,
        session_id=None,
        fake=False,
        auto_approve=False,
        replay=fixture,
        budget_overrides={
            "max_rounds": 3,
            "max_tool_calls": 2,
            "max_tokens": 10_000,
            "max_elapsed_seconds": 30,
        },
    )

    assert result["status"] == "completed"
    assert "offline replay contents" in result["tool_results"][0]["stdout"]
    assert result["budget"]["max_rounds"] == 3
    assert result["budget"]["max_tool_calls"] == 2
    assert result["budget"]["max_tokens"] == 10_000
    assert result["budget"]["max_elapsed_seconds"] == 30


@pytest.mark.asyncio
async def test_cli_replay_rejects_fixture_outside_workspace(tmp_path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    fixture = tmp_path / "outside.json"
    fixture.write_text(json.dumps(_script()), encoding="utf-8")

    with pytest.raises(typer.BadParameter, match="invalid replay fixture"):
        await _run_task_async(
            "do not read outside",
            root=root,
            session_id=None,
            fake=False,
            auto_approve=False,
            replay=fixture,
        )
