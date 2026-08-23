from __future__ import annotations

import json
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator
from astercode.storage import Storage
from astercode.subagents import reset_parent_authority


@pytest.mark.asyncio
async def test_offline_subagent_runs_independent_read_only_session(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\nchild evidence\n", encoding="utf-8")
    config_data = app_config.model_dump()
    config_data["security"]["subagents"] = {
        "enabled": True,
        "read_only": True,
        "max_depth": 1,
        "max_concurrency": 1,
        "max_tool_calls": 2,
        "max_tokens": 2_000,
        "max_elapsed_seconds": 30,
    }
    config_data["features"]["multi_agent"] = True
    config = AppConfig.model_validate(config_data)
    script = [
            {
                "plan": ["delegate one narrow read-only check"],
                "message": "Delegating the README check.",
                "tool_calls": [
                    {
                        "tool": "subagent.research",
                        "arguments": {
                            "task": "Read README.md and report its heading.",
                            "workspace": str(tmp_path),
                            "requested_tools": ["fs.read"],
                            "budget": {
                                "max_tool_calls": 1,
                                "max_tokens": 1_000,
                                "max_elapsed_seconds": 20,
                            },
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "obtain isolated read-only evidence",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["read the requested file"],
                "message": "Reading README.md.",
                "tool_calls": [
                    {
                        "tool": "fs.read",
                        "arguments": {
                            "path": "README.md",
                            "start_line": 1,
                            "end_line": 2,
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "collect the requested evidence",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The heading is Fixture.",
                "tool_calls": [],
                "outcome": "completed",
            },
            {
                "plan": [],
                "message": "The isolated child found the Fixture heading.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    provider = DeterministicFakeProvider(
        [
            {
                "decision": decision,
                "usage": {
                    "requests": 1,
                    "input_tokens": 40,
                    "output_tokens": 10,
                    "total_tokens": 50,
                    "cost_usd": 0.0,
                },
            }
            for decision in script
        ]
    )
    runtime = Orchestrator(config, provider=provider, storage=storage)

    result = await runtime.run("Use a read-only child to inspect the README heading.")

    assert result["status"] == "completed"
    # Parent accounting includes its own two model rounds plus both child
    # rounds and the child's concrete fs.read call.
    assert result["usage"]["rounds"] == 4
    assert result["usage"]["tool_calls"] == 2
    assert result["usage"]["total_tokens"] == 200
    assert [item["tool"] for item in result["tool_results"]] == [
        "subagent.research"
    ]
    delegated = json.loads(result["tool_results"][0]["stdout"])
    assert delegated["status"] == "completed"
    assert delegated["read_only"] is True
    assert delegated["evidence"][0]["tool"] == "fs.read"
    assert delegated["child_session_id"] != result["session_id"]
    child = storage.get_session(delegated["child_session_id"])
    assert child["status"] == "completed"
    checkpoint = storage.latest_checkpoint(delegated["child_session_id"])
    assert checkpoint is not None
    assert checkpoint["phase"] == "SUBAGENT_COMPLETED"
    assert checkpoint["state"]["grant_id"] == delegated["grant_id"]
    assert checkpoint["state"]["read_only"] is True
    assert runtime.subagent_policy.active_count() == 0
    assert {spec.name for spec in runtime.registry.specs()}.issuperset(
        {"subagent.research"}
    )
    await runtime.close()


@pytest.mark.asyncio
async def test_subagent_tool_is_absent_when_disabled(
    app_config: AppConfig, storage: Storage
) -> None:
    runtime = Orchestrator(
        app_config, provider=DeterministicFakeProvider(), storage=storage
    )

    assert "subagent.research" not in {spec.name for spec in runtime.registry.specs()}
    await runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("feature_enabled", "security_enabled"), [(True, False), (False, True)]
)
async def test_subagent_requires_both_feature_and_security_switches(
    app_config: AppConfig,
    storage: Storage,
    feature_enabled: bool,
    security_enabled: bool,
) -> None:
    data = app_config.model_dump()
    data["features"]["multi_agent"] = feature_enabled
    data["security"]["subagents"]["enabled"] = security_enabled
    runtime = Orchestrator(
        AppConfig.model_validate(data),
        provider=DeterministicFakeProvider(),
        storage=storage,
    )

    assert "subagent.research" not in {spec.name for spec in runtime.registry.specs()}
    await runtime.close()


@pytest.mark.asyncio
async def test_recovered_reservation_is_conservatively_charged(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    data = app_config.model_dump()
    data["features"]["multi_agent"] = True
    data["security"]["subagents"].update(
        {
            "enabled": True,
            "max_tool_calls": 2,
            "max_tokens": 200,
            "max_elapsed_seconds": 20,
        }
    )
    config = AppConfig.model_validate(data)
    parent = storage.create_session(str(tmp_path), "parent")
    child = storage.create_session(str(tmp_path), "child")
    storage.save_checkpoint(
        {
            "session_id": child["session_id"],
            "phase": "SUBAGENT_RESERVED",
            "state": {
                "parent_session_id": parent["session_id"],
                "grant_id": "subgrant_recovered",
                "budget": {
                    "max_tool_calls": 2,
                    "max_tokens": 200,
                    "max_elapsed_seconds": 20,
                },
            },
        }
    )
    runtime = Orchestrator(
        config, provider=DeterministicFakeProvider(), storage=storage
    )
    token = runtime._bind_subagent_context(
        parent["session_id"],
        {
            "max_tool_calls": 10,
            "max_tokens": 1_000,
            "max_elapsed_seconds": 100,
            "max_concurrency": 1,
        },
    )
    try:
        assert runtime.subagent_tools is not None
        result = await runtime.subagent_tools.research(
            "inspect",
            str(tmp_path),
            ["fs.read"],
            {
                "max_tool_calls": 1,
                "max_tokens": 1,
                "max_elapsed_seconds": 1,
            },
        )
    finally:
        reset_parent_authority(token)

    assert result.status == "failed"
    assert "parent remaining budget" in str(result.error)
    recovered = storage.list_subagent_reservations(parent["session_id"])
    assert [item["grant_id"] for item in recovered] == ["subgrant_recovered"]
    await runtime.close()
