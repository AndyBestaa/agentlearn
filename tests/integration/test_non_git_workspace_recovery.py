from __future__ import annotations

from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage


def _git_status_call(root: Path, *, model_cwd: str | None = None) -> dict[str, object]:
    cwd = str(root) if model_cwd is None else model_cwd
    return {
        "tool": "git.status",
        "arguments": {"cwd": cwd},
        "host": "local",
        "cwd": cwd,
        "purpose": "check whether the workspace is a Git repository",
    }


@pytest.mark.asyncio
async def test_non_git_status_failure_is_observation_then_agent_creates_code(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    patch = """*** Begin Patch
*** Add File: addition.py
def add(left: int, right: int) -> int:
    return left + right
*** End Patch"""
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["inspect", "create", "verify"],
                "message": "Checking workspace state.",
                "tool_calls": [_git_status_call(tmp_path, model_cwd="/")],
                "outcome": "continue",
            },
            {
                "plan": ["create", "verify"],
                "message": "This is not a Git repository; creating the requested code directly.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {"patch": patch},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "create the addition implementation",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["verify"],
                "message": "Verifying the created file.",
                "tool_calls": [
                    {
                        "tool": "fs.read",
                        "arguments": {
                            "path": "addition.py",
                            "start_line": 1,
                            "end_line": 10,
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "verify the implementation",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The addition implementation was created and verified.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        auto_approve=True,
    )

    result = await runtime.run("Create a Python function for simple addition")
    await runtime.close()

    assert result["status"] == "completed"
    assert [item["status"] for item in result["tool_results"]] == [
        "failed",
        "completed",
        "completed",
    ]
    assert result["tool_results"][0]["tool"] == "git.status"
    assert "no git metadata" in str(result["tool_results"][0]["error"])
    assert result["blockers"] == []
    assert (tmp_path / "addition.py").read_text(encoding="utf-8").endswith(
        "return left + right\n"
    )


@pytest.mark.asyncio
async def test_repeated_read_only_failures_remain_bounded_and_cannot_claim_completion(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["inspect"],
                "message": "First Git check.",
                "tool_calls": [_git_status_call(tmp_path)],
                "outcome": "continue",
            },
            {
                "plan": ["inspect"],
                "message": "Second Git check.",
                "tool_calls": [_git_status_call(tmp_path)],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "Incorrectly claiming completion.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )

    result = await runtime.run("Create code, but only failed reads are proposed")
    await runtime.close()

    assert result["status"] == "partial"
    assert len(result["tool_results"]) == 2
    assert all(item["status"] == "failed" for item in result["tool_results"])
    assert "evidence" in " ".join(result["blockers"])


@pytest.mark.asyncio
async def test_model_patch_separator_is_repaired_only_with_exact_context(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    target = tmp_path / "value.py"
    target.write_text('VALUE = "before"\nprint(VALUE)\n', encoding="utf-8")
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["modify"],
                "message": "Updating the value.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {
                            "patch": (
                                "*** Begin Patch\n"
                                "*** Update File: value.py\n"
                                '- VALUE = "before"\n'
                                '+ VALUE = "after"\n'
                                "*** End Patch"
                            )
                        },
                        "host": "local",
                        "cwd": None,
                        "purpose": "update the exact existing value",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The exact update completed.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        auto_approve=True,
    )

    result = await runtime.run("Update value.py")
    await runtime.close()

    assert result["status"] == "completed"
    assert target.read_text(encoding="utf-8") == 'VALUE = "after"\nprint(VALUE)\n'


@pytest.mark.asyncio
async def test_stale_duplicate_patch_is_recoverable_without_reexecution(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    target = tmp_path / "value.py"
    target.write_text('VALUE = "before"\nprint(VALUE)\n', encoding="utf-8")
    patch = (
        "*** Begin Patch\n"
        "*** Update File: value.py\n"
        '-VALUE = "before"\n'
        '+VALUE = "after"\n'
        "*** End Patch"
    )
    stale_duplicate = (
        "*** Begin Patch\n"
        f"*** Update File: {target}\n"
        '-VALUE = "before"\n'
        '+VALUE = "after"\n'
        " print(VALUE)\n"
        "*** End Patch"
    )
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["modify"],
                "message": "Applying the requested update.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {"patch": stale_duplicate},
                        "host": "local",
                        "cwd": None,
                        "purpose": "update value.py",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["verify"],
                "message": "Incorrectly repeating the already applied patch.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {"patch": patch},
                        "host": "local",
                        "cwd": None,
                        "purpose": "repeat a stale update",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The first update succeeded; the stale duplicate did not execute.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        auto_approve=True,
    )

    result = await runtime.run("Update value.py once")
    await runtime.close()

    assert result["status"] == "completed"
    assert [item["status"] for item in result["tool_results"]] == [
        "completed",
        "cancelled",
    ]
    assert result["tool_results"][1]["side_effects"] == []
    assert target.read_text(encoding="utf-8") == 'VALUE = "after"\nprint(VALUE)\n'


@pytest.mark.asyncio
async def test_blank_read_root_and_non_git_failure_continue_to_workspace_write(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    patch = (
        "*** Begin Patch\n"
        "*** Add File: addition.py\n"
        "+def add(left: int, right: int) -> int:\n"
        "+    return left + right\n"
        "*** End Patch"
    )
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["inspect", "create"],
                "message": "Inspecting the workspace.",
                "tool_calls": [
                    {
                        "tool": "fs.list",
                        "arguments": {"path": "", "recursive": True},
                        "host": "local",
                        "cwd": None,
                        "purpose": "inspect the current workspace root",
                    },
                    _git_status_call(tmp_path, model_cwd="/workspace"),
                ],
                "outcome": "continue",
            },
            {
                "plan": ["create"],
                "message": "The workspace is not a Git repository; creating the code.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {"patch": patch},
                        "host": "local",
                        "cwd": None,
                        "purpose": "create the requested addition code",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The addition code was created.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        auto_approve=True,
    )

    result = await runtime.run("Create code for simple addition")
    await runtime.close()

    assert result["status"] == "completed"
    assert [item["status"] for item in result["tool_results"]] == [
        "completed",
        "failed",
        "completed",
    ]
    assert (tmp_path / "addition.py").read_text(encoding="utf-8") == (
        "def add(left: int, right: int) -> int:\n    return left + right\n"
    )


@pytest.mark.asyncio
async def test_blank_delete_target_still_fails_closed(
    app_config: AppConfig, storage: Storage
) -> None:
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["delete"],
                "message": "Submitting an invalid blank delete target.",
                "tool_calls": [
                    {
                        "tool": "fs.delete",
                        "arguments": {"path": "", "recursive": True},
                        "host": "local",
                        "cwd": None,
                        "purpose": "invalid destructive request",
                    }
                ],
                "outcome": "continue",
            }
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        auto_approve=True,
    )

    result = await runtime.run("Delete a blank target")
    await runtime.close()

    assert result["status"] == "blocked"
    assert result["tool_results"][0]["status"] == "cancelled"
    assert "PathAuthorizationError" in " ".join(result["blockers"])


@pytest.mark.asyncio
async def test_missing_stat_is_observation_then_create_continues(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    patch = (
        "*** Begin Patch\n"
        "*** Add File: expected_missing.py\n"
        "+FLAG = True\n"
        "*** End Patch"
    )
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["check", "create"],
                "message": "Checking whether the target already exists.",
                "tool_calls": [
                    {
                        "tool": "fs.stat",
                        "arguments": {"path": "expected_missing.py"},
                        "host": "local",
                        "cwd": None,
                        "purpose": "confirm the target is absent before creation",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["create"],
                "message": "The missing target is expected; creating it now.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {"patch": patch},
                        "host": "local",
                        "cwd": None,
                        "purpose": "create the requested file",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The file was created after the absence check.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
        auto_approve=True,
    )

    result = await runtime.run("Create expected_missing.py after checking it")
    await runtime.close()

    assert result["status"] == "completed"
    assert [item["status"] for item in result["tool_results"]] == [
        "failed",
        "completed",
    ]
    missing_error = str(result["tool_results"][0]["error"])
    assert "does not exist" in missing_error or "cannot resolve path" in missing_error
    assert (tmp_path / "expected_missing.py").read_text(encoding="utf-8") == (
        "FLAG = True\n"
    )
