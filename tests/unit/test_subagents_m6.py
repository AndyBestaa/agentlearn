from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import astercode.subagents as subagents_module
from astercode.subagents import (
    DeterministicFakeSubagentRunner,
    ReadOnlySubagentPolicy,
    SubagentBlockedError,
    SubagentBudget,
    SubagentRequest,
    SubagentResearchTools,
    bind_parent_authority,
    make_parent_authority,
    reset_parent_authority,
    update_parent_authority_usage,
)


def _parent(tmp_path: Path):
    return make_parent_authority(
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read", "fs.search", "fs.apply_patch"],
        remaining_budget=SubagentBudget(max_tool_calls=8, max_tokens=4_000, max_elapsed_seconds=60),
        max_depth=1,
    )


def test_subagent_grant_is_read_only_permission_intersection(tmp_path: Path) -> None:
    grant = ReadOnlySubagentPolicy(enabled=True).grant(
        _parent(tmp_path),
        SubagentRequest(
            task="inspect the parser",
            workspace=tmp_path,
            requested_tools=frozenset({"fs.read", "fs.search"}),
            budget=SubagentBudget(max_tool_calls=4, max_tokens=2_000, max_elapsed_seconds=30),
        ),
    )

    assert grant.read_only is True
    assert grant.allowed_tools == {"fs.read", "fs.search"}
    assert grant.depth == 1


def test_subagent_cannot_inherit_parent_write_permission(tmp_path: Path) -> None:
    request = SubagentRequest(
        task="modify a file",
        workspace=tmp_path,
        requested_tools=frozenset({"fs.apply_patch"}),
    )

    with pytest.raises(SubagentBlockedError, match="read-only"):
        ReadOnlySubagentPolicy(enabled=True).grant(_parent(tmp_path), request)


def test_subagent_cannot_exceed_parent_budget_or_depth(tmp_path: Path) -> None:
    too_large = SubagentRequest(
        task="inspect all files",
        workspace=tmp_path,
        requested_tools=frozenset({"fs.read"}),
        budget=SubagentBudget(max_tool_calls=9, max_tokens=4_000, max_elapsed_seconds=60),
    )
    with pytest.raises(SubagentBlockedError, match="budget"):
        ReadOnlySubagentPolicy(enabled=True).grant(_parent(tmp_path), too_large)

    parent_at_limit = _parent(tmp_path).model_copy(update={"depth": 1})
    with pytest.raises(SubagentBlockedError, match="depth"):
        ReadOnlySubagentPolicy(enabled=True).grant(
            parent_at_limit,
            SubagentRequest(task="inspect", workspace=tmp_path, requested_tools=frozenset({"fs.read"})),
        )

    concurrency_full = _parent(tmp_path).model_copy(update={"active_children": 1})
    with pytest.raises(SubagentBlockedError, match="concurrency"):
        ReadOnlySubagentPolicy(enabled=True).grant(
            concurrency_full,
            SubagentRequest(
                task="inspect",
                workspace=tmp_path,
                requested_tools=frozenset({"fs.read"}),
                budget=SubagentBudget(max_tool_calls=2, max_tokens=100, max_elapsed_seconds=10),
            ),
        )


def test_fake_subagent_enforces_granted_runtime_budget(tmp_path: Path) -> None:
    grant = ReadOnlySubagentPolicy(enabled=True).grant(
        _parent(tmp_path),
        SubagentRequest(
            task="inspect",
            workspace=tmp_path,
            requested_tools=frozenset({"fs.read"}),
            budget=SubagentBudget(max_tool_calls=2, max_tokens=100, max_elapsed_seconds=10),
        ),
    )
    runner = DeterministicFakeSubagentRunner(
        {"inspect": {"summary": "ok", "used_tools": ["fs.read"], "tool_calls": 1, "tokens": 20}}
    )

    result = runner.run(grant)

    assert result["summary"] == "ok"
    assert result["read_only"] is True


def test_identical_requests_get_unique_budget_bound_grants(tmp_path: Path) -> None:
    policy = ReadOnlySubagentPolicy(enabled=True)
    parent = make_parent_authority(
        authority_id="same-parent",
        parent_session_id="parent-session",
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read"],
        remaining_budget=SubagentBudget(
            max_tool_calls=4, max_tokens=400, max_elapsed_seconds=40
        ),
        max_concurrency=2,
    )
    request = SubagentRequest(
        task="inspect",
        workspace=tmp_path,
        requested_tools=frozenset({"fs.read"}),
        budget=SubagentBudget(
            max_tool_calls=2, max_tokens=200, max_elapsed_seconds=20
        ),
    )

    first = policy.grant(parent, request)
    second = policy.grant(parent, request)

    assert first.grant_id != second.grant_id
    assert first.binding_hash != second.binding_hash
    assert first.budget == second.budget
    assert policy.active_count("same-parent") == 2
    assert policy.release(first.grant_id) is True
    assert policy.release(first.grant_id) is False
    assert policy.active_count("same-parent") == 1


def test_concurrency_and_budget_are_reserved_atomically(tmp_path: Path) -> None:
    policy = ReadOnlySubagentPolicy(enabled=True)
    parent = make_parent_authority(
        authority_id="concurrent-parent",
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read"],
        remaining_budget=SubagentBudget(
            max_tool_calls=4, max_tokens=200, max_elapsed_seconds=20
        ),
        max_concurrency=2,
    )
    request = SubagentRequest(
        task="inspect",
        workspace=tmp_path,
        requested_tools=frozenset({"fs.read"}),
        budget=SubagentBudget(
            max_tool_calls=2, max_tokens=100, max_elapsed_seconds=10
        ),
    )

    def reserve() -> str:
        try:
            return policy.grant(parent, request).grant_id
        except SubagentBlockedError:
            return "blocked"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: reserve(), range(8)))

    granted = [item for item in outcomes if item != "blocked"]
    assert len(granted) == 2
    assert len(set(granted)) == 2
    assert policy.active_count("concurrent-parent") == 2


def test_released_grant_frees_only_the_atomic_reservation(tmp_path: Path) -> None:
    policy = ReadOnlySubagentPolicy(enabled=True)
    parent = make_parent_authority(
        authority_id="sequential-parent",
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read"],
        remaining_budget=SubagentBudget(
            max_tool_calls=2, max_tokens=200, max_elapsed_seconds=20
        ),
    )
    request = SubagentRequest(
        task="inspect",
        workspace=tmp_path,
        requested_tools=frozenset({"fs.read"}),
        budget=SubagentBudget(
            max_tool_calls=1, max_tokens=100, max_elapsed_seconds=10
        ),
    )

    grant = policy.grant(parent, request)
    assert policy.release(grant.grant_id) is True
    next_grant = policy.grant(parent, request)
    assert next_grant.grant_id != grant.grant_id
    assert policy.release(next_grant.grant_id) is True
    assert policy.active_count() == 0


def test_browser_is_not_a_subagent_capability(tmp_path: Path) -> None:
    request = SubagentRequest(
        task="inspect a page",
        workspace=tmp_path,
        requested_tools=frozenset({"browser.snapshot"}),
    )

    with pytest.raises(SubagentBlockedError, match="read-only"):
        ReadOnlySubagentPolicy(enabled=True).grant(_parent(tmp_path), request)


@pytest.mark.asyncio
async def test_failed_child_releases_slot_and_redacts_bounded_output(
    tmp_path: Path,
) -> None:
    policy = ReadOnlySubagentPolicy(enabled=True)
    parent = make_parent_authority(
        authority_id="failure-parent",
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read"],
        remaining_budget=SubagentBudget(
            max_tool_calls=2, max_tokens=200, max_elapsed_seconds=20
        ),
    )
    token = bind_parent_authority(parent)
    try:
        failing = SubagentResearchTools(
            policy, DeterministicFakeSubagentRunner({})
        )
        failure = await failing.research(
            "inspect",
            str(tmp_path),
            ["fs.read"],
            {
                "max_tool_calls": 1,
                "max_tokens": 100,
                "max_elapsed_seconds": 10,
            },
        )
        assert failure.status == "failed"
        assert policy.active_count() == 0

        secret = "sk-" + "a" * 48
        noisy = SubagentResearchTools(
            policy,
            DeterministicFakeSubagentRunner(
                {
                    "inspect": {
                        "summary": secret + " " + "x " * 15_000,
                        "used_tools": ["fs.read"],
                        "tool_calls": 1,
                        "tokens": 10,
                    }
                }
            ),
        )
        success = await noisy.research(
            "inspect",
            str(tmp_path),
            ["fs.read"],
            {
                "max_tool_calls": 1,
                "max_tokens": 100,
                "max_elapsed_seconds": 10,
            },
        )
        assert secret not in success.stdout
        assert success.truncated is True
        assert len(success.stdout) <= 20_020
        assert success.metadata["child_usage_charge"] == {
            "rounds": 1,
            "tool_calls": 1,
            "input_tokens": 10,
            "output_tokens": 0,
            "total_tokens": 10,
            "cost_usd": 0.0,
        }
        assert policy.active_count() == 0
    finally:
        reset_parent_authority(token)


@pytest.mark.asyncio
async def test_cancelled_child_releases_slot(tmp_path: Path) -> None:
    class WaitingRunner:
        async def run(self, grant: Any) -> dict[str, Any]:
            del grant
            await asyncio.Event().wait()
            return {}

    policy = ReadOnlySubagentPolicy(enabled=True)
    parent = make_parent_authority(
        authority_id="cancel-parent",
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read"],
        remaining_budget=SubagentBudget(
            max_tool_calls=1, max_tokens=100, max_elapsed_seconds=10
        ),
    )
    token = bind_parent_authority(parent)
    try:
        tools = SubagentResearchTools(policy, WaitingRunner())
        task = asyncio.create_task(
            tools.research(
                "inspect",
                str(tmp_path),
                ["fs.read"],
                {
                    "max_tool_calls": 1,
                    "max_tokens": 100,
                    "max_elapsed_seconds": 10,
                },
            )
        )
        await asyncio.sleep(0)
        assert policy.active_count() == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert policy.active_count() == 0
    finally:
        reset_parent_authority(token)


@pytest.mark.asyncio
async def test_parent_live_usage_reduces_child_budget(tmp_path: Path) -> None:
    policy = ReadOnlySubagentPolicy(enabled=True)
    parent = make_parent_authority(
        authority_id="used-parent",
        authorized_roots=[tmp_path],
        allowed_tools=["fs.read"],
        remaining_budget=SubagentBudget(
            max_tool_calls=2, max_tokens=200, max_elapsed_seconds=20
        ),
    )
    token = bind_parent_authority(parent)
    try:
        update_parent_authority_usage(
            {"tool_calls": 1, "total_tokens": 150}
        )
        tools = SubagentResearchTools(
            policy,
            DeterministicFakeSubagentRunner(
                {"inspect": {"summary": "unused", "used_tools": []}}
            ),
        )
        result = await tools.research(
            "inspect",
            str(tmp_path),
            ["fs.read"],
            {
                "max_tool_calls": 1,
                "max_tokens": 100,
                "max_elapsed_seconds": 10,
            },
        )
        assert result.status == "failed"
        assert "parent remaining budget" in str(result.error)
        assert policy.active_count() == 0
    finally:
        reset_parent_authority(token)


@pytest.mark.asyncio
async def test_runner_cancel_parent_is_scoped_and_waits_for_task() -> None:
    class FakeCore:
        def __init__(self) -> None:
            self.cancelled: list[str] = []

        async def cancel(self, session_id: str) -> None:
            self.cancelled.append(session_id)

    async def wait_forever() -> dict[str, Any]:
        await asyncio.Event().wait()
        return {}

    runner = object.__new__(subagents_module.OfflineReadOnlyAgentRunner)
    runner._active_lock = asyncio.Lock()
    first_core = FakeCore()
    second_core = FakeCore()
    first_task = asyncio.create_task(wait_forever())
    second_task = asyncio.create_task(wait_forever())
    runner._active = {
        "grant-a": subagents_module._ActiveChild(
            "parent-a", "child-a", first_core, first_task
        ),
        "grant-b": subagents_module._ActiveChild(
            "parent-b", "child-b", second_core, second_task
        ),
    }

    await runner.cancel_parent("parent-a")

    assert first_task.done() is True
    assert first_task.cancelled() is True
    assert first_core.cancelled == ["child-a"]
    assert second_task.done() is False
    assert second_core.cancelled == []
    await runner.cancel_all()
    assert second_task.done() is True
    assert second_core.cancelled == ["child-b"]
