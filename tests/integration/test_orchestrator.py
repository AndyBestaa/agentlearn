from __future__ import annotations

from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.models import ApprovalDecision, RiskLevel, ToolError, ToolResult, ToolSpec, ToolStatus, utc_now
from astercode.orchestrator import AsterCodeOrchestrator, GatewayAuthorization
from astercode.provider import DeterministicFakeProvider, ProviderDecision, ProviderResponse, ProviderStreamEvent
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage


@pytest.mark.asyncio
async def test_fake_provider_runs_langgraph_tool_loop(
    app_config: AppConfig,
    storage: Storage,
    replay_script: list[dict[str, object]],
    tmp_path: Path,
) -> None:
    (tmp_path / "sample.txt").write_text("hello from the workspace\n", encoding="utf-8")
    provider = DeterministicFakeProvider(replay_script)
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )

    result = await orchestrator.run("Read sample.txt and report what it contains")

    assert result["status"] == "completed"
    assert len(provider.requests) == 2
    assert result["tool_results"][0]["tool"] == "fs.read"
    assert "hello from the workspace" in result["tool_results"][0]["stdout"]
    assert len(result["test_status"]) == 1
    assert result["test_status"][0]["call_id"] == result["tool_results"][0]["call_id"]
    assert result["test_status"][0]["verified"] is True
    assert "CHECKPOINT" in result["phase_history"]
    await orchestrator.close()


@pytest.mark.asyncio
async def test_approval_interrupt_and_bound_resume(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["create the requested directory"],
                "message": "A reversible workspace write is proposed.",
                "tool_calls": [
                    {
                        "tool": "fs.mkdir",
                        "arguments": {"path": "generated"},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "create the requested workspace directory",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The directory was created.",
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
        auto_approve=False,
    )

    paused = await orchestrator.run("Create a generated directory")

    assert paused["status"] == "waiting_approval"
    assert not (tmp_path / "generated").exists()
    request = paused["approval_request"]
    decision = ApprovalDecision(
        approval_id=request["approval_id"],
        action_id=request["action_id"],
        action_hash=request["action_hash"],
        nonce=request["nonce"],
        approved=True,
        actor="integration-test",
    )

    resumed = await orchestrator.resume(paused["session_id"], decision.model_dump(mode="json"))

    assert resumed["status"] == "completed"
    assert (tmp_path / "generated").is_dir()
    assert resumed["tool_results"][0]["tool"] == "fs.mkdir"
    assert resumed["approvals"][0]["approval_id"] == request["approval_id"]
    await orchestrator.close()


@pytest.mark.asyncio
async def test_changed_approval_binding_never_executes(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["create a directory"],
                "message": "Approval is required.",
                "tool_calls": [
                    {
                        "tool": "fs.mkdir",
                        "arguments": {"path": "must-not-exist"},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "exercise approval binding",
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
    paused = await orchestrator.run("Exercise an approval mismatch")
    request = paused["approval_request"]
    changed = ApprovalDecision(
        approval_id=request["approval_id"],
        action_id=request["action_id"],
        action_hash="0" * 64,
        nonce=request["nonce"],
        approved=True,
        actor="integration-test",
    )

    resumed = await orchestrator.resume(paused["session_id"], changed.model_dump(mode="json"))

    assert resumed["status"] == "blocked"
    assert not (tmp_path / "must-not-exist").exists()
    assert resumed["usage"]["tool_calls"] == 0
    await orchestrator.close()


@pytest.mark.asyncio
async def test_provider_cannot_close_task_without_evidence(app_config, storage) -> None:
    provider = DeterministicFakeProvider(
        [{"plan": [], "message": "done", "tool_calls": [], "outcome": "completed"}]
    )
    orchestrator = Orchestrator(
        app_config, provider=provider, registry=build_registry(app_config), storage=storage
    )
    result = await orchestrator.run("claim completion without doing work")
    await orchestrator.close()
    assert result["status"] == "partial"
    assert "evidence" in " ".join(result["blockers"])


@pytest.mark.asyncio
async def test_relevant_long_term_memory_is_advisory_context(app_config, storage) -> None:
    proposal = storage.propose_memory(
        content="The project uses pytest for local validation",
        namespace="project",
        source="integration-test",
    )
    storage.commit_memory(proposal["proposal_id"])
    provider = DeterministicFakeProvider(
        [{"plan": [], "message": "inspect", "tool_calls": [], "outcome": "completed"}]
    )
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    await orchestrator.run("pytest")
    await orchestrator.close()
    memories = provider.requests[0].context["long_term_memory"]
    assert memories and memories[0]["namespace"] == "project"


@pytest.mark.asyncio
async def test_orchestrator_consumes_provider_stream_contract(app_config, storage) -> None:
    class StreamOnlyProvider:
        name = "stream-only"
        is_live = False

        async def complete(self, request):
            raise AssertionError("the orchestrator must consume stream(), not complete()")

        async def stream(self, request):
            yield ProviderStreamEvent(type="started")
            yield ProviderStreamEvent(type="delta", delta='{"plan":[]')
            yield ProviderStreamEvent(
                type="completed",
                response=ProviderResponse(
                    decision=ProviderDecision(
                        plan=[],
                        message="No executable proposal.",
                        tool_calls=[],
                        outcome="completed",
                    ),
                    response_id="offline-stream-response",
                ),
            )

    emitted: list[dict[str, object]] = []
    core = AsterCodeOrchestrator(
        StreamOnlyProvider(),
        Orchestrator(app_config, storage=storage).gateway,
        event_sink=lambda event: emitted.append(dict(event)),
    )

    result = await core.run("exercise the provider stream")

    assert result["status"] == "partial"
    assert [item["type"] for item in result["provider_events"]] == ["started", "delta", "completed"]
    assert [item["event"] for item in emitted] == ["provider.started", "provider.delta", "provider.completed"]
    assert emitted[1]["delta"] == '{"plan":[]'


@pytest.mark.asyncio
async def test_retry_is_limited_to_idempotent_retryable_calls(tmp_path: Path) -> None:
    class FlakyGateway:
        def __init__(self) -> None:
            self.attempts = 0

        async def authorize(self, call, context, decision=None):
            return GatewayAuthorization(outcome="allow", risk=RiskLevel.P0, reason="read-only test")

        async def execute(self, call, context):
            self.attempts += 1
            now = utc_now()
            if self.attempts == 1:
                return ToolResult(
                    call_id=call.call_id,
                    action_id=call.action_id,
                    tool=call.tool,
                    cwd=call.cwd,
                    started_at=now,
                    ended_at=now,
                    status=ToolStatus.FAILED,
                    error=ToolError(code="transient", message="temporary read failure", retryable=True),
                )
            return ToolResult(
                call_id=call.call_id,
                action_id=call.action_id,
                tool=call.tool,
                cwd=call.cwd,
                started_at=now,
                ended_at=now,
                status=ToolStatus.COMPLETED,
                stdout="recovered",
            )

        async def verify(self, result, context):
            return {"verified": result.status is ToolStatus.COMPLETED}

    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["read once"],
                "message": "read",
                "tool_calls": [
                    {
                        "tool": "test.read",
                        "arguments": {},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "exercise safe retry",
                    }
                ],
                "outcome": "continue",
            },
            {"plan": [], "message": "done", "tool_calls": [], "outcome": "completed"},
        ]
    )
    gateway = FlakyGateway()
    core = AsterCodeOrchestrator(
        provider,
        gateway,
        tools=[ToolSpec(name="test.read", capability="test.read", idempotent=True)],
        max_tool_retries=2,
    )

    result = await core.run("retry a transient read")

    assert result["status"] == "completed"
    assert gateway.attempts == 2
    assert result["usage"]["tool_calls"] == 2
    assert next(iter(result["retry_attempts"].values())) == 1


@pytest.mark.asyncio
async def test_non_idempotent_failure_is_never_retried(tmp_path: Path) -> None:
    class FailingGateway:
        def __init__(self) -> None:
            self.attempts = 0

        async def authorize(self, call, context, decision=None):
            return GatewayAuthorization(outcome="allow", risk=RiskLevel.P0, reason="test")

        async def execute(self, call, context):
            self.attempts += 1
            now = utc_now()
            return ToolResult(
                call_id=call.call_id,
                action_id=call.action_id,
                tool=call.tool,
                cwd=call.cwd,
                started_at=now,
                ended_at=now,
                status=ToolStatus.FAILED,
                error=ToolError(code="transient", message="do not replay", retryable=True),
            )

    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["perform one non-idempotent action"],
                "message": "act once",
                "tool_calls": [
                    {
                        "tool": "test.write",
                        "arguments": {},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "prove non-idempotent failures are not replayed",
                    }
                ],
                "outcome": "continue",
            }
        ]
    )
    gateway = FailingGateway()
    core = AsterCodeOrchestrator(
        provider,
        gateway,
        tools=[ToolSpec(name="test.write", capability="test.write", idempotent=False)],
        max_tool_retries=8,
    )

    result = await core.run("never replay this action")

    assert result["status"] == "failed"
    assert gateway.attempts == 1
    assert result["usage"]["tool_calls"] == 1
    assert result["retry_attempts"] == {}
