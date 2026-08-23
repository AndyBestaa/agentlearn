from __future__ import annotations

import asyncio
import time

import pytest

from astercode.models import RiskLevel, ToolSpec
from astercode.orchestrator import AsterCodeOrchestrator, GatewayAuthorization, RunBudget
from astercode.provider import (
    ProviderDecision,
    ProviderRequest,
    ProviderResponse,
    ProviderStreamEvent,
    ProviderUsage,
)


class _NoopGateway:
    async def authorize(self, call, context, decision=None):
        return GatewayAuthorization(outcome="allow", risk=RiskLevel.P0, reason="budget test")

    async def execute(self, call, context):
        raise AssertionError("no tool should execute")


@pytest.mark.asyncio
async def test_provider_call_is_cancelled_at_remaining_elapsed_budget() -> None:
    class SlowProvider:
        name = "slow-fake"
        is_live = False

        async def complete(self, request):
            raise AssertionError("orchestrator must use stream")

        async def stream(self, request):
            yield ProviderStreamEvent(type="started")
            await asyncio.sleep(10)

    started = time.monotonic()
    result = await AsterCodeOrchestrator(SlowProvider(), _NoopGateway()).run(
        "wait for a slow model",
        budget=RunBudget(max_elapsed_seconds=0.05),
    )

    assert time.monotonic() - started < 1
    assert result["status"] == "blocked"
    assert "remaining elapsed-time budget" in " ".join(result["blockers"])
    assert result["usage"]["rounds"] == 0


@pytest.mark.asyncio
async def test_provider_request_receives_remaining_token_caps() -> None:
    class CapturingProvider:
        name = "capturing-fake"
        is_live = False

        def __init__(self) -> None:
            self.requests: list[ProviderRequest] = []

        async def complete(self, request):
            raise AssertionError("orchestrator must use stream")

        async def stream(self, request):
            self.requests.append(request)
            yield ProviderStreamEvent(type="started")
            yield ProviderStreamEvent(
                type="completed",
                response=ProviderResponse(
                    decision=ProviderDecision(
                        plan=[],
                        message="no evidence",
                        tool_calls=[],
                        outcome="completed",
                    ),
                    usage=ProviderUsage(requests=1, cost_usd=0.0),
                ),
            )

    provider = CapturingProvider()
    result = await AsterCodeOrchestrator(provider, _NoopGateway()).run(
        "use a tiny token budget",
        budget=RunBudget(max_tokens=7, max_output_tokens=3),
    )

    assert result["status"] == "partial"
    assert len(provider.requests) == 1
    assert provider.requests[0].max_output_tokens == 3
    assert provider.requests[0].max_total_tokens == 7
    assert provider.requests[0].timeout_seconds is not None


@pytest.mark.asyncio
async def test_unknown_cost_stops_before_another_provider_round() -> None:
    class UnknownCostProvider:
        name = "unknown-cost-fake"
        is_live = False

        def __init__(self) -> None:
            self.calls = 0

        async def complete(self, request):
            raise AssertionError("orchestrator must use stream")

        async def stream(self, request):
            self.calls += 1
            yield ProviderStreamEvent(type="started")
            yield ProviderStreamEvent(
                type="completed",
                response=ProviderResponse(
                    decision=ProviderDecision(
                        plan=[],
                        message="continue",
                        tool_calls=[],
                        outcome="continue",
                    ),
                    usage=ProviderUsage(requests=1, cost_usd=None),
                ),
            )

    provider = UnknownCostProvider()
    result = await AsterCodeOrchestrator(provider, _NoopGateway()).run(
        "do not continue with unknown cost",
        budget=RunBudget(max_cost_usd=1),
    )

    assert provider.calls == 0
    assert result["status"] == "blocked"
    assert "selected provider" in " ".join(result["blockers"])


@pytest.mark.asyncio
async def test_cost_cap_stops_after_capable_provider_returns_unknown_cost() -> None:
    class MisreportingProvider:
        name = "misreporting-cost-fake"
        is_live = False
        supports_cost_tracking = True

        def __init__(self) -> None:
            self.calls = 0

        async def complete(self, request):
            raise AssertionError("orchestrator must use stream")

        async def stream(self, request):
            self.calls += 1
            yield ProviderStreamEvent(type="started")
            yield ProviderStreamEvent(
                type="completed",
                response=ProviderResponse(
                    decision=ProviderDecision(
                        plan=[],
                        message="continue",
                        tool_calls=[],
                        outcome="continue",
                    ),
                    usage=ProviderUsage(requests=1, cost_usd=None),
                ),
            )

    provider = MisreportingProvider()
    result = await AsterCodeOrchestrator(provider, _NoopGateway()).run(
        "stop when reported cost is missing",
        budget=RunBudget(max_cost_usd=1),
    )

    assert provider.calls == 1
    assert result["status"] == "blocked"
    assert "provider cost is unknown" in " ".join(result["blockers"])


@pytest.mark.asyncio
async def test_tool_timeout_is_minimum_of_spec_argument_and_run_budget() -> None:
    class OneToolProvider:
        name = "one-tool-fake"
        is_live = False

        async def complete(self, request):
            raise AssertionError("orchestrator must use stream")

        async def stream(self, request):
            yield ProviderStreamEvent(type="started")
            yield ProviderStreamEvent(
                type="completed",
                response=ProviderResponse(
                    decision=ProviderDecision.model_validate(
                        {
                            "plan": ["run the bounded tool"],
                            "message": "run slow tool",
                            "outcome": "continue",
                            "tool_calls": [
                                {
                                    "tool": "test.slow",
                                    "arguments": {"timeout": 0.04},
                                    "host": "local",
                                    "cwd": None,
                                    "purpose": "budget test",
                                }
                            ],
                        }
                    ),
                    usage=ProviderUsage(requests=1, cost_usd=0.0),
                ),
            )

    class SlowGateway:
        def __init__(self) -> None:
            self.timeout: float | None = None

        async def authorize(self, call, context, decision=None):
            return GatewayAuthorization(outcome="allow", risk=RiskLevel.P0, reason="budget test")

        async def execute(self, call, context):
            self.timeout = context.execution_timeout_seconds
            await asyncio.sleep(10)

    gateway = SlowGateway()
    core = AsterCodeOrchestrator(
        OneToolProvider(),
        gateway,
        tools=[
            ToolSpec(
                name="test.slow",
                capability="test.slow",
                timeout=0.5,
                side_effects=["file_write"],
                input_schema={
                    "type": "object",
                    "properties": {"timeout": {"type": "number"}},
                    "required": ["timeout"],
                    "additionalProperties": False,
                },
            )
        ],
    )
    started = time.monotonic()
    result = await core.run(
        "bound a slow side-effectful tool",
        budget=RunBudget(max_elapsed_seconds=2),
    )

    assert time.monotonic() - started < 1
    assert gateway.timeout is not None and gateway.timeout <= 0.04
    assert result["tool_results"][0]["status"] == "unknown"
    assert result["tool_results"][0]["side_effects"] == ["possible_unconfirmed_side_effect"]
