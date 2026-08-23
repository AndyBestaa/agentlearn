from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from astercode.provider import (
    ProviderDecision,
    ProviderRequest,
    ProviderResponse,
    ProviderStreamEvent,
    ProviderUsage,
)
from astercode.runtime import Orchestrator, build_registry


class WaitingProvider:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    @property
    def name(self) -> str:
        return "waiting-test-provider"

    @property
    def is_live(self) -> bool:
        return False

    async def complete(self, request: ProviderRequest) -> ProviderResponse:
        del request
        raise AssertionError("runtime must consume stream()")

    async def stream(
        self,
        request: ProviderRequest,
    ) -> AsyncIterator[ProviderStreamEvent]:
        del request
        yield ProviderStreamEvent(type="started")
        self.started.set()
        await self.release.wait()
        yield ProviderStreamEvent(
            type="completed",
            response=ProviderResponse(
                decision=ProviderDecision(
                    plan=[],
                    message="waiting provider completed",
                    tool_calls=[],
                    outcome="completed",
                ),
                usage=ProviderUsage(cost_usd=0.0),
            ),
        )


@pytest.mark.asyncio
async def test_session_is_running_while_provider_is_in_flight(
    app_config,
    storage,
) -> None:
    provider = WaitingProvider()
    runtime = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    task = asyncio.create_task(runtime.run("wait for a provider response"))
    try:
        await asyncio.wait_for(provider.started.wait(), timeout=5)
        session = storage.list_sessions(limit=1)[0]

        assert session["status"] == "running"
        persisted = storage.get_session(session["session_id"])
        assert persisted["state"]["goal"] == "wait for a provider response"
        assert persisted["state"]["status"] == "running"

        provider.release.set()
        result = await asyncio.wait_for(task, timeout=5)
        assert result["status"] == "partial"
    finally:
        provider.release.set()
        if not task.done():
            try:
                await asyncio.wait_for(task, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        await runtime.close()
