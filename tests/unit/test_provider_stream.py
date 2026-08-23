from __future__ import annotations

from types import SimpleNamespace

import agents
import agents.models.openai_responses as responses_model
import openai
import pytest

from astercode.provider import OpenAIAgentsProvider, ProviderRequest


@pytest.mark.asyncio
async def test_live_provider_stream_adapter_uses_sdk_stream_without_network(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    class FakeRun:
        def __init__(self) -> None:
            self.final_output = {
                "plan": [],
                "message": "offline streamed decision",
                "tool_calls": [],
                "outcome": "completed",
            }
            self.context_wrapper = SimpleNamespace(
                usage=SimpleNamespace(requests=1, input_tokens=4, output_tokens=3, total_tokens=7)
            )
            self.last_response_id = "resp_offline_fixture"
            self.released = False
            self.cancelled = False

        async def stream_events(self):
            yield SimpleNamespace(
                type="raw_response_event",
                data=SimpleNamespace(type="response.output_text.delta", delta='{"plan":'),
            )
            yield SimpleNamespace(type="run_item_stream_event", name="message_output_created")

        def release_agents(self) -> None:
            self.released = True

        def cancel(self) -> None:
            self.cancelled = True

    run = FakeRun()
    monkeypatch.setattr(openai, "AsyncOpenAI", FakeClient)
    monkeypatch.setattr(responses_model, "OpenAIResponsesModel", lambda **kwargs: object())
    monkeypatch.setattr(agents, "Agent", lambda **kwargs: object())
    monkeypatch.setattr(agents, "ModelSettings", lambda **kwargs: kwargs)
    monkeypatch.setattr(agents, "RunConfig", lambda **kwargs: kwargs)
    monkeypatch.setattr(agents.Runner, "run_streamed", lambda *args, **kwargs: run)
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-placeholder-not-a-real-secret")

    provider = OpenAIAgentsProvider(model_id="test-model", instructions="test instructions")
    request = ProviderRequest(
        session_id="session-test",
        turn_id="turn-test",
        phase="PLAN",
        goal="stream without network",
        context={},
        available_tools=[],
    )

    events = [event async for event in provider.stream(request)]

    assert [event.type for event in events] == ["started", "delta", "completed"]
    assert events[1].delta == '{"plan":'
    assert events[-1].response is not None
    assert events[-1].response.response_id == "resp_offline_fixture"
    assert events[-1].response.usage.total_tokens == 7
    assert run.released is True
