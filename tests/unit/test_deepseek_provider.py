from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from typing import Any

import httpx2
import openai
import pytest

from astercode.provider import (
    DeepSeekChatProvider,
    ProviderConfigurationError,
    ProviderExecutionError,
    ProviderRequest,
)

_MODEL_ID = "deepseek-v4-flash"
_FAKE_KEY = "sk-" + "T" * 32
_USAGE = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


def _request() -> ProviderRequest:
    return ProviderRequest(
        session_id="session-deepseek-test",
        turn_id="turn-deepseek-test",
        phase="PLAN",
        goal="inspect the workspace without network access",
        context={"evidence": ["offline fixture"]},
        available_tools=[],
    )


def _decision_text() -> str:
    return json.dumps(
        {
            "plan": ["inspect README"],
            "message": "proposal ready",
            "tool_calls": [
                {
                    "tool": "fs.read",
                    "arguments_json": json.dumps({"path": "README.md"}),
                    "host": "local",
                    "cwd": None,
                    "purpose": "inspect project documentation",
                }
            ],
            "outcome": "continue",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _completion_payload(
    *,
    content: str,
    finish_reason: str = "stop",
    usage: dict[str, int] | None = _USAGE,
) -> dict[str, Any]:
    return {
        "id": "chatcmpl-deepseek-offline",
        "object": "chat.completion",
        "created": 1,
        "model": _MODEL_ID,
        "choices": [
            {
                "index": 0,
                "finish_reason": finish_reason,
                "message": {
                    "role": "assistant",
                    "content": content,
                    "reasoning_content": "server-side hidden reasoning",
                },
            }
        ],
        "usage": usage,
    }


MockHandler = Callable[[httpx2.Request], httpx2.Response] | Callable[[httpx2.Request], Coroutine[None, None, httpx2.Response]]


def _install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: MockHandler,
) -> list[httpx2.AsyncClient]:
    """Keep the real SDK while replacing only its network transport."""

    clients: list[httpx2.AsyncClient] = []

    def build_http_client(**kwargs: Any) -> httpx2.AsyncClient:
        assert kwargs == {"trust_env": False}
        http_client = httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            trust_env=False,
        )
        clients.append(http_client)
        return http_client

    monkeypatch.setattr(openai, "DefaultAsyncHttpxClient", build_http_client)
    return clients


@pytest.mark.asyncio
async def test_complete_uses_chat_completions_bearer_json_thinking_and_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    async def handler(request: httpx2.Request) -> httpx2.Response:
        observed.update(
            url=str(request.url),
            authorization=request.headers.get("authorization"),
            body=json.loads(request.content),
            raw_body=request.content.decode("utf-8"),
        )
        return httpx2.Response(
            200,
            json=_completion_payload(content=_decision_text()),
            headers={"content-type": "application/json"},
        )

    clients = _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Follow the local policy boundary.",
        reasoning_effort="max",
        max_output_tokens=1_024,
        max_retries=0,
    )

    response = await provider.complete(_request())

    assert observed["url"] == "https://api.deepseek.com/chat/completions"
    assert observed["authorization"] == f"Bearer {_FAKE_KEY}"
    assert _FAKE_KEY not in observed["raw_body"]
    body = observed["body"]
    assert body["model"] == _MODEL_ID
    assert body["stream"] is False
    assert body["response_format"] == {"type": "json_object"}
    assert body["thinking"] == {"type": "enabled"}
    assert body["reasoning_effort"] == "max"
    assert body["max_tokens"] == 1_024
    assert "ASTERCode INTERNAL PROVIDER OUTPUT CONTRACT" in body["messages"][0]["content"]
    assert json.loads(body["messages"][1]["content"])["goal"] == _request().goal

    assert response.response_id == "chatcmpl-deepseek-offline"
    assert response.usage.model_dump() == {
        "requests": 1,
        "input_tokens": 11,
        "output_tokens": 7,
        "total_tokens": 18,
        "cost_usd": None,
    }
    assert response.decision.tool_calls[0].arguments == {"path": "README.md"}
    assert "server-side hidden reasoning" not in response.model_dump_json()
    assert clients and all(client.is_closed for client in clients)


def test_request_arguments_narrow_max_tokens_to_host_budget() -> None:
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="safe prompt",
        max_output_tokens=1_024,
    )
    request = _request().model_copy(update={"max_output_tokens": 7})

    body = provider._request_arguments(
        request,
        model_id=_MODEL_ID,
        instructions="safe prompt",
        stream=False,
    )

    assert body["max_tokens"] == 7


def _stream_chunk(
    *,
    delta: dict[str, Any] | None = None,
    finish_reason: str | None = None,
    choices: list[dict[str, Any]] | None = None,
    usage: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "id": "chatcmpl-deepseek-stream",
        "object": "chat.completion.chunk",
        "created": 2,
        "model": _MODEL_ID,
        "choices": (
            choices
            if choices is not None
            else [
                {
                    "index": 0,
                    "delta": delta or {},
                    "finish_reason": finish_reason,
                }
            ]
        ),
        "usage": usage,
    }


def _sse(events: list[dict[str, Any]]) -> bytes:
    records = [f"data: {json.dumps(event, ensure_ascii=False)}\n\n" for event in events]
    records.append("data: [DONE]\n\n")
    return "".join(records).encode("utf-8")


@pytest.mark.asyncio
async def test_stream_reassembles_content_ignores_reasoning_and_accepts_usage_only_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _decision_text()
    split_at = len(decision) // 2
    observed_body: dict[str, Any] = {}
    events = [
        _stream_chunk(
            delta={
                "role": "assistant",
                "content": None,
                "reasoning_content": "private chain of thought must not be emitted",
            }
        ),
        _stream_chunk(delta={"content": decision[:split_at]}),
        _stream_chunk(delta={"content": decision[split_at:]}),
        _stream_chunk(delta={}, finish_reason="stop"),
        _stream_chunk(choices=[], usage=_USAGE),
    ]

    async def handler(request: httpx2.Request) -> httpx2.Response:
        observed_body.update(json.loads(request.content))
        return httpx2.Response(
            200,
            content=_sse(events),
            headers={"content-type": "text/event-stream"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Offline streaming test.",
        reasoning_effort="none",
        max_retries=0,
    )

    provider_events = [event async for event in provider.stream(_request())]

    assert observed_body["stream"] is True
    assert observed_body["stream_options"] == {"include_usage": True}
    assert observed_body["thinking"] == {"type": "disabled"}
    assert [event.type for event in provider_events] == [
        "started",
        "delta",
        "completed",
    ]
    assert "".join(event.delta or "" for event in provider_events) == decision
    serialized_events = json.dumps(
        [event.model_dump(mode="json") for event in provider_events],
        ensure_ascii=False,
    )
    assert "private chain of thought" not in serialized_events
    completed = provider_events[-1].response
    assert completed is not None
    assert completed.response_id == "chatcmpl-deepseek-stream"
    assert completed.usage.total_tokens == 18
    assert completed.decision.message == "proposal ready"


@pytest.mark.asyncio
async def test_stream_coalesces_thousands_of_wire_parts_into_bounded_verified_deltas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = json.dumps(
        {
            "plan": ["inspect README"],
            "message": "x" * 20_000,
            "tool_calls": [],
            "outcome": "completed",
        },
        separators=(",", ":"),
    )
    wire_part_chars = 5
    wire_parts = [decision[start : start + wire_part_chars] for start in range(0, len(decision), wire_part_chars)]
    assert len(wire_parts) > 1_000
    events = [
        *(_stream_chunk(delta={"content": part}) for part in wire_parts),
        _stream_chunk(delta={}, finish_reason="stop"),
        _stream_chunk(choices=[], usage=_USAGE),
    ]

    async def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200,
            content=_sse(events),
            headers={"content-type": "text/event-stream"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Coalesce only after validating the complete response.",
        max_retries=0,
    )

    provider_events = [event async for event in provider.stream(_request())]

    delta_events = [event for event in provider_events if event.type == "delta"]
    expected_delta_count = (len(decision) + provider.VERIFIED_STREAM_DELTA_CHARS - 1) // provider.VERIFIED_STREAM_DELTA_CHARS
    assert len(delta_events) == expected_delta_count
    assert len(delta_events) < len(wire_parts) // 1_000
    assert all(event.delta is not None and len(event.delta) <= provider.VERIFIED_STREAM_DELTA_CHARS for event in delta_events)
    assert "".join(event.delta or "" for event in delta_events) == decision
    assert provider_events[0].type == "started"
    assert provider_events[-1].type == "completed"


def test_low_reasoning_effort_is_preserved() -> None:
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Offline body test.",
        reasoning_effort="low",
    )

    assert provider._thinking_body() == {
        "thinking": {"type": "enabled"},
        "reasoning_effort": "low",
    }


@pytest.mark.parametrize(
    ("content", "finish_reason", "usage", "message"),
    [
        ("not-json", "stop", _USAGE, "invalid JSON"),
        (_decision_text(), "length", _USAGE, "did not finish"),
        (_decision_text(), "stop", None, "omitted required token usage"),
        (_decision_text(), "stop", {}, "invalid prompt_tokens"),
        (
            _decision_text(),
            "stop",
            {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 1},
            "inconsistent total token usage",
        ),
    ],
)
@pytest.mark.asyncio
async def test_complete_rejects_invalid_json_finish_or_usage(
    monkeypatch: pytest.MonkeyPatch,
    content: str,
    finish_reason: str,
    usage: dict[str, int] | None,
    message: str,
) -> None:
    async def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200,
            json=_completion_payload(
                content=content,
                finish_reason=finish_reason,
                usage=usage,
            ),
            headers={"content-type": "application/json"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Reject malformed responses.",
        max_retries=0,
    )

    with pytest.raises(ProviderExecutionError, match=message):
        await provider.complete(_request())


@pytest.mark.asyncio
async def test_authentication_error_does_not_expose_key(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers.get("authorization") == f"Bearer {_FAKE_KEY}"
        return httpx2.Response(
            401,
            json={
                "error": {
                    "message": f"rejected credential {_FAKE_KEY}",
                    "type": "authentication_error",
                    "code": "invalid_api_key",
                }
            },
            headers={"content-type": "application/json"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Never expose credentials.",
        max_retries=0,
    )

    with pytest.raises(ProviderExecutionError) as raised:
        await provider.complete(_request())

    captured = capsys.readouterr()
    visible = "\n".join((str(raised.value), repr(raised.value), caplog.text, captured.out, captured.err))
    assert _FAKE_KEY not in visible
    assert "AuthenticationError" in str(raised.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.deepseek.com",
        "https://api.deepseek.com/anthropic",
        "https://api.deepseek.com.evil.test",
        "https://user:password@api.deepseek.com",
        "https://api.deepseek.com:444",
        "https://api.deepseek.com?redirect=evil",
        "https://api.deepseek.com#fragment",
        "https://api.deepseek.com:not-a-port",
    ],
)
def test_base_url_rejects_non_official_chat_origins(base_url: str) -> None:
    with pytest.raises(ProviderConfigurationError):
        DeepSeekChatProvider(
            model_id=_MODEL_ID,
            base_url=base_url,
            instructions="Must fail before client construction.",
        )


@pytest.mark.asyncio
async def test_stream_rejects_a_second_choice_after_terminal_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        _stream_chunk(delta={"content": _decision_text()}, finish_reason="length"),
        _stream_chunk(delta={}, finish_reason="stop"),
        _stream_chunk(choices=[], usage=_USAGE),
    ]

    async def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200,
            content=_sse(events),
            headers={"content-type": "text/event-stream"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Reject malformed terminal state.",
        max_retries=0,
    )

    with pytest.raises(ProviderExecutionError, match="after its terminal choice"):
        _ = [event async for event in provider.stream(_request())]


@pytest.mark.asyncio
async def test_stream_rejects_inconsistent_usage_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        _stream_chunk(choices=[], usage=_USAGE),
        _stream_chunk(delta={"content": _decision_text()}),
        _stream_chunk(delta={}, finish_reason="stop"),
        _stream_chunk(
            choices=[],
            usage={"prompt_tokens": 11, "completion_tokens": 8, "total_tokens": 19},
        ),
    ]

    async def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200,
            content=_sse(events),
            headers={"content-type": "text/event-stream"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Reject inconsistent usage.",
        max_retries=0,
    )

    with pytest.raises(ProviderExecutionError, match="inconsistent token usage blocks"):
        _ = [event async for event in provider.stream(_request())]


@pytest.mark.asyncio
async def test_stream_buffers_until_cross_chunk_secret_check_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sk-" + "S" * 32
    decision = json.dumps(
        {
            "plan": [],
            "message": secret,
            "tool_calls": [],
            "outcome": "blocked",
        },
        separators=(",", ":"),
    )
    split_at = decision.index(secret) + 3
    events = [
        _stream_chunk(delta={"content": decision[:split_at]}),
        _stream_chunk(delta={"content": decision[split_at:]}),
        _stream_chunk(delta={}, finish_reason="stop"),
        _stream_chunk(choices=[], usage=_USAGE),
    ]

    async def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200,
            content=_sse(events),
            headers={"content-type": "text/event-stream"},
        )

    _install_mock_transport(monkeypatch, handler)
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_KEY)
    provider = DeepSeekChatProvider(
        model_id=_MODEL_ID,
        instructions="Never emit credentials.",
        max_retries=0,
    )
    visible_events = []

    with pytest.raises(ProviderExecutionError, match="secret-looking material"):
        async for event in provider.stream(_request()):
            visible_events.append(event)

    assert [event.type for event in visible_events] == ["started"]
    assert secret not in json.dumps([event.model_dump(mode="json") for event in visible_events])
