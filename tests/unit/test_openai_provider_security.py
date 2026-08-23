from __future__ import annotations

from typing import Any, cast

import openai
import pytest

from astercode.provider import DeepSeekChatProvider, OpenAIAgentsProvider

_UNTRUSTED_BASE_URL = "https://attacker.invalid/v1"
_UNTRUSTED_PROXY = "http://proxy.attacker.invalid:8080"


def _set_untrusted_network_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", _UNTRUSTED_BASE_URL)
    monkeypatch.setenv("HTTP_PROXY", _UNTRUSTED_PROXY)
    monkeypatch.setenv("HTTPS_PROXY", _UNTRUSTED_PROXY)
    monkeypatch.setenv("ALL_PROXY", _UNTRUSTED_PROXY)


def test_openai_client_builder_pins_endpoint_and_disables_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_untrusted_network_environment(monkeypatch)
    captured_http_kwargs: dict[str, Any] = {}
    captured_client_kwargs: dict[str, Any] = {}

    class FakeHttpClient:
        pass

    class FakeAsyncOpenAI:
        def __init__(self, **kwargs: Any) -> None:
            captured_client_kwargs.update(kwargs)

    def build_http_client(**kwargs: Any) -> FakeHttpClient:
        captured_http_kwargs.update(kwargs)
        return FakeHttpClient()

    monkeypatch.setattr(openai, "DefaultAsyncHttpxClient", build_http_client)
    monkeypatch.setattr(openai, "AsyncOpenAI", FakeAsyncOpenAI)

    client = OpenAIAgentsProvider._build_sdk_client(
        api_key="test-only-placeholder",
        timeout_seconds=17.0,
    )

    assert isinstance(client, FakeAsyncOpenAI)
    assert captured_http_kwargs == {"trust_env": False}
    assert captured_client_kwargs["base_url"] == "https://api.openai.com/v1"
    assert captured_client_kwargs["timeout"] == 17.0
    assert captured_client_kwargs["http_client"].__class__ is FakeHttpClient
    assert _UNTRUSTED_BASE_URL not in map(str, captured_client_kwargs.values())
    assert _UNTRUSTED_PROXY not in map(str, captured_client_kwargs.values())


@pytest.mark.asyncio
async def test_installed_openai_client_construction_ignores_network_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the pinned SDK version's real constructors without making a request."""

    _set_untrusted_network_environment(monkeypatch)
    client = OpenAIAgentsProvider._build_sdk_client(
        api_key="test-only-placeholder",
        timeout_seconds=1.0,
    )
    try:
        assert str(client.base_url) == "https://api.openai.com/v1/"
        assert cast(Any, client)._client._trust_env is False
    finally:
        await client.close()


def test_openai_provider_has_no_configurable_base_url() -> None:
    with pytest.raises(TypeError, match="base_url"):
        OpenAIAgentsProvider(
            model_id="offline-test-model",
            instructions="offline test",
            base_url=_UNTRUSTED_BASE_URL,  # type: ignore[call-arg]
        )


def test_deepseek_client_builder_pins_endpoint_and_disables_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_untrusted_network_environment(monkeypatch)
    captured_http_kwargs: dict[str, Any] = {}
    captured_client_kwargs: dict[str, Any] = {}

    class FakeHttpClient:
        pass

    class FakeAsyncOpenAI:
        def __init__(self, **kwargs: Any) -> None:
            captured_client_kwargs.update(kwargs)

    def build_http_client(**kwargs: Any) -> FakeHttpClient:
        captured_http_kwargs.update(kwargs)
        return FakeHttpClient()

    monkeypatch.setattr(openai, "DefaultAsyncHttpxClient", build_http_client)
    monkeypatch.setattr(openai, "AsyncOpenAI", FakeAsyncOpenAI)

    client = DeepSeekChatProvider._build_sdk_client(
        api_key="test-only-placeholder",
        base_url=DeepSeekChatProvider.OFFICIAL_BASE_URL,
        timeout_seconds=19.0,
        max_retries=0,
    )

    assert isinstance(client, FakeAsyncOpenAI)
    assert captured_http_kwargs == {"trust_env": False}
    assert captured_client_kwargs["base_url"] == "https://api.deepseek.com"
    assert captured_client_kwargs["timeout"] == 19.0
    assert captured_client_kwargs["max_retries"] == 0
    assert _UNTRUSTED_BASE_URL not in map(str, captured_client_kwargs.values())
    assert _UNTRUSTED_PROXY not in map(str, captured_client_kwargs.values())
