from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from astercode.config import AppConfig, ModelConfig, load_config
from astercode.provider import (
    DeepSeekChatProvider,
    DeterministicFakeProvider,
    OpenAIAgentsProvider,
    ProviderConfigurationError,
)
from astercode.runtime import _provider_from_config

_MODEL_ID = "deepseek-v4-flash"
_FAKE_DEEPSEEK_KEY = "sk-" + "D" * 32
_FAKE_OPENAI_KEY = "sk-" + "O" * 32


def _with_model(app_config: AppConfig, model: ModelConfig) -> AppConfig:
    return app_config.model_copy(update={"model": model}, deep=True)


@pytest.mark.parametrize(
    "alias",
    ["deepseek", "deepseek_chat", "deepseek_openai", "deepseek_openai_chat"],
)
def test_deepseek_model_aliases_receive_provider_specific_defaults(alias: str) -> None:
    model = ModelConfig.model_validate({"provider": alias})

    assert model.provider == "deepseek"
    assert model.api_key_env == "DEEPSEEK_API_KEY"
    assert model.base_url == DeepSeekChatProvider.OFFICIAL_BASE_URL


def test_environment_overlay_selects_deepseek_without_copying_secret_value(
    tmp_path: Path,
) -> None:
    config = load_config(
        project_root=tmp_path,
        environ={
            "ASTERCODE_MODEL_PROVIDER": "deepseek_openai_chat",
            "DEEPSEEK_MODEL": _MODEL_ID,
            "DEEPSEEK_API_KEY": _FAKE_DEEPSEEK_KEY,
        },
    )

    assert config.model.provider == "deepseek"
    assert config.model.model_id == _MODEL_ID
    assert config.model.api_key_env == "DEEPSEEK_API_KEY"
    assert config.model.base_url == DeepSeekChatProvider.OFFICIAL_BASE_URL
    assert _FAKE_DEEPSEEK_KEY not in config.model.model_dump_json()


def test_deepseek_environment_uses_provider_from_file_when_no_provider_override(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[model]\nprovider = "deepseek"\n',
        encoding="utf-8",
    )

    config = load_config(
        config_path,
        project_root=tmp_path,
        environ={"DEEPSEEK_MODEL": "deepseek-v4-pro"},
    )

    assert config.model.provider == "deepseek"
    assert config.model.model_id == "deepseek-v4-pro"
    assert config.model.api_key_env == "DEEPSEEK_API_KEY"


def test_runtime_routes_each_explicit_provider(
    app_config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", _FAKE_DEEPSEEK_KEY)
    monkeypatch.setenv("OPENAI_API_KEY", _FAKE_OPENAI_KEY)

    deepseek = _provider_from_config(
        _with_model(
            app_config,
            ModelConfig(provider="deepseek", model_id=_MODEL_ID),
        )
    )
    openai_provider = _provider_from_config(
        _with_model(
            app_config,
            ModelConfig(provider="openai", model_id="openai-offline-test-model"),
        )
    )
    fake = _provider_from_config(
        _with_model(
            app_config,
            ModelConfig(provider="fake", model_id="must-not-activate-a-live-provider"),
        )
    )

    assert isinstance(deepseek, DeepSeekChatProvider)
    assert deepseek.name == "deepseek-openai-chat"
    assert isinstance(openai_provider, OpenAIAgentsProvider)
    assert isinstance(fake, DeterministicFakeProvider)


def test_deepseek_route_does_not_fall_back_to_openai_key(
    app_config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", _FAKE_OPENAI_KEY)
    provider = _provider_from_config(
        _with_model(
            app_config,
            ModelConfig(provider="deepseek", model_id=_MODEL_ID),
        )
    )

    assert isinstance(provider, DeepSeekChatProvider)
    with pytest.raises(ProviderConfigurationError, match="DEEPSEEK_API_KEY"):
        provider._resolve_configuration()


def test_unknown_provider_is_rejected_before_runtime_routing() -> None:
    with pytest.raises(ValidationError, match="unsupported model provider"):
        ModelConfig.model_validate({"provider": "repository-controlled-endpoint"})


@pytest.mark.parametrize(
    "model_id",
    ["deepseek-chat", "gpt-4o", "flash", "deepseek-v4-flash[1m]", "deepseek-v4-flash[1M]"],
)
def test_deepseek_rejects_non_chat_model_ids_before_network(model_id: str) -> None:
    with pytest.raises(ValidationError, match="DeepSeek model_id"):
        ModelConfig.model_validate({"provider": "deepseek", "model_id": model_id})

    with pytest.raises(ProviderConfigurationError, match="DeepSeek Chat model_id"):
        DeepSeekChatProvider(model_id=model_id, instructions="No network should be attempted.")


@pytest.mark.parametrize("reasoning", ["minimal", "medium"])
def test_deepseek_rejects_unsupported_reasoning_levels(reasoning: str) -> None:
    with pytest.raises(ValidationError, match="DeepSeek reasoning"):
        ModelConfig.model_validate({"provider": "deepseek", "reasoning": reasoning})

    with pytest.raises(ProviderConfigurationError, match="reasoning_effort"):
        DeepSeekChatProvider(
            model_id=_MODEL_ID,
            instructions="No network should be attempted.",
            reasoning_effort=reasoning,
        )
