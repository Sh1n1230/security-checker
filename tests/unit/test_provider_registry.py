"""Provider の組み立てと capability 解決 (設計書 §9.3, §19.1)."""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.config.schema import ReviewerConfig
from security_checker.errors import ConfigError
from security_checker.providers.base import StructuredMode
from security_checker.providers.presets.loader import HttpPreset, load_http_presets
from security_checker.providers.registry import (
    build_http_provider,
    build_provider,
    resolve_api_key,
    resolve_capabilities,
)


def reviewer(**overrides: Any) -> ReviewerConfig:
    payload: dict[str, Any] = {
        "name": "r1",
        "transport": "http",
        "dialect": "openai_chat",
        "base_url": "https://endpoint.test/v1",
        "model": "m",
    }
    payload.update(overrides)
    return ReviewerConfig(**payload)


def test_api_key_comes_from_env_only():
    config = reviewer(api_key_env="MY_KEY")
    assert resolve_api_key(config, {"MY_KEY": "value"}) == "value"


def test_missing_env_names_the_reviewer_and_variable():
    config = reviewer(api_key_env="MY_KEY")
    with pytest.raises(ConfigError) as excinfo:
        resolve_api_key(config, {})
    assert "r1" in str(excinfo.value)
    assert "MY_KEY" in str(excinfo.value)


def test_no_api_key_env_is_allowed():
    assert resolve_api_key(reviewer(), {}) is None


def test_capabilities_default_to_json_mode():
    """未知のエンドポイントでも「まず動く」既定にする (§9.3)."""
    capabilities = resolve_capabilities(reviewer(), None)
    assert capabilities.structured_output is StructuredMode.JSON_MODE


def test_preset_capabilities_are_applied():
    preset = HttpPreset(
        name="p",
        dialect="openai_chat",
        capabilities={"structured_output": "json_schema", "max_context_tokens": 32000},
    )
    capabilities = resolve_capabilities(reviewer(), preset)
    assert capabilities.structured_output is StructuredMode.JSON_SCHEMA
    assert capabilities.max_context_tokens == 32000


def test_user_overrides_beat_preset():
    preset = HttpPreset(
        name="p", dialect="openai_chat", capabilities={"structured_output": "json_schema"}
    )
    config = reviewer(capabilities={"structured_output": "prompt_only", "supports_seed": True})
    capabilities = resolve_capabilities(config, preset)
    assert capabilities.structured_output is StructuredMode.PROMPT_ONLY
    assert capabilities.supports_seed is True


def test_build_http_provider():
    provider = build_http_provider(reviewer(), environ={}, presets={})
    assert provider.transport == "http"
    assert provider.dialect == "openai_chat"
    assert provider.model == "m"


def test_unknown_dialect_is_config_error():
    config = reviewer(dialect="openai_chat").model_copy(update={"dialect": "unknown_dialect"})
    with pytest.raises(ConfigError, match="dialect"):
        build_http_provider(config, environ={}, presets={})


def test_preset_supplies_missing_fields():
    presets = {
        "internal": HttpPreset(
            name="internal", dialect="openai_chat", base_url="https://internal/v1"
        )
    }
    config = ReviewerConfig(name="r1", transport="http", preset="internal", model="m")
    provider = build_http_provider(config, environ={}, presets=presets)
    assert provider.base_url == "https://internal/v1"


def test_unknown_preset_lists_alternatives():
    config = ReviewerConfig(name="r1", transport="http", preset="missing", model="m")
    with pytest.raises(ConfigError, match="preset"):
        build_http_provider(config, environ={}, presets={})


def test_preset_matching_by_host_and_model():
    presets = {
        "matched": HttpPreset(
            name="matched",
            dialect="openai_chat",
            match={"host": "endpoint.test", "model": "^m$"},
            capabilities={"structured_output": "json_schema"},
        )
    }
    provider = build_http_provider(reviewer(), environ={}, presets=presets)
    assert provider.capabilities.structured_output is StructuredMode.JSON_SCHEMA


def test_bundled_presets_are_empty_but_loadable(tmp_path):
    """同梱プリセットは意図的に空。それでも設定直書きで動くことが前提 (§9.7)."""
    assert load_http_presets(tmp_path) == {}


def test_user_presets_are_loaded(tmp_path):
    (tmp_path / "mine.yml").write_text(
        "dialect: openai_chat\nbase_url: https://mine/v1\n", encoding="utf-8"
    )
    presets = load_http_presets(tmp_path)
    assert presets["mine"].base_url == "https://mine/v1"
    assert presets["mine"].source == "user"


def test_broken_user_preset_is_config_error(tmp_path):
    (tmp_path / "bad.yml").write_text("dialect: [不正]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_http_presets(tmp_path)


def test_unknown_transport_lists_what_is_available():
    config = ReviewerConfig(
        name="r1", transport="http", dialect="openai_chat", base_url="https://x/v1", model="m"
    )
    unknown = config.model_copy(update={"transport": "carrier-pigeon"})
    with pytest.raises(ConfigError, match="http, process"):
        build_provider(unknown, environ={})
