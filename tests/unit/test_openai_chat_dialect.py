"""openai_chat 方言のリクエスト/レスポンス変換 (設計書 §9.3)."""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect

SCHEMA = {"type": "object", "properties": {"vulnerable": {"type": "boolean"}}}


@pytest.fixture
def dialect() -> OpenAIChatDialect:
    return OpenAIChatDialect()


def make_request(**overrides: Any) -> CompletionRequest:
    payload: dict[str, Any] = {
        "system": "system-text",
        "user": "user-text",
        "json_schema": SCHEMA,
        "max_output_tokens": 500,
    }
    payload.update(overrides)
    return CompletionRequest(**payload)


def test_endpoint_and_headers(dialect: OpenAIChatDialect) -> None:
    assert dialect.endpoint("https://x/v1/") == "https://x/v1/chat/completions"
    assert dialect.headers("k")["Authorization"] == "Bearer k"
    assert "Authorization" not in dialect.headers(None)


def test_json_schema_mode_sends_schema(dialect: OpenAIChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["schema"] == SCHEMA
    assert payload["max_tokens"] == 500
    assert payload["temperature"] == 0.0


def test_json_mode_sends_json_object(dialect: OpenAIChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_MODE
    )
    assert payload["response_format"] == {"type": "json_object"}


def test_prompt_only_mode_sends_no_response_format(dialect: OpenAIChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.PROMPT_ONLY
    )
    assert "response_format" not in payload


def test_capability_flags_are_respected(dialect: OpenAIChatDialect) -> None:
    capabilities = Capabilities(
        supports_system_role=False, supports_temperature=False, supports_seed=True
    )
    payload = dialect.build_payload(
        make_request(seed=42),
        model="m",
        capabilities=capabilities,
        mode=StructuredMode.JSON_MODE,
    )
    assert len(payload["messages"]) == 1  # system を user に畳む
    assert "system-text" in payload["messages"][0]["content"]
    assert "temperature" not in payload
    assert payload["seed"] == 42


def test_parse_response(dialect: OpenAIChatDialect) -> None:
    parsed = dialect.parse_response(
        {
            "model": "server-model",
            "choices": [{"message": {"content": '{"vulnerable": true}'}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "completion_tokens_details": {"reasoning_tokens": 5},
                "prompt_tokens_details": {"cached_tokens": 10},
            },
        }
    )
    assert parsed.text == '{"vulnerable": true}'
    assert parsed.usage.input_tokens == 100
    assert parsed.usage.reasoning_tokens == 5
    assert parsed.usage.cached_tokens == 10
    assert parsed.model_reported == "server-model"


def test_parse_response_with_content_parts(dialect: OpenAIChatDialect) -> None:
    parsed = dialect.parse_response(
        {"choices": [{"message": {"content": [{"type": "text", "text": "a"}, {"text": "b"}]}}]}
    )
    assert parsed.text == "ab"


def test_parse_response_tolerates_missing_usage(dialect: OpenAIChatDialect) -> None:
    parsed = dialect.parse_response({"choices": [{"message": {"content": "x"}}]})
    assert parsed.usage.input_tokens == 0
    assert parsed.finish_reason == "stop"


@pytest.mark.parametrize(
    "payload",
    [{}, {"choices": []}, {"choices": ["x"]}, {"choices": [{"message": {"content": 42}}]}],
)
def test_broken_responses_raise(dialect: OpenAIChatDialect, payload: dict[str, Any]) -> None:
    with pytest.raises(ProviderResponseError):
        dialect.parse_response(payload)
