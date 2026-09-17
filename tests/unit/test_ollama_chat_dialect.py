"""ollama_chat 方言のリクエスト/レスポンス変換 (設計書 §9.4).

この方言が別に存在する理由は num_ctx を制御できることなので、
「常に明示して送る」ことを最初のテストで縛る。
"""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.base import DialectOptions
from security_checker.providers.http.dialects.ollama_chat import (
    DEFAULT_NUM_CTX,
    OllamaChatDialect,
)

SCHEMA = {"type": "object", "properties": {"vulnerable": {"type": "boolean"}}}


@pytest.fixture
def dialect() -> OllamaChatDialect:
    return OllamaChatDialect()


def make_request(**overrides: Any) -> CompletionRequest:
    payload: dict[str, Any] = {
        "system": "system-text",
        "user": "user-text",
        "json_schema": SCHEMA,
        "max_output_tokens": 500,
    }
    payload.update(overrides)
    return CompletionRequest(**payload)


def test_num_ctx_is_always_sent(dialect: OllamaChatDialect) -> None:
    """既定の文脈長のままだと黙って切り詰められる. 必ず明示する (§9.4)."""
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    assert payload["options"]["num_ctx"] == DEFAULT_NUM_CTX
    assert payload["stream"] is False


def test_num_ctx_and_keep_alive_come_from_the_config() -> None:
    dialect = OllamaChatDialect(DialectOptions(num_ctx=16384, keep_alive="10m"))
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_MODE
    )
    assert payload["options"]["num_ctx"] == 16384
    assert payload["keep_alive"] == "10m"


def test_keep_alive_is_omitted_when_unset(dialect: OllamaChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_MODE
    )
    assert "keep_alive" not in payload


def test_endpoint_and_headers(dialect: OllamaChatDialect) -> None:
    assert dialect.endpoint("http://localhost:11434/") == "http://localhost:11434/api/chat"
    # ローカル前提だが、認証付きプロキシの背後でも使えるようにする
    assert dialect.headers("k")["Authorization"] == "Bearer k"
    assert "Authorization" not in dialect.headers(None)


def test_json_schema_mode_sends_the_schema_as_format(dialect: OllamaChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    assert payload["format"] == SCHEMA


def test_json_mode_sends_format_json(dialect: OllamaChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_MODE
    )
    assert payload["format"] == "json"


def test_prompt_only_sends_no_format(dialect: OllamaChatDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.PROMPT_ONLY
    )
    assert "format" not in payload


def test_capability_flags_are_respected(dialect: OllamaChatDialect) -> None:
    capabilities = Capabilities(
        supports_system_role=False, supports_temperature=False, supports_seed=True
    )
    payload = dialect.build_payload(
        make_request(seed=42),
        model="m",
        capabilities=capabilities,
        mode=StructuredMode.JSON_MODE,
    )
    assert len(payload["messages"]) == 1
    assert "system-text" in payload["messages"][0]["content"]
    assert "temperature" not in payload["options"]
    assert payload["options"]["seed"] == 42


def test_parse_response(dialect: OllamaChatDialect) -> None:
    parsed = dialect.parse_response(
        {
            "model": "m",
            "message": {"role": "assistant", "content": '{"vulnerable": true}'},
            "done_reason": "stop",
            "prompt_eval_count": 120,
            "eval_count": 30,
        }
    )
    assert parsed.text == '{"vulnerable": true}'
    assert parsed.usage.input_tokens == 120
    assert parsed.usage.output_tokens == 30
    assert parsed.model_reported == "m"


def test_parse_response_without_message_is_an_error(dialect: OllamaChatDialect) -> None:
    with pytest.raises(ProviderResponseError):
        dialect.parse_response({"done": True})


def test_missing_model_error_says_what_to_do(dialect: OllamaChatDialect) -> None:
    """「次の行動」を書く (§20.2). 未取得モデルは最も多い詰まりどころ."""
    hint = dialect.explain_error(404, '{"error":"model \'x\' not found, try pulling it first"}')
    assert hint is not None
    assert "pull" in hint

    assert dialect.explain_error(400, "something else") is None
