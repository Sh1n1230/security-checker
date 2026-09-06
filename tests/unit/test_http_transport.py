"""http transport のエラー正規化と降格 (設計書 §9.2, §10.2)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderBadRequestError,
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderServerError,
    ProviderTimeoutError,
)
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect
from security_checker.providers.http.transport import HttpProvider

BASE_URL = "http://endpoint.test/v1"
URL = f"{BASE_URL}/chat/completions"
SCHEMA = {"type": "object", "properties": {"vulnerable": {"type": "boolean"}}}


def make_provider(**overrides: Any) -> HttpProvider:
    settings: dict[str, Any] = {
        "name": "r1",
        "dialect": OpenAIChatDialect(),
        "base_url": BASE_URL,
        "model": "m",
        "capabilities": Capabilities(structured_output=StructuredMode.JSON_SCHEMA),
        "api_key": "secret-key",
        "client": httpx.AsyncClient(),
    }
    settings.update(overrides)
    return HttpProvider(**settings)


def request() -> CompletionRequest:
    return CompletionRequest(system="s", user="u", json_schema=SCHEMA, timeout_s=5.0)


def ok_body(content: str = '{"vulnerable": false}') -> dict[str, Any]:
    return {
        "model": "m",
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3},
    }


@respx.mock
async def test_successful_completion():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ok_body()))
    provider = make_provider()
    response = await provider.complete(request())

    assert response.text == '{"vulnerable": false}'
    assert response.usage.input_tokens == 10
    assert response.latency_ms >= 0
    assert route.calls[0].request.headers["Authorization"] == "Bearer secret-key"
    await provider.aclose()


@respx.mock
async def test_extra_headers_are_sent():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ok_body()))
    provider = make_provider(extra_headers={"X-Custom": "v"})
    await provider.complete(request())
    assert route.calls[0].request.headers["X-Custom"] == "v"
    await provider.aclose()


@respx.mock
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, ProviderAuthError),
        (403, ProviderAuthError),
        (429, ProviderRateLimitError),
        (500, ProviderServerError),
        (503, ProviderServerError),
    ],
)
async def test_error_normalization(status, expected):
    respx.post(URL).mock(return_value=httpx.Response(status, text="boom"))
    provider = make_provider()
    with pytest.raises(expected):
        await provider.complete(request())
    await provider.aclose()


@respx.mock
async def test_rate_limit_carries_retry_after():
    respx.post(URL).mock(
        return_value=httpx.Response(429, text="slow down", headers={"Retry-After": "12"})
    )
    provider = make_provider()
    with pytest.raises(ProviderRateLimitError) as excinfo:
        await provider.complete(request())
    assert excinfo.value.retry_after == 12.0
    assert excinfo.value.retryable is True
    await provider.aclose()


@respx.mock
async def test_timeout_is_normalized():
    respx.post(URL).mock(side_effect=httpx.ReadTimeout("timeout"))
    provider = make_provider()
    with pytest.raises(ProviderTimeoutError):
        await provider.complete(request())
    await provider.aclose()


@respx.mock
async def test_connection_error_is_server_error():
    respx.post(URL).mock(side_effect=httpx.ConnectError("refused"))
    provider = make_provider()
    with pytest.raises(ProviderServerError):
        await provider.complete(request())
    await provider.aclose()


@respx.mock
async def test_non_json_response_is_response_error():
    respx.post(URL).mock(return_value=httpx.Response(200, text="not json"))
    provider = make_provider()
    with pytest.raises(ProviderResponseError):
        await provider.complete(request())
    await provider.aclose()


@respx.mock
async def test_degrades_from_json_schema_to_json_mode_on_400():
    """スキーマ非対応のエンドポイントでも「まず動く」 (§10.2)."""
    responses = [
        httpx.Response(400, text="response_format.json_schema is not supported"),
        httpx.Response(200, json=ok_body()),
    ]
    route = respx.post(URL).mock(side_effect=responses)
    provider = make_provider()

    response = await provider.complete(request())

    assert response.degraded_to is StructuredMode.JSON_MODE
    assert provider.effective_mode is StructuredMode.JSON_MODE
    first, second = route.calls
    assert "json_schema" in first.request.content.decode()
    assert '"response_format":{"type":"json_object"}' in second.request.content.decode()
    await provider.aclose()


@respx.mock
async def test_degradation_is_sticky_within_run():
    respx.post(URL).mock(
        side_effect=[
            httpx.Response(400, text="unsupported"),
            httpx.Response(200, json=ok_body()),
            httpx.Response(200, json=ok_body()),
        ]
    )
    provider = make_provider()
    await provider.complete(request())
    await provider.complete(request())
    assert provider.effective_mode is StructuredMode.JSON_MODE
    await provider.aclose()


@respx.mock
async def test_bad_request_without_schema_is_not_degraded():
    respx.post(URL).mock(return_value=httpx.Response(400, text="bad model"))
    provider = make_provider(
        capabilities=Capabilities(structured_output=StructuredMode.PROMPT_ONLY)
    )
    with pytest.raises(ProviderBadRequestError):
        await provider.complete(CompletionRequest(system="s", user="u", json_schema=None))
    await provider.aclose()


@respx.mock
async def test_health_check():
    respx.post(URL).mock(return_value=httpx.Response(200, json=ok_body()))
    provider = make_provider()
    assert (await provider.health_check()).ok is True

    respx.post(URL).mock(return_value=httpx.Response(500, text="down"))
    assert (await provider.health_check()).ok is False
    await provider.aclose()
