"""Provider 契約テスト (設計書 §25.2).

外部プラグイン作者は次だけ書けば自作 Provider の適合性を検証できる:

    class TestMyProvider(ProviderContractTests):
        def make_provider(self):
            return MyProvider(...)
"""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
    StructuredMode,
)


class ProviderContractTests:
    """すべての Provider が満たすべき契約."""

    def make_provider(self) -> LLMProvider:  # pragma: no cover - サブクラスが実装する
        raise NotImplementedError

    def make_request(self, **overrides: Any) -> CompletionRequest:
        payload: dict[str, Any] = {
            "system": "system",
            "user": "user",
            "json_schema": {"type": "object", "properties": {}},
            "max_output_tokens": 128,
            "timeout_s": 5.0,
        }
        payload.update(overrides)
        return CompletionRequest(**payload)

    def test_capabilities_are_valid(self) -> None:
        provider = self.make_provider()
        capabilities = provider.capabilities
        assert isinstance(capabilities, Capabilities)
        assert capabilities.max_context_tokens > 0
        assert capabilities.max_output_tokens > 0
        assert isinstance(capabilities.structured_output, StructuredMode)

    def test_identity_fields(self) -> None:
        provider = self.make_provider()
        assert provider.transport in ("http", "process")
        assert isinstance(provider.dialect, str) and provider.dialect

    @pytest.mark.asyncio
    async def test_complete_returns_response(self) -> None:
        provider = self.make_provider()
        response = await provider.complete(self.make_request())
        assert isinstance(response, CompletionResponse)
        assert isinstance(response.text, str)
        assert response.usage.input_tokens >= 0
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_aclose_is_idempotent(self) -> None:
        provider = self.make_provider()
        await provider.aclose()
        await provider.aclose()
