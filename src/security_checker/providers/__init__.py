"""Provider レイヤ (設計書 §9). 分類の軸は transport × dialect であり、ベンダーではない."""

from __future__ import annotations

from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    HealthStatus,
    LLMProvider,
    StructuredMode,
)
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderBadRequestError,
    ProviderError,
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderServerError,
    ProviderTimeoutError,
)
from security_checker.providers.http.transport import HttpProvider
from security_checker.providers.registry import build_provider

__all__ = [
    "Capabilities",
    "CompletionRequest",
    "CompletionResponse",
    "HealthStatus",
    "HttpProvider",
    "LLMProvider",
    "ProviderAuthError",
    "ProviderBadRequestError",
    "ProviderError",
    "ProviderRateLimitError",
    "ProviderResponseError",
    "ProviderServerError",
    "ProviderTimeoutError",
    "StructuredMode",
    "build_provider",
]
