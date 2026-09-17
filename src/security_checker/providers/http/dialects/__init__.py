"""方言アダプタ. 形の変換のみを行い、ベンダー名は現れない (設計書 §9)."""

from __future__ import annotations

from collections.abc import Callable

from security_checker.providers.http.dialects.anthropic_messages import AnthropicMessagesDialect
from security_checker.providers.http.dialects.base import (
    Dialect,
    DialectOptions,
    DialectResponse,
)
from security_checker.providers.http.dialects.ollama_chat import OllamaChatDialect
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect

# P3 で gemini_generate を追加する
DIALECTS: dict[str, Callable[..., Dialect]] = {
    AnthropicMessagesDialect.name: AnthropicMessagesDialect,
    OllamaChatDialect.name: OllamaChatDialect,
    OpenAIChatDialect.name: OpenAIChatDialect,
}

__all__ = [
    "DIALECTS",
    "AnthropicMessagesDialect",
    "Dialect",
    "DialectOptions",
    "DialectResponse",
    "OllamaChatDialect",
    "OpenAIChatDialect",
]
