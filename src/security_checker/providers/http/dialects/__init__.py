"""方言アダプタ. 形の変換のみを行い、ベンダー名は現れない (設計書 §9)."""

from __future__ import annotations

from collections.abc import Callable

from security_checker.providers.http.dialects.base import (
    Dialect,
    DialectOptions,
    DialectResponse,
)
from security_checker.providers.http.dialects.ollama_chat import OllamaChatDialect
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect

# P3 で anthropic_messages / gemini_generate を追加する
DIALECTS: dict[str, Callable[..., Dialect]] = {
    OllamaChatDialect.name: OllamaChatDialect,
    OpenAIChatDialect.name: OpenAIChatDialect,
}

__all__ = [
    "DIALECTS",
    "Dialect",
    "DialectOptions",
    "DialectResponse",
    "OllamaChatDialect",
    "OpenAIChatDialect",
]
