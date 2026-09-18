"""`openai_chat` 方言 — `POST {base_url}/chat/completions` (設計書 §9.3).

この形を話すサービスは多数あり、そのどれも本体の変更なしに使える。
特定のサービスを想定した分岐はここに持たない。
"""

from __future__ import annotations

from typing import Any

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.base import DialectOptions, DialectResponse

SCHEMA_NAME = "security_review_verdict"


class OpenAIChatDialect:
    """chat/completions 形式のリクエスト・レスポンス変換."""

    name = "openai_chat"

    def __init__(self, options: DialectOptions | None = None) -> None:
        # この形には文脈長やモデル保持の指定が無いため、受け取っても使わない
        self.options = options or DialectOptions()

    def endpoint(self, base_url: str, model: str) -> str:
        # この形はモデルをペイロードで送るため、URL には現れない
        return f"{base_url.rstrip('/')}/chat/completions"

    def headers(self, api_key: str | None) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def build_payload(
        self,
        req: CompletionRequest,
        *,
        model: str,
        capabilities: Capabilities,
        mode: StructuredMode,
    ) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if capabilities.supports_system_role:
            messages.append({"role": "system", "content": req.system})
            messages.append({"role": "user", "content": req.user})
        else:
            # system ロールを持たないエンドポイント向けに 1 通に畳む
            messages.append({"role": "user", "content": f"{req.system}\n\n{req.user}"})

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": req.max_output_tokens,
        }
        if capabilities.supports_temperature:
            payload["temperature"] = req.temperature
        if capabilities.supports_seed and req.seed is not None:
            payload["seed"] = req.seed

        if req.json_schema is not None:
            if mode is StructuredMode.JSON_SCHEMA:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": SCHEMA_NAME,
                        "strict": True,
                        "schema": req.json_schema,
                    },
                }
            elif mode is StructuredMode.JSON_MODE:
                payload["response_format"] = {"type": "json_object"}
            # prompt_only では response_format を送らない (プロンプト側で縛る)
        return payload

    def parse_response(self, payload: dict[str, Any]) -> DialectResponse:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderResponseError("応答に choices がありません")
        first = choices[0]
        if not isinstance(first, dict):
            raise ProviderResponseError("choices[0] がオブジェクトではありません")
        message = first.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if content is None:
            content = ""
        if isinstance(content, list):
            # content が配列で返る実装もある (text パートを連結する)
            parts = [
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and part.get("type") in (None, "text")
            ]
            content = "".join(parts)
        if not isinstance(content, str):
            raise ProviderResponseError("message.content が文字列ではありません")

        raw_usage = payload.get("usage")
        usage = Usage()
        if isinstance(raw_usage, dict):
            details = raw_usage.get("completion_tokens_details")
            reasoning = details.get("reasoning_tokens") if isinstance(details, dict) else None
            prompt_details = raw_usage.get("prompt_tokens_details")
            cached = (
                prompt_details.get("cached_tokens") if isinstance(prompt_details, dict) else None
            )
            usage = Usage(
                input_tokens=_as_int(raw_usage.get("prompt_tokens")),
                output_tokens=_as_int(raw_usage.get("completion_tokens")),
                reasoning_tokens=_as_int(reasoning),
                cached_tokens=_as_int(cached),
            )

        return DialectResponse(
            text=content,
            usage=usage,
            finish_reason=str(first.get("finish_reason") or "stop"),
            model_reported=payload.get("model") if isinstance(payload.get("model"), str) else None,
        )

    def health_payload(self, model: str) -> dict[str, Any]:
        return {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }

    def explain_error(self, status: int, body: str) -> str | None:
        """この形はサービスごとに本文が違いすぎるため、推測しない."""
        return None


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0
