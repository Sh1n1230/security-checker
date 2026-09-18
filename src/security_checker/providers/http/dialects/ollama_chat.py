"""`ollama_chat` 方言 — `POST {base_url}/api/chat` (設計書 §9.4).

同じエンドポイントは `openai_chat` 方言でも話せるが、**文脈長 (num_ctx) を
制御できない**。既定の文脈長のまま長いプロンプトを送ると、警告もなく黙って
切り詰められ、判定の質が壊れる。実運用で最もはまりやすい罠なので、
この方言では num_ctx を必ず明示して送る。
"""

from __future__ import annotations

from typing import Any

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.base import DialectOptions, DialectResponse

#: 明示しなかった場合の既定. エンドポイント側の既定 (2048) は短すぎる
DEFAULT_NUM_CTX = 8192


class OllamaChatDialect:
    """`/api/chat` 形式のリクエスト・レスポンス変換."""

    name = "ollama_chat"

    def __init__(self, options: DialectOptions | None = None) -> None:
        resolved = options or DialectOptions()
        self.num_ctx = resolved.num_ctx or DEFAULT_NUM_CTX
        self.keep_alive = resolved.keep_alive

    def endpoint(self, base_url: str, model: str) -> str:
        return f"{base_url.rstrip('/')}/api/chat"

    def headers(self, api_key: str | None) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        # ローカルで動かす前提の形だが、認証を挟むプロキシの背後に置く構成もある
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
            messages.append({"role": "user", "content": f"{req.system}\n\n{req.user}"})

        options: dict[str, Any] = {
            # 黙って切り詰められないよう、常に明示する (この方言の存在理由)
            "num_ctx": self.num_ctx,
            "num_predict": req.max_output_tokens,
        }
        if capabilities.supports_temperature:
            options["temperature"] = req.temperature
        if capabilities.supports_seed and req.seed is not None:
            options["seed"] = req.seed

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            # 応答を 1 つの JSON として受け取る (逐次生成は扱わない)
            "stream": False,
            "options": options,
        }
        if self.keep_alive is not None:
            payload["keep_alive"] = self.keep_alive

        if req.json_schema is not None:
            if mode is StructuredMode.JSON_SCHEMA:
                # format に JSON Schema をそのまま渡せる
                payload["format"] = req.json_schema
            elif mode is StructuredMode.JSON_MODE:
                payload["format"] = "json"
            # prompt_only では format を送らない (プロンプト側で縛る)
        return payload

    def parse_response(self, payload: dict[str, Any]) -> DialectResponse:
        message = payload.get("message")
        if not isinstance(message, dict):
            raise ProviderResponseError("応答に message がありません")
        content = message.get("content")
        if content is None:
            content = ""
        if not isinstance(content, str):
            raise ProviderResponseError("message.content が文字列ではありません")

        usage = Usage(
            input_tokens=_as_int(payload.get("prompt_eval_count")),
            output_tokens=_as_int(payload.get("eval_count")),
        )
        model_reported = payload.get("model")
        return DialectResponse(
            text=content,
            usage=usage,
            finish_reason=str(payload.get("done_reason") or "stop"),
            model_reported=model_reported if isinstance(model_reported, str) else None,
        )

    def health_payload(self, model: str) -> dict[str, Any]:
        return {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "stream": False,
            "options": {"num_ctx": self.num_ctx, "num_predict": 1},
        }

    def explain_error(self, status: int, body: str) -> str | None:
        """モデル未取得を、実行できるコマンドの案内に変える (§9.4)."""
        if status == 404 and "not found" in body.lower():
            return (
                "モデルが見つかりません。先にモデルを取得してください (例: `ollama pull <model>`)"
            )
        return None


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0
