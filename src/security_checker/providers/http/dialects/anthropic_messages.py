"""`anthropic_messages` 方言 — `POST {base_url}/v1/messages` (設計書 §9.6).

「Anthropic 社の」ではなく「Messages API という形の」という意味の名前である。
この形を話すエンドポイントであれば、提供元がどこであっても同じアダプタで扱える。

`openai_chat` と互換性がない点が 2 つある。
  1. system がメッセージ配列ではなく独立したフィールドである
  2. JSON Schema は `response_format` ではなく `output_config.format` で指定する

2 は以前はツール呼び出しの強制 (`tool_choice: tool`) で代替していたが、強制は新しいモデルで
400 になり、`strict` の無いツール入力はスキーマに合う保証も無かった (#297)。
`output_config.format` ならスキーマに合う応答が保証される。ただしこの指定は数値・文字列長・
配列長の制約を受け付けないので、送る前に外し、値の制約は今どおり pydantic で検証する。
`output_config` を受け付けないエンドポイントでは、上位の段階的降格で
json_mode / prompt_only に落ちる。
"""

from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.base import (
    DialectOptions,
    DialectResponse,
    output_limit,
)

#: output_config.format の JSON Schema が受け付けないキーワード. 値の制約は pydantic 側で検証する
UNSUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "maxItems",
        "uniqueItems",
    }
)
#: この形のバージョン指定ヘッダ. headers 設定で上書きできる
DEFAULT_API_VERSION = "2023-06-01"


class AnthropicMessagesDialect:
    """Messages 形式のリクエスト・レスポンス変換."""

    name = "anthropic_messages"

    def __init__(self, options: DialectOptions | None = None) -> None:
        # この形には文脈長やモデル保持の指定が無いため、受け取っても使わない
        self.options = options or DialectOptions()

    def endpoint(self, base_url: str, model: str) -> str:
        """リクエストを送る URL を返す."""
        # base_url に /v1 を含めて書く人と含めない人の両方がいる。
        # どちらでも同じ URL になるよう正規化する (二重の /v1 を作らない)。
        trimmed = base_url.rstrip("/")
        trimmed = trimmed.removesuffix("/v1")
        return f"{trimmed}/v1/messages"

    def headers(self, api_key: str | None) -> dict[str, str]:
        """認証を含む HTTP ヘッダを返す."""
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": DEFAULT_API_VERSION,
        }
        if api_key:
            # この形は Authorization ではなく専用ヘッダで鍵を渡す
            headers["x-api-key"] = api_key
        return headers

    def build_payload(
        self,
        req: CompletionRequest,
        *,
        model: str,
        capabilities: Capabilities,
        mode: StructuredMode,
    ) -> dict[str, Any]:
        """CompletionRequest をこの方言のリクエスト本文にする."""
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": output_limit(req, capabilities),
            "messages": [{"role": "user", "content": req.user}],
        }
        if capabilities.supports_system_role:
            # system はメッセージではなく独立フィールド。この差異をここで吸収する
            payload["system"] = req.system
        else:
            payload["messages"] = [{"role": "user", "content": f"{req.system}\n\n{req.user}"}]
        if capabilities.supports_temperature:
            payload["temperature"] = req.temperature

        if req.json_schema is not None and mode is StructuredMode.JSON_SCHEMA:
            payload["output_config"] = {
                "format": {"type": "json_schema", "schema": supported_schema(req.json_schema)}
            }
        # json_mode に相当する仕組みはこの形に無い。prompt_only と同じく
        # プロンプト側の指示だけで縛り、抽出と修復は structured.py に任せる。
        return payload

    def parse_response(self, payload: dict[str, Any]) -> DialectResponse:
        """応答の本文から、テキスト・構造化出力・使用量を取り出す."""
        content = payload.get("content")
        if not isinstance(content, list):
            raise ProviderResponseError("応答に content がありません")

        texts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])

        text = "".join(texts)
        if not text:
            raise ProviderResponseError("応答に text が含まれていません")
        parsed = _json_object(text)

        raw_usage = payload.get("usage")
        usage = Usage()
        if isinstance(raw_usage, dict):
            # input_tokens はキャッシュの読み出し・書き込みを含まない。ほかの方言 (prompt_tokens) と
            # 同じく「送った入力の合計」にそろえ、予算とコストの見積りで数え漏らさない (#667)
            cache_read = _as_int(raw_usage.get("cache_read_input_tokens"))
            cache_write = _as_int(raw_usage.get("cache_creation_input_tokens"))
            usage = Usage(
                input_tokens=_as_int(raw_usage.get("input_tokens")) + cache_read + cache_write,
                output_tokens=_as_int(raw_usage.get("output_tokens")),
                cached_tokens=cache_read,
            )

        model_reported = payload.get("model")
        return DialectResponse(
            text=text,
            parsed=parsed,
            usage=usage,
            finish_reason=str(payload.get("stop_reason") or "stop"),
            model_reported=model_reported if isinstance(model_reported, str) else None,
        )

    def health_payload(self, model: str, capabilities: Capabilities) -> dict[str, Any]:
        """疎通確認用の最小のリクエスト本文 (出力は 1 トークン)."""
        return {
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        }

    def is_auth_error(self, status: int, body: str) -> bool:
        """この方言は認証エラーを 401 / 403 で返すので、本文では判定しない."""
        return False

    def default_capabilities(self) -> dict[str, object]:
        """この形に json_mode は無い. 構造化出力は output_config.format (json_schema) で得る."""
        return {"structured_output": StructuredMode.JSON_SCHEMA.value}

    def explain_error(self, status: int, body: str) -> str | None:
        """次に取れる行動が分かる場合だけ文章にする (§20.2)."""
        lowered = body.lower()
        if status == HTTPStatus.NOT_FOUND and "model" in lowered:
            return (
                "model に指定した ID がこのエンドポイントに存在しません。"
                "設定の model を確認してください"
            )
        if status == HTTPStatus.BAD_REQUEST and "max_tokens" in lowered:
            return (
                "出力トークンの上限がモデルの許容範囲を超えています。"
                "max_output_tokens を下げてください"
            )
        return None


def supported_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """output_config.format が受け付けないキーワードを外した JSON Schema を返す (#297)."""
    stripped = _strip_unsupported(schema)
    return stripped if isinstance(stripped, dict) else {}


def _strip_unsupported(node: object) -> object:
    """`properties` の中身はプロパティ名 → スキーマなので、名前そのものは消さない.

    `minItems` は 0 か 1 だけ受け付けられるので、それ以外のときだけ外す。
    """
    if isinstance(node, list):
        return [_strip_unsupported(item) for item in node]
    if not isinstance(node, dict):
        return node
    result: dict[str, object] = {}
    for key, value in node.items():
        if key == "properties" and isinstance(value, dict):
            result[key] = {name: _strip_unsupported(sub) for name, sub in value.items()}
        elif key in UNSUPPORTED_SCHEMA_KEYWORDS or (key == "minItems" and value not in (0, 1)):
            continue
        else:
            result[key] = _strip_unsupported(value)
    return result


def _json_object(text: str) -> dict[str, Any] | None:
    """本文がそのまま JSON オブジェクトなら返す. 違えば None (抽出と修復は structured.py が行う)."""
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else 0
