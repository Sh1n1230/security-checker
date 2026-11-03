"""方言 (dialect) の契約.

方言は「リクエストとレスポンスの形」だけを知る。HTTP の送受信・エラー正規化は
transport.py が持ち、認証やリトライの都合が方言側に漏れないようにする。
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode

#: 思考トークンを持つモデルでは、出力の上限を思考で使い切って本文が切れる。
#: reasoning を宣言している場合だけ、その分の余裕を足す (§9.6)
REASONING_HEADROOM_TOKENS = 4096


def output_limit(req: CompletionRequest, capabilities: Capabilities) -> int:
    """方言が送る出力の上限. 上限に思考トークンを含むかは問わず、宣言があれば余裕を足す."""
    if capabilities.reasoning:
        return req.max_output_tokens + REASONING_HEADROOM_TOKENS
    return req.max_output_tokens


class DialectResponse(BaseModel):
    """方言が HTTP レスポンス JSON から取り出した共通形."""

    model_config = ConfigDict(frozen=True)

    text: str
    parsed: dict[str, Any] | None = None
    usage: Usage = Usage()
    finish_reason: str = "stop"
    model_reported: str | None = None


class DialectOptions(BaseModel):
    """方言ごとの追加パラメータ.

    設定 (ReviewerConfig) から方言へ渡す値。**方言を特定する分岐を registry に
    作らないため**、全方言が同じ型を受け取り、使わないものは無視する。
    """

    model_config = ConfigDict(frozen=True)

    #: 文脈長の明示指定. 既定値のまま黙って切り詰める実装があるため、必ず送れるようにする
    num_ctx: int | None = None
    #: 連続レビューでモデルの再ロードを避けるための保持時間 (例: "5m")
    keep_alive: str | None = None


class Dialect(Protocol):
    """リクエスト / レスポンスの形の変換のみを担う."""

    name: str

    def endpoint(self, base_url: str, model: str) -> str:
        """送信先 URL. モデル名を URL に含める形もあるため model を受け取る."""
        ...

    def headers(self, api_key: str | None) -> dict[str, str]: ...

    def build_payload(
        self,
        req: CompletionRequest,
        *,
        model: str,
        capabilities: Capabilities,
        mode: StructuredMode,
    ) -> dict[str, Any]: ...

    def parse_response(self, payload: dict[str, Any]) -> DialectResponse: ...

    def health_payload(self, model: str, capabilities: Capabilities) -> dict[str, Any]: ...

    def is_auth_error(self, status: int, body: str) -> bool:
        """401/403 以外で返る認証エラーか. 鍵の不備を別のコードで返す形のために置く."""
        ...

    def explain_error(self, status: int, body: str) -> str | None:
        """4xx の本文から、利用者が次に取れる行動を導けるなら文章にして返す.

        エラーメッセージには「次の行動」を書く (設計書 §20.2)。
        判断できなければ None を返し、transport の既定メッセージに任せる。
        """
        ...
