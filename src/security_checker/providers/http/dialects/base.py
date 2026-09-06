"""方言 (dialect) の契約.

方言は「リクエストとレスポンスの形」だけを知る。HTTP の送受信・エラー正規化は
transport.py が持ち、認証やリトライの都合が方言側に漏れないようにする。
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode


class DialectResponse(BaseModel):
    """方言が HTTP レスポンス JSON から取り出した共通形."""

    model_config = ConfigDict(frozen=True)

    text: str
    parsed: dict[str, Any] | None = None
    usage: Usage = Usage()
    finish_reason: str = "stop"
    model_reported: str | None = None


class Dialect(Protocol):
    """リクエスト / レスポンスの形の変換のみを担う."""

    name: str

    def endpoint(self, base_url: str) -> str: ...

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

    def health_payload(self, model: str) -> dict[str, Any]: ...
