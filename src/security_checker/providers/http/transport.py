"""http transport — 共通の HTTP 送受信とエラー正規化 (設計書 §9.1, §9.2).

方言は形の変換だけを担当し、ここが通信・認証ヘッダ・例外の写像を持つ。
リトライとレート制御は **持たない**(scheduler の責務・§22)。
"""

from __future__ import annotations

import time
from typing import Any, Literal

import httpx

from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    HealthStatus,
    StructuredMode,
    next_weaker_mode,
)
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderBadRequestError,
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderServerError,
    ProviderTimeoutError,
)
from security_checker.providers.http.dialects import Dialect

ERROR_BODY_LIMIT = 500


class HttpProvider:
    """任意の HTTP エンドポイントを 1 つの方言で話す Provider."""

    transport: Literal["http", "process"] = "http"

    def __init__(
        self,
        *,
        name: str,
        dialect: Dialect,
        base_url: str,
        model: str,
        capabilities: Capabilities,
        api_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.name = name
        self.dialect_impl = dialect
        self.dialect = dialect.name
        self.base_url = base_url
        self.model = model
        self._capabilities = capabilities
        self._api_key = api_key
        self._extra_headers = extra_headers or {}
        self._client = client or httpx.AsyncClient()
        self._owns_client = client is None
        self._effective_mode = capabilities.structured_output
        self._degraded_to: StructuredMode | None = None

    @property
    def capabilities(self) -> Capabilities:
        return self._capabilities

    @property
    def effective_mode(self) -> StructuredMode:
        """降格後の実効モード. 一度降格したら run 内で使い続ける (§9.3)."""
        return self._effective_mode

    async def complete(self, req: CompletionRequest) -> CompletionResponse:
        """1 リクエスト = 1 判定. 400 が返ったら 1 段階降格して再送する (§10.2)."""
        mode = self._effective_mode if req.json_schema is not None else StructuredMode.PROMPT_ONLY
        started = time.monotonic()
        while True:
            try:
                payload = await self._post(
                    self.dialect_impl.build_payload(
                        req, model=self.model, capabilities=self._capabilities, mode=mode
                    ),
                    timeout_s=req.timeout_s,
                )
            except ProviderBadRequestError:
                weaker = next_weaker_mode(mode) if req.json_schema is not None else None
                if weaker is None:
                    raise
                mode = weaker
                self._effective_mode = weaker
                self._degraded_to = weaker
                continue

            parsed = self.dialect_impl.parse_response(payload)
            return CompletionResponse(
                text=parsed.text,
                parsed=parsed.parsed,
                usage=parsed.usage,
                finish_reason=parsed.finish_reason,
                model_reported=parsed.model_reported,
                provider_request_id=None,
                latency_ms=int((time.monotonic() - started) * 1000),
                degraded_to=self._degraded_to,
            )

    async def health_check(self) -> HealthStatus:
        started = time.monotonic()
        try:
            await self._post(self.dialect_impl.health_payload(self.model), timeout_s=30.0)
        except Exception as exc:  # 到達性の確認なので、種類を問わず結果に畳む
            return HealthStatus(ok=False, detail=str(exc))
        return HealthStatus(ok=True, latency_ms=int((time.monotonic() - started) * 1000))

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # --- 内部 -------------------------------------------------------------

    async def _post(self, payload: dict[str, Any], *, timeout_s: float) -> dict[str, Any]:
        headers = {**self.dialect_impl.headers(self._api_key), **self._extra_headers}
        url = self.dialect_impl.endpoint(self.base_url, self.model)
        try:
            response = await self._client.post(
                url, json=payload, headers=headers, timeout=timeout_s
            )
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(
                f"{self.name}: 応答が {timeout_s}s 以内に返りませんでした", provider=self.name
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderServerError(
                f"{self.name}: 接続に失敗しました: {exc}", provider=self.name
            ) from exc

        self._raise_for_status(response)
        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderResponseError(
                f"{self.name}: 応答が JSON ではありません", provider=self.name
            ) from exc
        if not isinstance(body, dict):
            raise ProviderResponseError(
                f"{self.name}: 応答のトップレベルがオブジェクトではありません", provider=self.name
            )
        return body

    def _raise_for_status(self, response: httpx.Response) -> None:
        status = response.status_code
        if status < 400:
            return
        detail = _excerpt(response.text)
        if status in (401, 403):
            raise ProviderAuthError(
                f"{self.name}: 認証に失敗しました ({status})。"
                f"api_key_env に指定した環境変数の値を確認してください: {detail}",
                provider=self.name,
            )
        if status == 429:
            raise ProviderRateLimitError(
                f"{self.name}: レート制限に達しました: {detail}",
                provider=self.name,
                retry_after=_retry_after(response),
            )
        if status >= 500:
            raise ProviderServerError(
                f"{self.name}: サーバエラー ({status}): {detail}", provider=self.name
            )
        # 方言が本文から次の行動を導けるなら、それを添える (§20.2)
        hint = self.dialect_impl.explain_error(status, response.text)
        raise ProviderBadRequestError(
            f"{self.name}: リクエストが拒否されました ({status}): {detail}"
            + (f" — {hint}" if hint else ""),
            provider=self.name,
        )


def _excerpt(text: str) -> str:
    collapsed = " ".join(text.split())
    return collapsed[:ERROR_BODY_LIMIT]


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None
