"""record / replay — 実 LLM の応答を記録して再生する (設計書 §25.3).

通常のテストは記録済みの応答 (カセット) を再生するだけで、ネットワークも鍵も使わない。
記録は鍵を持つ人が手動で行う。

    provider = CassetteProvider(Path("tests/cassettes/x.json"), inner=real_provider, record=True)

- キーは「system + user + スキーマ + モデル」のハッシュ。プロンプトが変われば再記録が必要になる
  (古い応答で新しいプロンプトを試したことにしない)。
- 記録時にマスキングフィルタ (§19.1) を通す。カセットはコミットするので、
  鍵の形をした文字列を残さない。
- 再生時に該当する記録が無ければ失敗する。黙って別の応答を返さない。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from security_checker.context.redact import redact_known_patterns
from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    HealthStatus,
    LLMProvider,
    StructuredMode,
)

CASSETTE_VERSION = 1


class CassetteMissError(AssertionError):
    """再生しようとした応答が記録されていない."""


def request_key(req: CompletionRequest, model: str) -> str:
    payload = json.dumps(
        {
            "model": model,
            "system": req.system,
            "user": req.user,
            "schema": req.json_schema,
            "structured_mode": req.structured_mode.value,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CassetteProvider:
    """記録モードでは inner を呼んで保存し、再生モードでは保存した応答を返す."""

    def __init__(
        self,
        path: Path,
        *,
        inner: LLMProvider | None = None,
        record: bool = False,
        model: str | None = None,
        transport: Literal["http", "process"] = "http",
        dialect: str = "cassette",
    ) -> None:
        if record and inner is None:
            raise ValueError("記録には実際の Provider (inner) が必要です")
        self.path = path
        self.inner = inner
        self.record = record
        self.model: str = model or str(getattr(inner, "model", "cassette"))
        self.name = getattr(inner, "name", "cassette")
        self.transport = getattr(inner, "transport", transport)
        self.dialect = getattr(inner, "dialect", dialect)
        self._entries: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.is_file():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if data.get("version") != CASSETTE_VERSION:
            raise ValueError(f"カセットの版が違います: {self.path}")
        entries: dict[str, dict[str, Any]] = data.get("entries", {})
        return entries

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(
            {"version": CASSETTE_VERSION, "model": self.model, "entries": self._entries},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        self.path.write_text(redact_known_patterns(text) + "\n", encoding="utf-8")

    @property
    def capabilities(self) -> Capabilities:
        if self.inner is not None:
            return self.inner.capabilities
        return Capabilities(structured_output=StructuredMode.JSON_SCHEMA)

    async def complete(self, req: CompletionRequest) -> CompletionResponse:
        key = request_key(req, self.model)
        if self.record and self.inner is not None:
            response = await self.inner.complete(req)
            self._entries[key] = {
                "user_head": req.user[:120],
                "response": response.model_dump(mode="json"),
            }
            self._save()
            return response
        entry = self._entries.get(key)
        if entry is None:
            raise CassetteMissError(
                f"{self.path} にこのリクエストの記録がありません (プロンプトが変わった可能性)。"
                "鍵を用意して `pytest --record` で記録し直してください"
            )
        return CompletionResponse.model_validate(entry["response"])

    async def health_check(self) -> HealthStatus:
        if self.inner is not None and self.record:
            return await self.inner.health_check()
        return HealthStatus(ok=True, detail="cassette")

    async def aclose(self) -> None:
        if self.inner is not None:
            await self.inner.aclose()
