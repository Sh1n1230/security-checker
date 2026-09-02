"""LLM Provider Interface (設計書 §9.1).

分類の軸は「ベンダー」ではなく **transport × dialect**。
このファイルにも、配下のコードにも、ベンダー名は現れない。
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from security_checker.models.verdict import Usage


class StructuredMode(StrEnum):
    """構造化出力の強制方法. 左ほど強い (設計書 §10.2)."""

    JSON_SCHEMA = "json_schema"
    JSON_MODE = "json_mode"
    PROMPT_ONLY = "prompt_only"


DEGRADATION_ORDER = (
    StructuredMode.JSON_SCHEMA,
    StructuredMode.JSON_MODE,
    StructuredMode.PROMPT_ONLY,
)


def next_weaker_mode(mode: StructuredMode) -> StructuredMode | None:
    """1 段階弱いモードを返す. これ以上降格できなければ None."""
    index = DEGRADATION_ORDER.index(mode)
    if index + 1 >= len(DEGRADATION_ORDER):
        return None
    return DEGRADATION_ORDER[index + 1]


class Capabilities(BaseModel):
    """エンドポイントが何をできるか. 叩いても分からないため 3 段構えで決める (§9.3)."""

    model_config = ConfigDict(frozen=True)

    structured_output: StructuredMode = StructuredMode.JSON_MODE
    tool_calling: bool = False
    vision: bool = False
    reasoning: bool = False
    max_context_tokens: int = 128_000
    max_output_tokens: int = 4096
    supports_system_role: bool = True
    supports_temperature: bool = True
    supports_seed: bool = False


class CompletionRequest(BaseModel):
    """1 回の判定要求. Provider は 1 リクエスト = 1 判定に徹する."""

    model_config = ConfigDict(frozen=True)

    system: str
    user: str
    json_schema: dict[str, Any] | None = None
    structured_mode: StructuredMode = StructuredMode.JSON_MODE
    max_output_tokens: int = 2000
    temperature: float = 0.0
    seed: int | None = None
    timeout_s: float = 120.0


class CompletionResponse(BaseModel):
    """Provider の応答. リトライ・レート制御は上位 (scheduler) の責務."""

    model_config = ConfigDict(frozen=True)

    text: str
    parsed: dict[str, Any] | None = None
    usage: Usage = Usage()
    finish_reason: str = "stop"
    model_reported: str | None = None
    provider_request_id: str | None = None
    latency_ms: int = 0
    degraded_to: StructuredMode | None = None


class HealthStatus(BaseModel):
    """`providers check` 用の到達性確認結果."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    detail: str | None = None
    latency_ms: int | None = None


class LLMProvider(Protocol):
    """すべての Provider が満たす契約 (§25.2 の契約テストが検証する)."""

    name: str
    transport: Literal["http", "process"]
    dialect: str

    @property
    def capabilities(self) -> Capabilities: ...

    async def complete(self, req: CompletionRequest) -> CompletionResponse: ...

    async def health_check(self) -> HealthStatus: ...

    async def aclose(self) -> None: ...


class CapabilityOverrides(BaseModel):
    """設定ファイルからの capability 明示指定 (最優先・§9.3)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    structured_output: StructuredMode | None = None
    max_context_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    supports_system_role: bool | None = None
    supports_temperature: bool | None = None
    supports_seed: bool | None = None
    reasoning: bool | None = None

    def apply(self, base: Capabilities) -> Capabilities:
        updates = {key: value for key, value in self.model_dump().items() if value is not None}
        return base.model_copy(update=updates)
