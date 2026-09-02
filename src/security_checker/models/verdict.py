"""ReviewVerdict — 1 つの LLM の判定 (設計書 §6.2).

P1 時点では生成する経路がまだない (P2 の Reviewer が埋める) が、
LLM に強制する JSON Schema そのものであるため、データモデルとして先に固定する。
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from security_checker.models.enums import Exploitability, Severity


class VerdictStatus(StrEnum):
    """Verdict の生成結果. LLM 由来ではなく実行系が付与する."""

    OK = "ok"
    SCHEMA_ERROR = "schema_error"
    PROVIDER_ERROR = "provider_error"
    SKIPPED = "skipped"


class Usage(BaseModel):
    """トークン使用量."""

    model_config = ConfigDict(frozen=True)

    input_tokens: int = 0
    output_tokens: int = 0
    estimated_usd: float | None = None


class Evidence(BaseModel):
    """判断根拠となったコード位置."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int
    end_line: int
    note: str


class Remediation(BaseModel):
    """修正方針. 例示のみで、適用は行わない (P3: No Automatic Modification)."""

    model_config = ConfigDict(frozen=True)

    approach: str
    example: str | None = None
    references: list[str] = Field(default_factory=list)


class ReviewJudgement(BaseModel):
    """LLM が生成する部分だけを切り出したもの. これが Structured Output の schema になる."""

    model_config = ConfigDict(frozen=True)

    vulnerable: bool
    vulnerability_type: str | None = None
    cwe: list[str] = Field(default_factory=list)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive_probability: float = Field(ge=0.0, le=1.0)
    exploitability: Exploitability = Exploitability.UNKNOWN
    impact: str | None = None
    attack_vector: str | None = None
    attack_path: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    reasoning: str
    remediation: Remediation | None = None
    needs_more_context: list[str] = Field(default_factory=list)


class ReviewVerdict(ReviewJudgement):
    """メタ情報 (実行系が付与) + LLM の判定."""

    model_config = ConfigDict(frozen=True)

    candidate_id: str
    reviewer: str
    model: str
    attempt: int = 1
    usage: Usage = Usage()
    latency_ms: int = 0
    status: VerdictStatus = VerdictStatus.OK
