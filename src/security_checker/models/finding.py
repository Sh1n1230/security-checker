"""Finding — 集約後の最終出力 (設計書 §6.3)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from security_checker.models.candidate import Candidate
from security_checker.models.enums import Agreement, FindingStatus, Severity
from security_checker.models.verdict import ReviewVerdict, VerdictStatus


class SuppressionReason(StrEnum):
    """抑制の理由 (設計書 §17.2)."""

    BASELINE = "baseline"
    IGNORE_FILE = "ignore_file"
    INLINE_ANNOTATION = "inline_annotation"


class AggregationDetail(BaseModel):
    """どの戦略でどう計算したかの説明. P4 (Auditable) の一部."""

    model_config = ConfigDict(frozen=True)

    strategy: str
    votes_vulnerable: int = 0
    votes_total: int = 0
    detail: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Candidate + 全 Verdict + 集約結果."""

    model_config = ConfigDict(frozen=True)

    candidate: Candidate
    verdicts: list[ReviewVerdict] = Field(default_factory=list)

    status: FindingStatus
    severity: Severity
    confidence: float = 0.0
    agreement: Agreement = Agreement.NOT_APPLICABLE
    cwe: list[str] = Field(default_factory=list)
    summary: str = ""
    aggregation: AggregationDetail | None = None

    suppressed: SuppressionReason | None = None

    @property
    def supporting_reasoning(self) -> str:
        """指摘の根拠として載せる理由. 無ければ空文字列.

        「脆弱」と判定した Reviewer の文章だけを選ぶ。反対意見やエラーメッセージを
        指摘の理由として見せない。inline・SARIF・サマリ・report.md で共通に使う。
        """
        for verdict in self.verdicts:
            if verdict.status is VerdictStatus.OK and verdict.vulnerable:
                reasoning = verdict.reasoning.strip()
                if reasoning:
                    return reasoning
        return ""
