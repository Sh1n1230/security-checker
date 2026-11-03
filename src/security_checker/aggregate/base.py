"""Aggregator の契約 (設計書 §13)."""

from __future__ import annotations

import math
import statistics
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from security_checker.config.schema import AggregationConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Agreement, FindingStatus, Severity
from security_checker.models.verdict import ReviewVerdict

SEVERITY_NUMBER = {
    Severity.NONE: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
NUMBER_SEVERITY = {value: key for key, value in SEVERITY_NUMBER.items()}

#: 「脆弱ではない」で候補を消す (false_positive にする) のに必要な確信度.
#: これ未満は review_required に残す。主指標は Recall で、見逃しを増やさない側に倒す (§27.2)
DECISIVE_CONFIDENCE = 0.8


def round_half_up(value: float) -> int:
    """x.5 を常に上へ丸める. 組み込みの round() は偶数丸めで、段によって向きが変わる."""
    return math.floor(value + 0.5)


def aggregate_severity(
    vulnerable: Sequence[ReviewVerdict],
    mode: str,
    weight_of: Callable[[ReviewVerdict], float],
) -> Severity:
    """「脆弱」と答えた Reviewer の severity をまとめる (§14.1).

    weighted_mean だけが重みを使う。median / max は外れ値の扱いの話で、重みの話ではない。
    """
    numbers = [SEVERITY_NUMBER[verdict.severity] for verdict in vulnerable]
    if not numbers:
        return Severity.NONE
    if mode == "max":
        return NUMBER_SEVERITY[max(numbers)]
    if mode == "weighted_mean":
        weights = [weight_of(verdict) for verdict in vulnerable]
        total = sum(weights)
        value = (
            sum(number * weight for number, weight in zip(numbers, weights, strict=True)) / total
            if total > 0
            else statistics.fmean(numbers)
        )
    else:  # median: 1 モデルの過大評価でノイズが増えるのを防ぐ
        value = float(statistics.median(numbers))
    return NUMBER_SEVERITY[round_half_up(value)]


class AggregationOutcome(BaseModel):
    """集約結果. detail に計算過程を必ず残す (P4: Auditable)."""

    model_config = ConfigDict(frozen=True)

    status: FindingStatus
    severity: Severity
    confidence: float
    agreement: Agreement
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)


class Aggregator(Protocol):
    name: str

    def aggregate(
        self,
        candidate: Candidate,
        verdicts: list[ReviewVerdict],
        cfg: AggregationConfig,
    ) -> AggregationOutcome: ...
