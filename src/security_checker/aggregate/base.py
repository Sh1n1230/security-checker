"""Aggregator の契約 (設計書 §13)."""

from __future__ import annotations

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
