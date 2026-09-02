"""ドメインモデル (設計書 §6)."""

from __future__ import annotations

from security_checker.models.candidate import Candidate, Location, PackageRef, candidate_id
from security_checker.models.enums import (
    Agreement,
    Category,
    Exploitability,
    FindingStatus,
    ScanStatus,
    Severity,
)
from security_checker.models.finding import AggregationDetail, Finding, SuppressionReason
from security_checker.models.report import (
    SCHEMA_VERSION,
    Coverage,
    Report,
    ReportWarning,
    ScannerRun,
    Score,
    TargetInfo,
)
from security_checker.models.verdict import (
    Evidence,
    Remediation,
    ReviewJudgement,
    ReviewVerdict,
    Usage,
    VerdictStatus,
)

__all__ = [
    "SCHEMA_VERSION",
    "AggregationDetail",
    "Agreement",
    "Candidate",
    "Category",
    "Coverage",
    "Evidence",
    "Exploitability",
    "Finding",
    "FindingStatus",
    "Location",
    "PackageRef",
    "Remediation",
    "Report",
    "ReportWarning",
    "ReviewJudgement",
    "ReviewVerdict",
    "ScanStatus",
    "ScannerRun",
    "Score",
    "Severity",
    "SuppressionReason",
    "TargetInfo",
    "Usage",
    "VerdictStatus",
    "candidate_id",
]
