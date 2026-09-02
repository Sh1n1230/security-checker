"""スコア算出 (設計書 §17.3).

v1 の「100 点満点・A〜D ランク」は残すが、補助指標に格下げする。
スキャナが 1 つでも skipped/failed なら partial: true を必ず立てる
(v1 は未導入でも満点に見えるという構造的欠陥があった)。
"""

from __future__ import annotations

from typing import Literal

from security_checker.models.candidate import Candidate
from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.report import ScannerRun, Score

DEDUCTION = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
    Severity.NONE: 0,
}
CATEGORY_CAP = 40


def rank_for(value: int) -> Literal["A", "B", "C", "D"]:
    if value >= 90:
        return "A"
    if value >= 70:
        return "B"
    if value >= 50:
        return "C"
    return "D"


def compute_score(candidates: list[Candidate], runs: list[ScannerRun]) -> Score:
    """カテゴリ毎に減点し、上限 40 で頭打ちにする."""
    deductions: dict[str, int] = {}
    for candidate in candidates:
        severity = candidate.severity_reported or Severity.INFO
        key = candidate.category.value
        deductions[key] = deductions.get(key, 0) + DEDUCTION[severity]
    capped = {key: min(value, CATEGORY_CAP) for key, value in deductions.items()}
    value = max(0, 100 - sum(capped.values()))

    incomplete = [run for run in runs if run.status is not ScanStatus.OK]
    partial_reason = None
    if incomplete:
        partial_reason = "、".join(
            f"{run.scanner} {'未実行' if run.status is ScanStatus.SKIPPED else '失敗'}"
            for run in incomplete
        )
    return Score(
        value=value,
        rank=rank_for(value),
        partial=bool(incomplete),
        partial_reason=partial_reason,
        deductions=capped,
    )
