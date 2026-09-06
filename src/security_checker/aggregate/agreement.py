"""一致度の算出 (設計書 §15).

評価者が 2〜5 人程度では Fleiss' kappa は不安定なので採用しない。
agreement は「正しさ」ではないため、confidence を **引き下げる方向にのみ** 強く効かせる。
"""

from __future__ import annotations

from security_checker.aggregate.base import SEVERITY_NUMBER
from security_checker.models.enums import Agreement
from security_checker.models.verdict import ReviewVerdict


def compute_agreement(valid: list[ReviewVerdict]) -> Agreement:
    """vulnerable の割合と severity の幅の 2 軸で決める."""
    if len(valid) < 2:
        # 「1 モデルの合意」を high agreement と偽装しない (§13.2)
        return Agreement.NOT_APPLICABLE

    vulnerable = [verdict for verdict in valid if verdict.vulnerable]
    vuln_ratio = len(vulnerable) / len(valid)
    numbers = [SEVERITY_NUMBER[verdict.severity] for verdict in vulnerable]
    spread = (max(numbers) - min(numbers)) if numbers else 0

    if vuln_ratio in (0.0, 1.0) and spread <= 1:
        return Agreement.HIGH
    if (vuln_ratio <= 0.25 or vuln_ratio >= 0.75) and spread <= 2:
        return Agreement.MEDIUM
    return Agreement.LOW
