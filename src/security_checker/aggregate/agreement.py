"""一致度の算出 (設計書 §15).

評価者が 2〜5 人程度では Fleiss' kappa は不安定なので採用しない。
agreement は「正しさ」ではないため、confidence を **引き下げる方向にのみ** 強く効かせる。
"""

from __future__ import annotations

from security_checker.aggregate.base import SEVERITY_NUMBER
from security_checker.models.enums import Agreement
from security_checker.models.verdict import ReviewVerdict

# Minimum number of valid verdicts required to compute agreement (§13.2).
_MIN_VERDICTS_FOR_AGREEMENT = 2

# Vulnerable-ratio thresholds for agreement bands (設計書 §15).
_HIGH_AGREEMENT_VULN_RATIO_EXTREMES = (0.0, 1.0)
_MEDIUM_AGREEMENT_VULN_RATIO_LOW = 0.25
_MEDIUM_AGREEMENT_VULN_RATIO_HIGH = 0.75

# Maximum severity-number spread allowed for each agreement level.
_HIGH_AGREEMENT_MAX_SPREAD = 1
_MEDIUM_AGREEMENT_MAX_SPREAD = 2


def compute_agreement(valid: list[ReviewVerdict]) -> Agreement:
    """vulnerable の割合と severity の幅の 2 軸で決める."""
    if len(valid) < _MIN_VERDICTS_FOR_AGREEMENT:
        # 「1 モデルの合意」を high agreement と偽装しない (§13.2)
        return Agreement.NOT_APPLICABLE

    vulnerable = [verdict for verdict in valid if verdict.vulnerable]
    vuln_ratio = len(vulnerable) / len(valid)
    numbers = [SEVERITY_NUMBER[verdict.severity] for verdict in vulnerable]
    spread = (max(numbers) - min(numbers)) if numbers else 0

    if vuln_ratio in _HIGH_AGREEMENT_VULN_RATIO_EXTREMES and spread <= _HIGH_AGREEMENT_MAX_SPREAD:
        return Agreement.HIGH
    if (
        vuln_ratio <= _MEDIUM_AGREEMENT_VULN_RATIO_LOW
        or vuln_ratio >= _MEDIUM_AGREEMENT_VULN_RATIO_HIGH
    ) and spread <= _MEDIUM_AGREEMENT_MAX_SPREAD:
        return Agreement.MEDIUM
    return Agreement.LOW
