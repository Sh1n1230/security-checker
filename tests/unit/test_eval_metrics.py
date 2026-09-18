"""評価指標の表駆動テスト (設計書 §27.2).

主指標は Recall。「判断を保留しただけで数字が良く見える」ことがないよう、
review_required を TP にも FN にも数えないことを固定する。
"""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.eval.metrics import CaseOutcome, evaluate_outcomes
from security_checker.models.enums import FindingStatus, Severity


def outcome(
    case_id: str = "c1",
    *,
    expected: bool = True,
    status: FindingStatus = FindingStatus.CONFIRMED,
    severity: Severity = Severity.HIGH,
    expected_severity: Severity = Severity.HIGH,
    expected_cwe: list[str] | None = None,
    cwe: list[str] | None = None,
    **overrides: Any,
) -> CaseOutcome:
    payload: dict[str, Any] = {
        "case_id": case_id,
        "expected_vulnerable": expected,
        "expected_severity": expected_severity,
        "expected_cwe": expected_cwe or [],
        "status": status,
        "severity": severity,
        "cwe": cwe or [],
    }
    payload.update(overrides)
    return CaseOutcome(**payload)


def test_perfect_run():
    metrics = evaluate_outcomes(
        [
            outcome("tp", expected=True, status=FindingStatus.CONFIRMED),
            outcome("tn", expected=False, status=FindingStatus.FALSE_POSITIVE),
        ]
    )
    assert metrics.recall == 1.0
    assert metrics.precision == 1.0
    assert metrics.f1 == 1.0
    assert metrics.fp_reduction == 1.0
    assert metrics.missed_true_positives == 0


def test_a_missed_true_positive_is_counted_and_listed():
    """見逃しは数字だけでなく、必ず実物を列挙する (§27.2)."""
    metrics = evaluate_outcomes(
        [
            outcome("found", expected=True, status=FindingStatus.LIKELY),
            outcome("missed", expected=True, status=FindingStatus.FALSE_POSITIVE),
        ]
    )
    assert metrics.recall == pytest.approx(0.5)
    assert metrics.missed_true_positives == 1
    assert metrics.missed_case_ids == ["missed"]


def test_review_required_is_neither_a_hit_nor_a_miss():
    """判断を保留しただけで数字が良く見えることがないようにする."""
    metrics = evaluate_outcomes(
        [outcome("deferred", expected=True, status=FindingStatus.REVIEW_REQUIRED)]
    )
    assert metrics.true_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.deferred_positives == 1
    # 母数が 0 のときは 0.0 ではなく None (読み違えを防ぐ)
    assert metrics.recall is None
    assert metrics.review_required_rate == 1.0


def test_dismissing_everything_does_not_look_good():
    """全部 false_positive と言えば FP 削減率は満点になる. Recall がそれを暴く."""
    metrics = evaluate_outcomes(
        [
            outcome("p1", expected=True, status=FindingStatus.FALSE_POSITIVE),
            outcome("p2", expected=True, status=FindingStatus.FALSE_POSITIVE),
            outcome("n1", expected=False, status=FindingStatus.FALSE_POSITIVE),
        ]
    )
    assert metrics.fp_reduction == 1.0  # 一見よく見えるが
    assert metrics.recall == 0.0  # 主指標は最低
    assert metrics.missed_true_positives == 2


def test_false_positive_reduction_is_relative_to_the_scanner():
    """スキャナ単体なら陰性ケースは全部 FP だった、という基準で測る."""
    metrics = evaluate_outcomes(
        [
            outcome("n1", expected=False, status=FindingStatus.FALSE_POSITIVE),
            outcome("n2", expected=False, status=FindingStatus.FALSE_POSITIVE),
            outcome("n3", expected=False, status=FindingStatus.CONFIRMED),
            outcome("n4", expected=False, status=FindingStatus.REVIEW_REQUIRED),
        ]
    )
    # 4 件中 1 件だけ報告に残った
    assert metrics.fp_reduction == pytest.approx(0.75)
    assert metrics.false_positives == 1


def test_errors_are_excluded_from_grading_but_reported():
    metrics = evaluate_outcomes(
        [
            outcome("ok", expected=True, status=FindingStatus.CONFIRMED),
            outcome("broken", expected=True, status=FindingStatus.ERROR),
        ]
    )
    assert metrics.errors == 1
    assert metrics.cases == 2
    assert metrics.recall == 1.0  # 採点対象からは外す


def test_severity_mae_and_cwe_match_rate():
    metrics = evaluate_outcomes(
        [
            outcome(
                "a",
                expected=True,
                status=FindingStatus.CONFIRMED,
                expected_severity=Severity.CRITICAL,
                severity=Severity.HIGH,
                expected_cwe=["CWE-78"],
                cwe=["CWE-78"],
            ),
            outcome(
                "b",
                expected=True,
                status=FindingStatus.CONFIRMED,
                expected_severity=Severity.HIGH,
                severity=Severity.HIGH,
                expected_cwe=["CWE-89"],
                cwe=["CWE-79"],
            ),
        ]
    )
    assert metrics.severity_mae == pytest.approx(0.5)
    assert metrics.cwe_match_rate == pytest.approx(0.5)


def test_cost_is_not_summed_when_a_transport_cannot_report_it():
    """測れないものを測ったふりをしない (§24.3)."""
    metrics = evaluate_outcomes(
        [
            outcome("a", usd=0.01, cost_known=True),
            outcome("b", usd=None, cost_known=False),
        ]
    )
    assert metrics.cost_known is False
    assert metrics.total_usd is None


def test_empty_input_is_not_an_error():
    assert evaluate_outcomes([]).cases == 0
