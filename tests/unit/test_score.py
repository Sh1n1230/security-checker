"""スコア算出のテスト (設計書 §17.3)."""

from __future__ import annotations

from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.models.report import ScannerRun
from security_checker.policy.score import compute_score, rank_for


def make_candidate(severity: Severity, category: Category = Category.SAST) -> Candidate:
    return Candidate(
        id=f"{severity.value}-{category.value}-{id(severity)}",
        scanner="semgrep",
        category=category,
        rule_id="r",
        title="t",
        message="m",
        severity_reported=severity,
    )


def ok_run(name: str = "semgrep") -> ScannerRun:
    return ScannerRun(scanner=name, category=Category.SAST, status=ScanStatus.OK)


def test_no_findings_is_full_score():
    score = compute_score([], [ok_run()])
    assert score.value == 100
    assert score.rank == "A"
    assert score.partial is False


def test_deductions_by_severity():
    candidates = [make_candidate(Severity.CRITICAL), make_candidate(Severity.MEDIUM)]
    score = compute_score(candidates, [ok_run()])
    assert score.value == 100 - 20 - 3


def test_category_cap_is_applied():
    candidates = [make_candidate(Severity.CRITICAL) for _ in range(10)]
    score = compute_score(candidates, [ok_run()])
    assert score.deductions["sast"] == 40
    assert score.value == 60


def test_caps_are_per_category():
    candidates = [make_candidate(Severity.CRITICAL) for _ in range(10)]
    candidates += [make_candidate(Severity.CRITICAL, Category.SECRET) for _ in range(10)]
    score = compute_score(candidates, [ok_run()])
    assert score.value == 20


def test_skipped_scanner_marks_partial():
    """v1 の構造的欠陥: 未導入でも満点に見えてしまう. partial で必ず可視化する."""
    runs = [
        ok_run(),
        ScannerRun(scanner="gitleaks", category=Category.SECRET, status=ScanStatus.SKIPPED),
    ]
    score = compute_score([], runs)
    assert score.value == 100
    assert score.partial is True
    assert score.partial_reason is not None
    assert "gitleaks" in score.partial_reason


def test_failed_scanner_marks_partial():
    runs = [ScannerRun(scanner="semgrep", category=Category.SAST, status=ScanStatus.FAILED)]
    score = compute_score([], runs)
    assert score.partial is True
    assert "失敗" in (score.partial_reason or "")


def test_rank_boundaries():
    assert rank_for(90) == "A"
    assert rank_for(89) == "B"
    assert rank_for(70) == "B"
    assert rank_for(69) == "C"
    assert rank_for(50) == "C"
    assert rank_for(49) == "D"
