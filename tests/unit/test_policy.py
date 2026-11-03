"""exit code 判定の表駆動テスト (設計書 §17.1)."""

from __future__ import annotations

import pytest

from security_checker.config.schema import PolicyConfig
from security_checker.errors import ExitCode
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding, SuppressionReason
from security_checker.models.report import (
    Coverage,
    Report,
    ReviewerRun,
    ScannerRun,
    Score,
    TargetInfo,
    utcnow,
)
from security_checker.policy.engine import evaluate
from tests.factories import make_candidate, make_report


def build_report(
    severities: list[Severity],
    statuses: list[ScanStatus],
    score_value: int = 100,
) -> Report:
    candidates = [
        Candidate(
            id=f"c{index}",
            scanner="semgrep",
            category=Category.SAST,
            rule_id="r",
            title="t",
            message="m",
            severity_reported=severity,
        )
        for index, severity in enumerate(severities)
    ]
    runs = [
        ScannerRun(scanner=f"s{index}", category=Category.SAST, status=status)
        for index, status in enumerate(statuses)
    ]
    now = utcnow()
    return Report(
        tool_version="test",
        run_id="run",
        started_at=now,
        finished_at=now,
        target=TargetInfo(root="."),
        scanners=runs,
        candidates=candidates,
        coverage=Coverage(
            scanners_total=len(runs),
            scanners_ok=sum(1 for s in statuses if s is ScanStatus.OK),
            scanners_skipped=sum(1 for s in statuses if s is ScanStatus.SKIPPED),
            scanners_failed=sum(1 for s in statuses if s is ScanStatus.FAILED),
            candidates_total=len(candidates),
        ),
        score=Score(value=score_value, rank="A", partial=False),
    )


@pytest.mark.parametrize(
    ("severities", "statuses", "fail_on", "strict", "expected"),
    [
        ([], [ScanStatus.OK], Severity.HIGH, True, ExitCode.OK),
        ([Severity.MEDIUM], [ScanStatus.OK], Severity.HIGH, True, ExitCode.OK),
        ([Severity.HIGH], [ScanStatus.OK], Severity.HIGH, True, ExitCode.POLICY_VIOLATION),
        ([Severity.CRITICAL], [ScanStatus.OK], Severity.HIGH, True, ExitCode.POLICY_VIOLATION),
        ([Severity.MEDIUM], [ScanStatus.OK], Severity.MEDIUM, True, ExitCode.POLICY_VIOLATION),
        # ツールが壊れた (3) は 脆弱性あり (1) より優先する
        ([Severity.CRITICAL], [ScanStatus.FAILED], Severity.HIGH, True, ExitCode.EXECUTION_ERROR),
        # --no-strict なら失敗しても実行エラーにはしない
        ([], [ScanStatus.FAILED], Severity.HIGH, False, ExitCode.OK),
        # skipped は failed と区別する (未導入は実行エラーではない)
        ([], [ScanStatus.SKIPPED], Severity.HIGH, True, ExitCode.OK),
        ([Severity.CRITICAL], [ScanStatus.OK], Severity.NONE, True, ExitCode.OK),
    ],
)
def test_exit_codes(severities, statuses, fail_on, strict, expected):
    report = build_report(severities, statuses)
    decision = evaluate(report, PolicyConfig(fail_on=fail_on, strict=strict))
    assert decision.exit_code is expected


def test_min_score_violation():
    report = build_report([], [ScanStatus.OK], score_value=40)
    decision = evaluate(report, PolicyConfig(fail_on=Severity.NONE, min_score=70))
    assert decision.exit_code is ExitCode.POLICY_VIOLATION
    assert "スコア" in decision.reasons[0]


def test_reasons_are_reported():
    report = build_report([Severity.CRITICAL], [ScanStatus.OK])
    decision = evaluate(report, PolicyConfig())
    assert decision.failed
    assert "policy.fail_on" in decision.reasons[0]


# --- レビューが最後まで行われなかった run (#159) --------------------------------


def _finding(status: FindingStatus, **overrides: object) -> Finding:
    candidate = make_candidate()
    return Finding(candidate=candidate, status=status, severity=Severity.CRITICAL, **overrides)


@pytest.mark.parametrize(
    ("findings", "overrides"),
    [
        ([_finding(FindingStatus.NOT_REVIEWED)], {}),
        ([_finding(FindingStatus.ERROR)], {}),
        ([_finding(FindingStatus.FALSE_POSITIVE)], {"stopped_reason": "予算を超えました"}),
        (
            [_finding(FindingStatus.REVIEW_REQUIRED)],
            {"reviewers": [ReviewerRun(name="r2", disabled_reason="401 Unauthorized")]},
        ),
    ],
)
def test_strict_treats_an_incomplete_review_as_an_execution_error(findings, overrides):
    report = make_report([make_candidate()], findings, **overrides)
    assert evaluate(report, PolicyConfig(strict=True)).exit_code is ExitCode.EXECUTION_ERROR
    # strict でなければレビュー済みの結果で判定する。exit は変えない
    assert evaluate(report, PolicyConfig(strict=False)).exit_code is ExitCode.OK


def test_all_reasons_for_an_incomplete_review_are_listed():
    report = make_report(
        [make_candidate()],
        [_finding(FindingStatus.NOT_REVIEWED)],
        stopped_reason="予算を超えました",
        reviewers=[ReviewerRun(name="r2", disabled_reason="401 Unauthorized")],
    )
    reasons = evaluate(report, PolicyConfig(strict=True)).reasons
    assert len(reasons) == 3
    assert any("r2" in reason for reason in reasons)
    assert any("予算を超えました" in reason for reason in reasons)


def test_a_suppressed_not_reviewed_candidate_is_not_incomplete():
    finding = _finding(FindingStatus.NOT_REVIEWED, suppressed=SuppressionReason.BASELINE)
    report = make_report([make_candidate()], [finding])
    assert evaluate(report, PolicyConfig(strict=True)).exit_code is ExitCode.OK
