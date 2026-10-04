"""ターミナル出力の回帰テスト (設計書 §18.2).

「0 件」と「検査できていない」が同じ見た目にならないことを確認する。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from security_checker.config.schema import Config
from security_checker.errors import ExitCode
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.models.report import Report
from security_checker.policy.engine import PolicyDecision
from security_checker.report import terminal
from security_checker.run import run_scan
from security_checker.testing.fakes import FakeScanner


def capture(report: Report, decision: PolicyDecision, output_dir: Path) -> str:
    console = Console(width=120, force_terminal=False, no_color=True)
    with console.capture() as captured:
        terminal.render(report, decision, output_dir, console=console)
    return captured.get()


@pytest.fixture
def candidate() -> Candidate:
    return Candidate(
        id="x",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="rules.dangerous",
        title="dangerous-eval",
        message="m",
        location=Location(path="src/app.py", start_line=42, end_line=42),
        severity_reported=Severity.HIGH,
    )


async def test_renders_candidates_and_score(tmp_path, candidate):
    outcome = await run_scan(
        Config(),
        tmp_path,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate])],
    )
    output = capture(outcome.report, outcome.decision, outcome.output_dir)

    assert "dangerous-eval" in output
    assert "src/app.py:42" in output
    assert "HIGH" in output
    assert "score 90/100" in output
    assert "policy.fail_on" in output  # 違反理由を表示する


async def test_failed_scanner_is_visible_and_score_is_marked_partial(tmp_path):
    scanners = [FakeScanner("semgrep", status=ScanStatus.FAILED, reason="exit 2", exit_code=2)]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)
    output = capture(outcome.report, outcome.decision, outcome.output_dir)

    assert "failed" in output
    assert "partial" in output
    assert "検出なし" in output  # 0 件表示は出るが partial 表示と併記される


async def test_skipped_scanner_is_distinguished_from_zero_findings(tmp_path):
    scanners = [FakeScanner("gitleaks", status=ScanStatus.SKIPPED, reason="未導入です")]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)
    output = capture(outcome.report, outcome.decision, outcome.output_dir)

    assert "skipped" in output
    assert "未導入です" in output


async def test_many_candidates_are_truncated_with_notice(tmp_path):
    candidates = [
        Candidate(
            id=f"c{index}",
            scanner="semgrep",
            category=Category.SAST,
            rule_id="r",
            title=f"rule-{index}",
            message="m",
            location=Location(path=f"src/f{index}.py", start_line=1, end_line=1),
            severity_reported=Severity.LOW,
        )
        for index in range(terminal.MAX_ROWS + 5)
    ]
    outcome = await run_scan(
        Config(),
        tmp_path,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=candidates)],
    )
    output = capture(outcome.report, outcome.decision, outcome.output_dir)

    assert "ほか 5 件" in output


async def test_no_scanners_configured(tmp_path):
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=[])
    output = capture(outcome.report, outcome.decision, outcome.output_dir)
    assert "有効なスキャナがありません" in output


# --- レビュー後の表示 (§18.2) ----------------------------------------------------------


def reviewed_report(**overrides: Any) -> Report:
    from security_checker.models.enums import FindingStatus
    from security_checker.models.finding import SuppressionReason
    from security_checker.models.report import ReviewerRun, SuppressedCandidate
    from security_checker.models.verdict import Usage
    from tests.factories import make_candidate, make_finding, make_report, make_verdict

    confirmed = make_candidate("c1", path="a.py")
    split = make_candidate("c2", path="b.py")
    pending = make_candidate("c3", path="c.py")
    fp = make_candidate("c4", path="d.py")
    findings = [
        make_finding(confirmed, FindingStatus.CONFIRMED, summary="確定した問題"),
        make_finding(
            split,
            FindingStatus.REVIEW_REQUIRED,
            summary="割れた問題",
            verdicts=[make_verdict("alpha", "c2"), make_verdict("beta", "c2", vulnerable=False)],
        ),
        make_finding(pending, FindingStatus.NOT_REVIEWED, verdicts=[]),
        make_finding(fp, FindingStatus.FALSE_POSITIVE),
    ]
    payload: dict[str, Any] = {
        "reviewers": [
            ReviewerRun(
                name="alpha",
                calls=4,
                usage=Usage(input_tokens=10, output_tokens=5, estimated_usd=0.001),
            ),
            ReviewerRun(name="beta", calls=4, verdicts_error=1, disabled_reason="401"),
        ],
        "usage": Usage(input_tokens=10, output_tokens=5, estimated_usd=0.001),
        "suppressed": [
            SuppressedCandidate(candidate=make_candidate("s1"), reason=SuppressionReason.BASELINE)
        ],
    }
    payload.update(overrides)
    return make_report([confirmed, split, pending, fp], findings, **payload)


def test_review_required_comes_right_after_confirmed(tmp_path):
    output = capture(reviewed_report(), PolicyDecision(exit_code=ExitCode.OK, reasons=[]), tmp_path)
    assert output.index("CONFIRMED") < output.index("REVIEW REQUIRED")
    assert "確定した問題" in output and "割れた問題" in output
    assert "alpha: high (0.90)" in output and "beta: not vulnerable" in output
    assert "Attack path: POST /upload" in output
    assert "未レビュー" in output
    assert "Suppressed" in output and "baseline 1" in output
    assert "無効化" in output and "error 1" in output
    assert "cost: $0.0010" in output
    assert "false_positive 1" in output


def test_many_findings_are_truncated(tmp_path):
    from security_checker.models.enums import FindingStatus
    from tests.factories import make_candidate, make_finding, make_report

    candidates = [
        make_candidate(f"c{i}", path=f"f{i}.py") for i in range(terminal.MAX_FINDING_PANELS + 3)
    ]
    report = make_report(candidates, [make_finding(c, FindingStatus.CONFIRMED) for c in candidates])
    output = capture(report, PolicyDecision(exit_code=ExitCode.OK, reasons=[]), tmp_path)
    assert "ほか 3 件" in output


def test_only_false_positives_says_nothing_to_report(tmp_path):
    from security_checker.models.enums import FindingStatus
    from tests.factories import make_candidate, make_finding, make_report

    c = make_candidate()
    output = capture(
        make_report([c], [make_finding(c, FindingStatus.FALSE_POSITIVE)]),
        PolicyDecision(exit_code=ExitCode.OK, reasons=[]),
        tmp_path,
    )
    assert "報告対象なし" in output


def test_unknown_cost_and_many_warnings(tmp_path):
    from security_checker.models.report import ReportWarning
    from security_checker.models.verdict import Usage

    report = reviewed_report(
        usage=Usage(cost_known=False),
        warnings=[ReportWarning(level="warn", source="x", message=f"w{i}") for i in range(7)],
    )
    output = capture(report, PolicyDecision(exit_code=ExitCode.OK, reasons=[]), tmp_path)
    assert "cost: unknown" in output
    assert "ほか 2 件の警告" in output


def test_diff_mode_label(tmp_path):
    from security_checker.models.report import TargetInfo
    from tests.factories import make_report

    report = make_report(
        [], target=TargetInfo(root="/r", mode="diff", changed_files=3, base="origin/main")
    )
    output = capture(report, PolicyDecision(exit_code=ExitCode.OK, reasons=[]), tmp_path)
    assert "diff mode vs origin/main, 3 files" in output
