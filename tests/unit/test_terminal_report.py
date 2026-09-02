"""ターミナル出力の回帰テスト (設計書 §18.2).

「0 件」と「検査できていない」が同じ見た目にならないことを確認する。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from security_checker.config.schema import Config
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
