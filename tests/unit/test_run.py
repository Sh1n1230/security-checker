"""Run オーケストレータのテスト (設計書 §3, §20.2)."""

from __future__ import annotations

import json

from security_checker.config.schema import Config
from security_checker.errors import ExitCode
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.report.json_writer import write_json
from security_checker.run import run_scan
from security_checker.testing.fakes import FakeScanner


def make_candidate(
    identifier: str, severity: Severity, path: str = "src/a.py", line: int = 1
) -> Candidate:
    return Candidate(
        id=identifier,
        scanner="fake",
        category=Category.SAST,
        rule_id="rules.x",
        title="t",
        message="m",
        location=Location(path=path, start_line=line, end_line=line),
        severity_reported=severity,
    )


async def test_candidates_are_sorted_and_deduped(tmp_path):
    shared = make_candidate("dup", Severity.LOW)
    scanners = [
        FakeScanner(
            "a",
            candidates=[make_candidate("m", Severity.MEDIUM), shared],
        ),
        FakeScanner(
            "b",
            candidates=[shared, make_candidate("c", Severity.CRITICAL)],
        ),
    ]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)

    ids = [candidate.id for candidate in outcome.report.candidates]
    assert ids == ["c", "m", "dup"]  # 重大度降順 + 重複排除
    assert outcome.report.coverage.candidates_total == 3


async def test_failed_scanner_produces_error_warning_and_exit_3(tmp_path):
    scanners = [
        FakeScanner("ok-one", candidates=[make_candidate("x", Severity.LOW)]),
        FakeScanner("broken", status=ScanStatus.FAILED, reason="exit 2", exit_code=2),
    ]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)

    assert outcome.decision.exit_code is ExitCode.EXECUTION_ERROR
    assert outcome.report.has_failed_scanner
    assert outcome.report.score.partial is True
    errors = [w for w in outcome.report.warnings if w.level == "error"]
    assert [w.source for w in errors] == ["broken"]


async def test_skipped_scanner_is_not_an_execution_error(tmp_path):
    scanners = [FakeScanner("absent", status=ScanStatus.SKIPPED, reason="未導入")]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)

    assert outcome.decision.exit_code is ExitCode.OK
    assert outcome.report.coverage.scanners_skipped == 1
    assert outcome.report.score.partial is True  # 満点に見せない
    assert [w.level for w in outcome.report.warnings] == ["warn"]


async def test_scanner_exception_is_contained(tmp_path):
    """1 つのスキャナの内部エラーで全体を落とさない (§20.2)."""
    scanners = [
        FakeScanner("boom", raises=RuntimeError("想定外")),
        FakeScanner("fine", candidates=[make_candidate("x", Severity.HIGH)]),
    ]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)

    statuses = {run.scanner: run.status for run in outcome.report.scanners}
    assert statuses == {"boom": ScanStatus.FAILED, "fine": ScanStatus.OK}
    assert len(outcome.report.candidates) == 1


async def test_report_json_roundtrip(tmp_path):
    scanners = [FakeScanner("a", candidates=[make_candidate("x", Severity.HIGH)])]
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=scanners)
    path = write_json(outcome.report, outcome.output_dir)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["tool"] == "security-checker"
    assert payload["run_id"] == outcome.report.run_id
    assert payload["severity_counts"]["high"] == 1
    assert payload["coverage"]["candidates_reviewed"] == 0


async def test_raw_dir_is_created(tmp_path):
    outcome = await run_scan(Config(), tmp_path, base_dir=tmp_path, scanners=[])
    assert (outcome.output_dir / "raw").is_dir()
    assert outcome.report.score.partial is False
    assert outcome.report.coverage.scanners_total == 0


async def test_unimplemented_scanners_are_reported_as_config_warning(tmp_path):
    config = Config.model_validate({"scanners": {"osv": {"enabled": True}}})
    outcome = await run_scan(config, tmp_path, base_dir=tmp_path)
    messages = [w.message for w in outcome.report.warnings if w.source == "config"]
    assert any("osv" in message for message in messages)
