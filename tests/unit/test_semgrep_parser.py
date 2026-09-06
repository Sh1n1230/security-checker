"""semgrep パーサのゴールデン / 異常系テスト (設計書 §25.1)."""

from __future__ import annotations

from pathlib import Path

from security_checker.models.enums import Category, Severity
from security_checker.scanners.semgrep import parse_semgrep

ROOT = Path("/repo")


def test_basic_normalization(raw_fixture):
    candidates, warnings = parse_semgrep(raw_fixture("semgrep_basic.json"), ROOT)

    assert warnings == []
    assert len(candidates) == 2
    first = candidates[0]
    assert first.scanner == "semgrep"
    assert first.category is Category.SAST
    assert first.severity_reported is Severity.HIGH
    assert first.confidence_reported == 0.9
    assert first.cwe == ["CWE-78"]
    assert first.title == "subprocess-injection"
    assert first.location is not None
    assert first.location.path == "app.py"
    assert first.location.start_line == 16
    assert first.references


def test_empty_results(raw_fixture):
    candidates, warnings = parse_semgrep(raw_fixture("semgrep_empty.json"), ROOT)
    assert candidates == []
    assert warnings == []


def test_broken_entries_are_reported_not_swallowed(raw_fixture):
    candidates, warnings = parse_semgrep(
        raw_fixture("semgrep_broken.json"), ROOT, exclude=["**/vendor/**"]
    )

    # 壊れた 2 件は落ちるが、残りは処理を続ける
    rule_ids = [candidate.rule_id for candidate in candidates]
    assert rule_ids == ["rules.no-start-line", "rules.unknown-severity"]
    assert "rules.excluded" not in rule_ids  # exclude が効いている

    joined = " / ".join(warnings)
    assert "results[0]" in joined
    assert "results[1]" in joined
    assert "Rule ファイルの読み込みに失敗しました" in joined


def test_broken_entry_defaults(raw_fixture):
    candidates, _ = parse_semgrep(raw_fixture("semgrep_broken.json"), ROOT)
    by_rule = {candidate.rule_id: candidate for candidate in candidates}

    no_line = by_rule["rules.no-start-line"]
    assert no_line.location is not None
    assert no_line.location.start_line == 0
    assert no_line.cwe == []  # "壊れた形式" からは CWE を取り出せない

    unknown = by_rule["rules.unknown-severity"]
    assert unknown.severity_reported is Severity.LOW  # 未知の severity は最小に倒す
    assert unknown.location is not None
    assert not unknown.location.path.startswith("/")  # 絶対パスを残さない


def test_non_dict_payload_is_flagged():
    candidates, warnings = parse_semgrep(["結果ではない"], ROOT)
    assert candidates == []
    assert warnings

    candidates, warnings = parse_semgrep({}, ROOT)
    assert candidates == []
    assert "results" in warnings[0]
