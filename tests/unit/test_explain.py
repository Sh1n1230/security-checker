"""explain: 1 件の候補について、判定と呼び出し記録をたどる (設計書 §24.4)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from security_checker.errors import ConfigError
from security_checker.models.enums import FindingStatus
from security_checker.models.finding import AggregationDetail, SuppressionReason
from security_checker.models.report import SuppressedCandidate
from security_checker.observability.explain import explain, load_report, render
from tests.factories import make_candidate, make_finding, make_report

if TYPE_CHECKING:
    from pathlib import Path


def _write_call(trace: Path, name: str, payload: dict[str, object] | str) -> None:
    calls = trace / "calls"
    calls.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (calls / name).write_text(text, encoding="utf-8")


def test_missing_report_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="レポートが見つかりません"):
        load_report(tmp_path / "report.json")


def test_broken_report_is_a_config_error(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="レポートを読めません"):
        load_report(path)


def test_ambiguous_prefix_lists_the_matching_ids():
    report = make_report([make_candidate("abc1"), make_candidate("abc2")])
    with pytest.raises(ConfigError, match="abc1, abc2"):
        explain(report, "abc")


def test_exact_id_wins_over_longer_ids_with_the_same_prefix():
    report = make_report([make_candidate("abc"), make_candidate("abc2")])
    assert explain(report, "abc").candidate.id == "abc"


def test_suppressed_and_outside_diff_candidates_say_why_they_were_not_reviewed():
    suppressed = make_candidate("s1")
    outside = make_candidate("o1")
    report = make_report(
        [],
        suppressed=[
            SuppressedCandidate(
                candidate=suppressed, reason=SuppressionReason.BASELINE, note="既知の指摘"
            )
        ],
        outside_diff=[outside],
    )
    text = render(explain(report, "s1"))
    assert f"抑制: {SuppressionReason.BASELINE.value} (既知の指摘)" in text
    assert "呼び出し記録 (trace) が見つかりません" in text
    assert "diff の範囲外のためレビューしていません" in render(explain(report, "o1"))


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ({"judge": {"reviewer": "j", "rationale": "根拠"}}, "Judge (j): 根拠"),
        ({"fallback_used": "judge が失敗"}, "Judge は使われませんでした: judge が失敗"),
        (
            {"demoted_by_min_confidence": {"from": "likely", "confidence": 0.3, "threshold": 0.5}},
            (
                "likely から review_required に落としました: "
                "確信度 0.3 が policy.min_confidence (0.5) 未満"
            ),
        ),
    ],
)
def test_judge_outcome_is_rendered(detail, expected):
    candidate = make_candidate("c1")
    finding = make_finding(
        candidate,
        FindingStatus.CONFIRMED,
        aggregation=AggregationDetail(
            strategy="judge", votes_vulnerable=1, votes_total=2, detail=detail
        ),
    )
    assert expected in render(explain(make_report([candidate], [finding]), "c1"))


def test_calls_are_read_from_the_trace_next_to_the_report(tmp_path):
    candidate = make_candidate("c1")
    report = make_report([candidate], run_id="R9")
    trace = tmp_path / "trace" / "R9"
    _write_call(trace, "0001.json", "{broken")  # 壊れた記録は飛ばす
    _write_call(trace, "0002.json", {"candidate_id": "other"})
    _write_call(
        trace,
        "0003.json",
        {
            "candidate_id": "c1",
            "reviewer": "r1",
            "degraded_to": "json_mode",
            "response": {"error": "HTTP 500"},
        },
    )
    result = explain(report, "c1", report_path=tmp_path / "report.json")
    assert [call["_file"] for call in result.calls] == ["0003.json"]
    text = render(result)
    assert "構造化出力を json_mode に降格" in text
    assert "エラー: HTTP 500" in text


def test_calls_are_read_with_both_old_and_new_file_names(tmp_path):
    """連番だけの古い名前と、Reviewer と候補 ID を含む新しい名前の両方を読む (#449)."""
    candidate = make_candidate("c1")
    report = make_report([candidate], run_id="R9")
    trace = tmp_path / "trace" / "R9"
    _write_call(trace, "0000.json", {"candidate_id": "c1", "reviewer": "r1"})
    _write_call(trace, "0001-r2-c1.json", {"candidate_id": "c1", "reviewer": "r2"})
    result = explain(report, "c1", report_path=tmp_path / "report.json")
    assert [call["_file"] for call in result.calls] == ["0000.json", "0001-r2-c1.json"]


def test_trace_without_calls_for_the_candidate_says_so(tmp_path):
    candidate = make_candidate("c1")
    report = make_report([candidate], run_id="R9")
    _write_call(tmp_path / "trace" / "R9", "0001.json", {"candidate_id": "other"})
    text = render(explain(report, "c1", report_path=tmp_path / "report.json"))
    assert "この候補の呼び出し記録はありません" in text
