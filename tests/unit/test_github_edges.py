"""GitHub 連携の境界: API の失敗の読み方・diff の解析・サマリの上限 (設計書 §21)."""

from __future__ import annotations

import subprocess
import time
from typing import Any

import httpx
import pytest

from security_checker.config.schema import GithubConfig
from security_checker.github import pr as pr_module
from security_checker.github.client import (
    GithubClient,
    GithubError,
    PullRequestContext,
    _error_message,
    _rate_limit_wait,
    context_from_env,
)
from security_checker.github.comment import (
    MAX_BODY_CHARS,
    MAX_SUMMARY_FINDINGS,
    _fit_body,
    plan_inline,
    render_summary,
)
from security_checker.github.pr import DiffError, DiffScope, parse_unified_diff
from security_checker.models.enums import Category, FindingStatus, Severity
from security_checker.models.finding import AggregationDetail
from security_checker.models.report import ReviewerRun, TargetInfo
from security_checker.models.verdict import Usage, VerdictStatus
from tests.factories import make_candidate, make_finding, make_report, make_verdict

PR = PullRequestContext(repository="o/r", number=7, head_sha="abc")


# --- client -----------------------------------------------------------------------


def test_broken_event_payload_falls_back_to_arguments(tmp_path):
    event = tmp_path / "event.json"
    event.write_text("{broken", encoding="utf-8")
    context = context_from_env(
        {"GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": "o/r"}, number=7
    )
    assert (context.repository, context.number, context.head_sha) == ("o/r", 7, None)


def test_connection_failure_is_a_github_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with (
        GithubClient("t", transport=httpx.MockTransport(handler)) as client,
        pytest.raises(GithubError, match="GitHub API に接続できません"),
    ):
        client.issue_comments(PR)


def test_head_sha_is_read_from_the_pull_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/o/r/pulls/7"
        return httpx.Response(200, json={"head": {"sha": "deadbeef"}})

    with GithubClient("t", transport=httpx.MockTransport(handler)) as client:
        assert client.head_sha(PR) == "deadbeef"


def test_error_message_of_a_non_json_body_is_its_first_200_characters():
    assert _error_message(httpx.Response(502, text="x" * 500)) == "x" * 200
    assert _error_message(httpx.Response(500, json=["not", "an", "object"])) == ""


def test_rate_limit_wait_reads_each_header_and_never_guesses_a_short_wait():
    assert _rate_limit_wait(httpx.Response(404)) is None
    assert _rate_limit_wait(httpx.Response(403, headers={"retry-after": "soon"})) == float("inf")
    reset = str(int(time.time()) + 30)
    wait = _rate_limit_wait(
        httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset})
    )
    assert wait is not None
    assert 25 <= wait <= 30
    without_reset = httpx.Response(403, headers={"x-ratelimit-remaining": "0"})
    assert _rate_limit_wait(without_reset) == float("inf")
    assert _rate_limit_wait(httpx.Response(403, json={"message": "forbidden"})) is None


# --- diff の解析 ------------------------------------------------------------------


def test_a_located_scanner_category_without_a_location_does_not_touch_the_diff():
    scope = DiffScope(base="main", added={}, changed_files=frozenset({"a.py"}))
    candidate = make_candidate(location=None, category=Category.SECRET)
    assert scope.touches(candidate) is False


def test_headers_with_broken_quoting_are_skipped():
    assert pr_module._strip_prefix('"b/unterminated') is None
    assert pr_module._header_path('"a/unterminated') is None
    assert pr_module._unquote_c('"no closing quote') is None


def test_header_of_a_rename_uses_the_new_side():
    assert pr_module._header_path("a/old name.py b/new name.py") == "new name.py"
    assert pr_module._header_path("not a git header") is None


def test_rename_is_tracked_under_the_new_path():
    diff = "\n".join(
        [
            "diff --git a/old.py b/new.py",
            "similarity index 90%",
            "rename from old.py",
            "rename to new.py",
            "--- a/old.py",
            "+++ b/new.py",
            "@@ -1,0 +2,1 @@",
            "+x = 1",
        ]
    )
    added, changed = parse_unified_diff(diff)
    assert "new.py" in changed
    assert added["new.py"] == ((2, 2),)


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (PermissionError(13, "denied"), "git を起動できません (PermissionError)"),
        (subprocess.TimeoutExpired(cmd="git", timeout=1), "秒以内に終わりませんでした"),
    ],
)
def test_git_failures_are_diff_errors(tmp_path, monkeypatch, error, message):
    def boom(*args: Any, **kwargs: Any) -> None:
        raise error

    monkeypatch.setattr("subprocess.run", boom)
    with pytest.raises(DiffError) as info:
        pr_module._git(tmp_path, "status")
    assert message in str(info.value)


def test_unreadable_new_file_counts_as_zero_lines(tmp_path):
    assert pr_module._count_lines(tmp_path / "missing.py") == 0
    (tmp_path / "bin").write_bytes(b"\0\1\2")
    assert pr_module._count_lines(tmp_path / "bin") == 0
    (tmp_path / "a.py").write_text("a\nb", encoding="utf-8")
    assert pr_module._count_lines(tmp_path / "a.py") == 2


# --- サマリ -----------------------------------------------------------------------


def _many_findings(count: int) -> Any:
    candidates = [make_candidate(f"c{index}", line=index + 1) for index in range(count)]
    return make_report(candidates, [make_finding(c, FindingStatus.CONFIRMED) for c in candidates])


def test_summary_lists_at_most_the_limit_and_says_how_many_are_left():
    text = render_summary(_many_findings(MAX_SUMMARY_FINDINGS + 4))
    assert "_ほか 4 件は full report を参照_" in text


def test_scan_only_summary_caps_the_candidate_table():
    candidates = [make_candidate(f"c{index}") for index in range(MAX_SUMMARY_FINDINGS + 2)]
    text = render_summary(make_report(candidates))
    assert "_ほか 2 件_" in text
    assert "スキャナのみ・LLM による判定なし" in text


def test_reviewed_run_without_findings_does_not_claim_scanner_only():
    report = make_report(
        [make_candidate()],
        reviewers=[ReviewerRun(name="r1", model="m", transport="http")],
    )
    text = render_summary(report)
    assert "候補 1 件" in text
    assert "スキャナのみ" not in text


def test_summary_names_reviewers_strategy_diff_range_and_cost():
    candidate = make_candidate()
    finding = make_finding(
        candidate,
        FindingStatus.REVIEW_REQUIRED,
        aggregation=AggregationDetail(strategy="consensus", votes_vulnerable=1, votes_total=2),
        verdicts=[
            make_verdict("r1"),
            make_verdict("r2", status=VerdictStatus.PROVIDER_ERROR, vulnerable=False),
        ],
    )
    report = make_report(
        [candidate],
        [finding],
        reviewers=[ReviewerRun(name="r1", model="m", transport="http")],
        target=TargetInfo(root="repo", mode="diff", base="origin/main", changed_files=3),
        usage=Usage(estimated_usd=0.0123, cost_known=True),
    )
    text = render_summary(report)
    assert "Reviewers: `r1` · Aggregation: consensus" in text
    assert "範囲: `origin/main` との差分 (3 ファイル)" in text
    assert "$0.0123" in text
    # 失敗した Reviewer の判定は「判断が分かれた」内訳に並べない
    assert "r2" not in text.split("REVIEW REQUIRED", 1)[1]


def test_a_single_block_over_the_body_limit_is_cut_at_a_line_without_an_open_fence():
    # 区切り (---) が 1 つも無いまま上限を超える本文. 開いたフェンスを残すと以降の表示が壊れる
    body = "## summary\n```python\n" + ("x = 1\n" * (MAX_BODY_CHARS // 4))
    text = _fit_body(body, footer="<sub>footer</sub>")
    assert len(text) <= MAX_BODY_CHARS
    assert "```" not in text
    assert text.endswith("<sub>footer</sub>\n")


def test_inline_plan_is_empty_for_a_status_that_cannot_be_commented():
    candidate = make_candidate(line=3)
    report = make_report([candidate], [make_finding(candidate, FindingStatus.CONFIRMED)])
    settings = GithubConfig(inline_min_status=FindingStatus.FALSE_POSITIVE)
    plan = plan_inline(report, settings, {"src/app.py": [(1, 10)]}, set())
    assert plan.comments == []
    assert Severity.HIGH in {f.severity for f in report.findings}
