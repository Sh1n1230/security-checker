"""E2E: 性質の異なる transport を混ぜた複数 Reviewer (設計書 §13.1, §15, §32 の P3).

P3 の完了条件そのもの:
  **異なる transport の Reviewer 2 つで review_required が正しく出る。**

片方は `http` (ScriptedProvider で応答を差し替え)、もう片方は `process`
(実際に subprocess を起動する最小のスクリプト)。判断を割って、
「無理に 1 つの答えを出さない」ことをパイプライン全体で確かめる。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from security_checker.config.schema import Config, ReviewerConfig
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Agreement, Category, FindingStatus, Severity
from security_checker.providers.registry import build_process_provider
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup, run_review
from security_checker.testing import FakeScanner, ScriptedProvider, verdict_payload

#: stdin を読み、与えられた verdict を散文で包んで stdout に返すだけのコマンド。
#: 実在のコマンドを模したものではなく、§9.7 の契約だけを満たす最小の実装。
REVIEWER_SCRIPT = (
    "import json,sys;"
    "sys.stdin.read();"
    "print('判定です:');"
    "print(json.dumps(json.loads(sys.argv[1]), ensure_ascii=False))"
)


def process_command(**verdict_overrides: Any) -> list[str]:
    return [sys.executable, "-c", REVIEWER_SCRIPT, json.dumps(verdict_payload(**verdict_overrides))]


def candidate() -> Candidate:
    return Candidate(
        id="sast-1",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="rules.sql-injection",
        title="sql-injection",
        message="文字列連結でクエリを組み立てています",
        location=Location(path="db.py", start_line=8, end_line=8),
        severity_reported=Severity.HIGH,
        cwe=["CWE-89"],
    )


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "db.py").write_text(
        "def find(cur, name):\n"
        "    # 呼び出し元で常に int にキャストされている、という主張もありうる\n"
        "    return cur.execute('select * from t where n = ' + name)\n",
        encoding="utf-8",
    )
    return root


def make_config(tmp_path: Path, **overrides: Any) -> Config:
    payload: dict[str, Any] = {
        "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
        "output": {"dir": str(tmp_path / "out")},
        "reviewers": [
            {
                "name": "http-reviewer",
                "transport": "http",
                "dialect": "openai_chat",
                "base_url": "http://stub/v1",
                "model": "stub",
            },
            {
                "name": "process-reviewer",
                "transport": "process",
                "command": ["unused-placeholder"],
                "timeout_s": 60,
            },
        ],
        "policy": {"strict": False},
    }
    payload.update(overrides)
    return Config.model_validate(payload)


def mixed_setup(
    http_script: list[Any],
    process_command_argv: list[str],
    *,
    weights: tuple[float, float] = (1.0, 1.0),
) -> ReviewerSetup:
    """http と process を 1 つずつ持つ Reviewer 構成を組み立てる."""
    http_config = ReviewerConfig(
        name="http-reviewer",
        transport="http",
        dialect="openai_chat",
        base_url="http://stub/v1",
        model="stub",
        weight=weights[0],
    )
    process_config = ReviewerConfig(
        name="process-reviewer",
        transport="process",
        command=process_command_argv,
        timeout_s=60,
        weight=weights[1],
    )

    http_provider = ScriptedProvider(http_script)
    process_provider = build_process_provider(process_config)
    return ReviewerSetup(
        runtimes=[
            build_runtime(
                Reviewer("http-reviewer", http_provider), http_config, default_concurrency=2
            ),
            build_runtime(
                Reviewer("process-reviewer", process_provider),
                process_config,
                default_concurrency=2,
            ),
        ],
        providers=[http_provider, process_provider],
        configs={"http-reviewer": http_config, "process-reviewer": process_config},
    )


async def test_disagreement_across_transports_becomes_review_required(tmp_path):
    """P3 の完了条件. 割れたら review_required (§13.1)."""
    root = workspace(tmp_path)
    setup = mixed_setup(
        [verdict_payload(vulnerable=True, severity="high", confidence=0.8)],
        process_command(vulnerable=False, severity="none", confidence=0.72),
    )

    outcome = await run_review(
        make_config(tmp_path),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
        reviewer_setup=setup,
    )

    finding = outcome.report.findings[0]
    assert finding.status is FindingStatus.REVIEW_REQUIRED
    # 両方の判定がレポートに残る (集約値だけを信じさせない・§15)
    assert {verdict.reviewer for verdict in finding.verdicts} == {
        "http-reviewer",
        "process-reviewer",
    }
    assert outcome.report.coverage.candidates_reviewed == 1
    # review_required は CI を落とさない (警告と失敗を分ける・§21.3)
    assert outcome.decision.exit_code.value == 0


async def test_agreement_across_transports_is_confirmed(tmp_path):
    """性質の異なる transport が一致したときは、その一致が情報量を持つ (§9.7)."""
    root = workspace(tmp_path)
    setup = mixed_setup(
        [verdict_payload(vulnerable=True, severity="high", confidence=0.92)],
        process_command(vulnerable=True, severity="high", confidence=0.88),
    )

    outcome = await run_review(
        make_config(tmp_path),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
        reviewer_setup=setup,
    )

    finding = outcome.report.findings[0]
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.agreement is Agreement.HIGH


async def test_each_transport_is_reported_separately(tmp_path):
    """どちらの transport が何回呼ばれたかが残る (P4)."""
    root = workspace(tmp_path)
    setup = mixed_setup(
        [verdict_payload(vulnerable=True)],
        process_command(vulnerable=False, severity="none"),
    )

    outcome = await run_review(
        make_config(tmp_path),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
        reviewer_setup=setup,
    )

    by_name = {run.name: run for run in outcome.report.reviewers}
    assert by_name["http-reviewer"].transport == "http"
    assert by_name["process-reviewer"].transport == "process"
    assert by_name["process-reviewer"].dialect == "text_io"
    assert all(run.calls == 1 for run in outcome.report.reviewers)
    # コストが分かる transport と分からない transport が混ざる。
    # 分からない方に引きずられて「不明」になることを隠さない (§24.3)
    assert outcome.report.usage.cost_known is False


async def test_weighted_strategy_can_break_the_tie(tmp_path):
    """同じ割れ方でも、重みを与えれば判定が動く (§14.2)."""
    root = workspace(tmp_path)
    setup = mixed_setup(
        [verdict_payload(vulnerable=True, severity="high", confidence=0.9)],
        process_command(vulnerable=False, severity="none", confidence=0.9),
        weights=(9.0, 1.0),
    )
    # 重みは設定ファイル側 (reviewers[].weight) が正。run が集約へ渡す
    config = make_config(
        tmp_path,
        aggregation={"strategy": "weighted"},
        reviewers=[
            {
                "name": "http-reviewer",
                "transport": "http",
                "dialect": "openai_chat",
                "base_url": "http://stub/v1",
                "model": "stub",
                "weight": 9.0,
            },
            {
                "name": "process-reviewer",
                "transport": "process",
                "command": ["unused-placeholder"],
                "weight": 1.0,
            },
        ],
    )

    outcome = await run_review(
        config,
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
        reviewer_setup=setup,
    )

    finding = outcome.report.findings[0]
    assert finding.status in (FindingStatus.LIKELY, FindingStatus.CONFIRMED)
    assert finding.aggregation is not None
    # 計算に使った重みがレポートに残る (P4)
    assert finding.aggregation.detail["weights"] == {
        "http-reviewer": 9.0,
        "process-reviewer": 1.0,
    }


async def test_one_transport_failing_does_not_hide_the_other(tmp_path):
    """片方が壊れても、もう片方の判定は残る (P9)."""
    root = workspace(tmp_path)
    broken = [sys.executable, "-c", "import sys;sys.stdin.read();sys.exit(3)"]
    setup = mixed_setup([verdict_payload(vulnerable=True, confidence=0.95)], broken)

    outcome = await run_review(
        make_config(tmp_path),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
        reviewer_setup=setup,
    )

    finding = outcome.report.findings[0]
    assert finding.status is not FindingStatus.ERROR
    # 失敗した側も verdict として残る (黙って消さない)
    assert len(finding.verdicts) == 2
    by_name = {run.name: run for run in outcome.report.reviewers}
    assert by_name["process-reviewer"].verdicts_error == 1
    assert by_name["http-reviewer"].verdicts_ok == 1
