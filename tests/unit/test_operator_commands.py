"""運用コマンド: providers list / providers check / review --estimate / explain.

いずれも実 LLM を叩かない。providers check は process transport の最小スクリプトで往復させる。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.config.schema import Config, ReviewerConfig
from security_checker.errors import ExitCode
from security_checker.models.enums import FindingStatus
from security_checker.observability.cost import ModelPrice, PriceTable
from security_checker.observability.estimate import estimate_run
from security_checker.observability.explain import explain, load_report, render
from security_checker.providers.check import catalog, check_reviewer, probe_task
from security_checker.report.json_writer import write_json
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup, run_review
from security_checker.testing import FakeScanner, ScriptedProvider, verdict_payload
from tests.factories import make_candidate

runner = CliRunner()

ECHO_VERDICT = "import json,sys;sys.stdin.read();print(json.dumps(json.loads(sys.argv[1])))"


def process_reviewer(name: str = "local", **verdict: Any) -> ReviewerConfig:
    return ReviewerConfig(
        name=name,
        transport="process",
        command=[sys.executable, "-c", ECHO_VERDICT, json.dumps(verdict_payload(**verdict))],
        timeout_s=60,
    )


# --- providers ------------------------------------------------------------------------


def test_catalog_lists_dialects_and_bundled_presets():
    found = catalog()
    assert {"openai_chat", "anthropic_messages", "gemini_generate", "ollama_chat"} <= set(
        found.dialects
    )
    assert "openai" in found.http_presets
    assert "claude" in found.process_presets


def test_cli_providers_list():
    result = runner.invoke(app, ["providers", "list"])
    assert result.exit_code == 0
    assert "openai_chat" in result.stdout
    assert "process" in result.stdout


async def test_check_passes_through_all_steps():
    result = await check_reviewer(process_reviewer())
    assert result.ok, result
    assert [step.label for step in result.steps] == ["設定", "疎通", "構造化出力"]


async def test_check_reports_a_model_that_calls_the_probe_safe():
    result = await check_reviewer(process_reviewer(vulnerable=False, severity="none"))
    assert result.ok
    assert any("eval" in s for s in result.suggestions)


async def test_check_reports_schema_failures_with_a_fix():
    reviewer = ReviewerConfig(
        name="broken",
        transport="process",
        command=[sys.executable, "-c", "import sys;sys.stdin.read();print('no json here')"],
        timeout_s=60,
    )
    result = await check_reviewer(reviewer)
    assert not result.ok
    assert result.steps[-1].label == "構造化出力"
    assert any("structured_output" in s for s in result.suggestions)


async def test_check_reports_a_missing_api_key():
    reviewer = ReviewerConfig(
        name="remote",
        transport="http",
        dialect="openai_chat",
        base_url="https://example.invalid/v1",
        model="m",
        api_key_env="SC_TEST_MISSING_KEY",
    )
    result = await check_reviewer(reviewer, environ={})
    assert not result.ok
    assert result.steps[0].label == "設定"
    assert "SC_TEST_MISSING_KEY" in result.steps[0].detail


async def test_check_without_probe_does_not_call_the_model(tmp_path):
    marker = tmp_path / "called"
    reviewer = ReviewerConfig(
        name="local",
        transport="process",
        command=[sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"],
        timeout_s=60,
    )
    result = await check_reviewer(reviewer, probe=False)
    assert [step.label for step in result.steps] == ["設定", "疎通"]
    assert not marker.exists()


def test_probe_task_contains_no_repository_code():
    task = probe_task()
    assert task.code_context.primary is not None
    assert task.code_context.primary.path == "probe.py"


def test_cli_providers_check_unknown_name(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["providers", "check", "nope", "--path", str(tmp_path)])
    assert result.exit_code == ExitCode.CONFIG_ERROR


def test_cli_providers_check_runs_the_configured_reviewer(tmp_path):
    reviewer = process_reviewer().model_dump(exclude_none=True)
    (tmp_path / "security-checker.yml").write_text(
        json.dumps({"version": 1, "reviewers": [reviewer]}), encoding="utf-8"
    )
    result = runner.invoke(app, ["providers", "check", "--path", str(tmp_path)])
    assert result.exit_code == ExitCode.OK, result.output
    assert "構造化出力" in result.stdout


# --- estimate -------------------------------------------------------------------------


def test_estimate_prices_known_models_and_refuses_to_guess():
    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "priced",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://x/v1",
                    "model": "m-priced",
                    "max_output_tokens": 100,
                },
                {
                    "name": "unpriced",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://x/v1",
                    "model": "m-unknown",
                },
            ]
        }
    )
    table = PriceTable(prices={"m-priced": ModelPrice(input_per_1m=1.0, output_per_1m=2.0)})
    result = estimate_run([probe_task(), probe_task()], config, table)
    priced, unpriced = result.reviewers
    assert priced.calls == 2
    assert priced.input_tokens > 0
    assert priced.max_output_tokens == 200
    assert priced.usd is not None and priced.usd > 0
    assert unpriced.usd is None and "価格表" in unpriced.note
    # 一部だけ足した合計は実際より安く見えるので出さない
    assert result.total_usd is None


def test_estimate_marks_process_transport_unknown():
    config = Config(reviewers=[process_reviewer()])
    result = estimate_run([probe_task()], config, PriceTable())
    assert result.reviewers[0].usd is None
    assert "process" in result.reviewers[0].note


def test_cli_review_estimate_sends_nothing(tmp_path, monkeypatch):
    marker = tmp_path / "called"
    reviewer = {
        "name": "local",
        "transport": "process",
        "command": [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"],
    }
    (tmp_path / "security-checker.yml").write_text(
        json.dumps(
            {
                "version": 1,
                "reviewers": [reviewer],
                "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["review", str(tmp_path), "--estimate", "--full"])
    assert result.exit_code == ExitCode.OK, result.output
    assert "合計" in result.stdout
    assert not marker.exists()


# --- explain --------------------------------------------------------------------------


async def reviewed_report(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("\n" * 41 + "run(cmd, shell=True)\n", encoding="utf-8")
    config = Config.model_validate(
        {
            "output": {"dir": str(tmp_path / "out")},
            "reviewers": [
                {
                    "name": "alpha",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://x/v1",
                    "model": "m",
                }
            ],
            "policy": {"strict": False},
        }
    )
    provider = ScriptedProvider([verdict_payload(reasoning="shell に渡っている")])
    setup = ReviewerSetup(
        runtimes=[
            build_runtime(Reviewer("alpha", provider), config.reviewers[0], default_concurrency=1)
        ],
        providers=[provider],
        configs={"alpha": config.reviewers[0]},
    )
    outcome = await run_review(
        config,
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[make_candidate("abcdef123456")])],
        reviewer_setup=setup,
    )
    return write_json(outcome.report, outcome.output_dir)


async def test_explain_shows_verdicts_and_calls(tmp_path):
    path = await reviewed_report(tmp_path)
    result = explain(load_report(path), "abcdef", report_path=path)
    assert result.finding is not None
    assert result.finding.status is FindingStatus.CONFIRMED
    assert len(result.calls) == 1
    text = render(result)
    assert "shell に渡っている" in text
    assert "呼び出し記録: 1 件" in text


async def test_cli_explain_and_unknown_id(tmp_path):
    path = await reviewed_report(tmp_path)
    ok = runner.invoke(app, ["explain", "abcdef123456", "--report", str(path)])
    assert ok.exit_code == 0, ok.output
    assert "alpha" in ok.stdout
    missing = runner.invoke(app, ["explain", "zzz", "--report", str(path)])
    assert missing.exit_code == ExitCode.CONFIG_ERROR
