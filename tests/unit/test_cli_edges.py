"""CLI の境界: 上書きの組み立て・init の対話入力・入力の誤りの終了コード (設計書 §12・§20)."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from typer.testing import CliRunner

from security_checker import cli
from security_checker.cli import app
from security_checker.config.schema import BudgetConfig
from security_checker.errors import ExitCode
from security_checker.models.enums import Severity
from security_checker.models.verdict import Usage
from security_checker.providers.check import CheckResult, ProviderCatalog
from security_checker.providers.detect import Detection
from security_checker.run import _remaining_budget, output_relative

runner = CliRunner()


# --- 上書きの組み立て -------------------------------------------------------------


def test_cli_overrides_only_contain_what_was_given():
    assert (
        cli._cli_overrides(
            fail_on=None,
            min_score=None,
            strict=None,
            exclude=None,
            output_dir=None,
            formats=None,
            semgrep_config=None,
        )
        == {}
    )
    overrides = cli._cli_overrides(
        fail_on=Severity.CRITICAL,
        min_score=70,
        strict=True,
        exclude=["vendor/**"],
        output_dir=Path("out"),
        formats=["json"],
        semgrep_config="p/ci",
    )
    assert overrides == {
        "policy": {"fail_on": "critical", "min_score": 70, "strict": True},
        "target": {"exclude": ["vendor/**"]},
        "output": {"dir": "out", "formats": ["json"]},
        "scanners": {"semgrep": {"config": "p/ci"}},
    }


def test_logging_overrides_only_contain_what_was_given():
    assert cli._logging_overrides(None, None) == {}
    assert cli._logging_overrides("json", "debug") == {
        "logging": {"format": "json", "level": "debug"}
    }


# --- init の補助 ------------------------------------------------------------------


def _detections(count: int) -> list[Detection]:
    return [
        Detection(transport="process", name=f"d{i}", available=True, detail="", config={})
        for i in range(1, count + 1)
    ]


def test_select_parses_numbers_and_reports_what_it_ignored():
    usable = _detections(3)
    console = Console(record=True, width=120)
    assert cli._select(usable, "-", console) == []
    assert cli._select(usable, "", console) == usable
    assert cli._select(usable, "3, 1, x, 9", console) == [usable[2], usable[0]]
    shown = console.export_text()
    assert "'x' は番号ではありません" in shown
    assert "'9' は番号ではありません" in shown


def test_unique_name_skips_names_already_taken():
    assert cli._unique_name("tool", set()) == "tool-2"
    assert cli._unique_name("tool", {"tool-2", "tool-3"}) == "tool-4"


def test_ignore_check_is_false_when_git_cannot_run(tmp_path, monkeypatch):
    def boom(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr("subprocess.run", boom)
    assert cli._git_ignores(tmp_path, tmp_path / "security-checker.local.yml") is False


# --- 入力の誤り -------------------------------------------------------------------


@pytest.mark.parametrize("command", [["review"], ["baseline", "update"]])
def test_missing_target_is_a_config_error(tmp_path, command):
    result = runner.invoke(app, [*command, str(tmp_path / "nope")])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "検査対象が見つかりません" in result.output


def test_comment_with_a_broken_report_is_a_config_error(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    report = tmp_path / "report.json"
    report.write_text("{broken", encoding="utf-8")
    result = runner.invoke(app, ["comment", str(report)])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "レポートを読めません" in result.output


def test_providers_list_says_none_and_shows_plugin_warnings(monkeypatch):
    empty = ProviderCatalog(
        dialects=["openai_chat"],
        http_presets={},
        process_presets={},
        plugins=[],
        warnings=["provider プラグイン 'x' の読み込みに失敗しました"],
    )
    monkeypatch.setattr(cli, "catalog", lambda: empty)
    result = runner.invoke(app, ["providers", "list"])
    assert result.exit_code == ExitCode.OK
    assert result.output.count("(なし)") == 3
    assert "プラグイン 'x' の読み込みに失敗しました" in result.output


# --- run の補助 -------------------------------------------------------------------


def test_output_relative_keeps_paths_outside_the_output_directory(tmp_path):
    output = tmp_path / "out"
    assert output_relative(output / "raw" / "x.json", output) == "raw/x.json"
    assert output_relative(tmp_path / "elsewhere.json", output) == str(tmp_path / "elsewhere.json")


def test_remaining_budget_is_none_once_money_or_tokens_run_out():
    budget = BudgetConfig(max_usd=1.0, max_total_tokens=1000)
    left = _remaining_budget(budget, Usage(input_tokens=400, estimated_usd=0.25))
    assert left is not None
    assert (left.max_usd, left.max_total_tokens) == (0.75, 600)
    assert _remaining_budget(budget, Usage(estimated_usd=1.0)) is None
    assert _remaining_budget(budget, Usage(input_tokens=1000, estimated_usd=0.1)) is None


def test_providers_check_uses_one_event_loop_for_all_reviewers(tmp_path, monkeypatch):
    loops: set[int] = set()

    async def fake_check(reviewer: Any, *, probe: bool) -> CheckResult:
        loops.add(id(asyncio.get_running_loop()))
        return CheckResult(name=reviewer.name, transport=reviewer.transport)

    monkeypatch.setattr(cli, "check_reviewer", fake_check)
    reviewers = "\n".join(
        f"  - {{name: r{i}, transport: process, command: [tool{i}]}}" for i in range(3)
    )
    (tmp_path / "security-checker.yml").write_text(
        f"version: 1\nreviewers:\n{reviewers}\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["providers", "check", "--path", str(tmp_path)])
    assert len(loops) == 1
    # 表示は設定に書いた順
    assert [line.split()[1] for line in result.output.splitlines() if "(process)" in line] == [
        "r0",
        "r1",
        "r2",
    ]
