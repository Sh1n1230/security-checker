"""CLI の review / scan / init / dry-run の分岐 (#475〜#479).

スキャンとレビューの本体は差し替え、CLI の側の分岐 (終了コード・表示・上書き) だけを確かめる。
実 LLM もスキャナも呼ばない。
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from typer.testing import CliRunner

from security_checker.cli import INTERRUPTED_EXIT_CODE, app
from security_checker.config.schema import Config, PolicyConfig
from security_checker.errors import ConfigError, ExitCode
from security_checker.github.pr import DiffScope
from security_checker.observability.estimate import Estimate, ReviewerEstimate
from security_checker.policy.engine import evaluate
from security_checker.providers.detect import Detection
from security_checker.run import RunOutcome
from tests.factories import make_report

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

REVIEWER = {
    "name": "priced",
    "transport": "http",
    "dialect": "openai_chat",
    "base_url": "http://x/v1",
    "model": "m",
}


def project(tmp_path: Path, **extra: Any) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "security-checker.yml").write_text(
        json.dumps({"version": 1, "reviewers": [REVIEWER], **extra}), encoding="utf-8"
    )
    return root


def outcome(tmp_path: Path, *, interrupted: bool = False) -> RunOutcome:
    report = make_report([])
    return RunOutcome(
        report=report,
        decision=evaluate(report, PolicyConfig()),
        output_dir=tmp_path / "out",
        interrupted=interrupted,
    )


def test_scan_reports_a_tool_error_with_its_exit_code(tmp_path, monkeypatch):
    """スキャンの途中の設定エラーは、トレースバックではなく終了コードで返す (#475)."""

    async def broken(*args: Any, **kwargs: Any) -> None:
        raise ConfigError("scanners.semgrep.config が読めません")

    monkeypatch.setattr("security_checker.cli.run_scan", broken)
    result = runner.invoke(app, ["scan", str(project(tmp_path)), "--full"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "scanners.semgrep.config が読めません" in result.stderr


def test_review_passes_max_candidates_and_exits_with_the_policy_decision(tmp_path, monkeypatch):
    """--max-candidates は設定の上限を上書きし、終了コードはポリシーの判定に従う (#476)."""
    seen: list[Config] = []

    async def fake_review(config: Config, *args: Any, **kwargs: Any) -> RunOutcome:
        seen.append(config)
        return outcome(tmp_path)

    monkeypatch.setattr("security_checker.cli.run_review", fake_review)
    result = runner.invoke(
        app, ["review", str(project(tmp_path)), "--full", "--max-candidates", "7", "--quiet"]
    )
    assert result.exit_code == ExitCode.OK, result.output
    assert seen[0].budget.max_candidates == 7


def test_an_interrupted_review_keeps_its_results_and_exits_130(tmp_path, monkeypatch):
    """中断されたら部分結果を書いたことを知らせ、シェルの慣習どおり 130 で返す (#476)."""

    async def fake_review(*args: Any, **kwargs: Any) -> RunOutcome:
        return outcome(tmp_path, interrupted=True)

    monkeypatch.setattr("security_checker.cli.run_review", fake_review)
    result = runner.invoke(app, ["review", str(project(tmp_path)), "--full", "--quiet"])
    assert result.exit_code == INTERRUPTED_EXIT_CODE
    assert "中断されました" in result.stderr
    assert (tmp_path / "out" / "report.json").is_file()


def test_estimate_warns_when_only_the_upper_bound_exceeds_the_budget(tmp_path, monkeypatch):
    """見積りは予算内でも、修復の再送をすべて含めた上限が超えるならその旨を出す (#477)."""
    scanned = type("Scanned", (), {"report": make_report([])})()

    async def fake_scan(*args: Any, **kwargs: Any) -> Any:
        return scanned

    def fake_estimate(*args: Any, **kwargs: Any) -> Estimate:
        item = ReviewerEstimate(
            name="priced", calls=1, input_tokens=10, max_output_tokens=10, usd=0.5, upper_usd=2.0
        )
        return Estimate(tasks=1, reviewers=[item])

    monkeypatch.setattr("security_checker.cli.run_scan", fake_scan)
    monkeypatch.setattr("security_checker.cli.estimate_run", fake_estimate)
    root = project(tmp_path, budget={"max_usd": 1.0})
    result = runner.invoke(app, ["review", str(root), "--estimate", "--full"])
    assert result.exit_code == ExitCode.OK, result.output
    assert "修復の再送が多いと予算を超えることがあります" in result.stdout
    assert "見積りが予算を超えています" not in result.stdout


def test_init_with_an_empty_command_is_a_config_error(tmp_path, monkeypatch):
    """--command に空文字を渡したら、空の Reviewer を書かずに止める (#479)."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "--command", "  ", "--stdout"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "--command が空です" in result.stderr


def detected(config: dict[str, object]) -> list[Detection]:
    return [Detection(transport="process", name="tool", available=True, detail="", config=config)]


def test_init_asks_which_detection_to_use_and_writes_the_chosen_one(tmp_path, monkeypatch):
    """--yes が無ければ番号で尋ね、選んだものだけを書く (#479)."""
    chosen: dict[str, object] = {"name": "tool", "transport": "process", "command": ["tool", "-p"]}
    monkeypatch.setattr("security_checker.cli.detect_all", lambda: detected(chosen))
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "--stdout"], input="1\n")
    assert result.exit_code == ExitCode.OK, result.output
    assert "name: tool" in result.stdout


def test_init_refuses_to_write_a_config_that_review_could_not_read(tmp_path, monkeypatch):
    """検出結果から作った設定が読めない形なら、書かずに止める (#479)."""
    broken: dict[str, object] = {"name": "tool", "transport": "process"}  # command も preset も無い
    monkeypatch.setattr("security_checker.cli.detect_all", lambda: detected(broken))
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "--stdout", "--yes"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "生成した設定が不正です" in result.stderr
    assert not (tmp_path / "security-checker.yml").exists()


def test_dry_run_in_diff_mode_says_what_is_left_out(tmp_path, monkeypatch):
    """diff モードの dry-run は、基準と、差分の外で送らない件数を示す (#478)."""
    scanned = type("Scanned", (), {"report": make_report([])})()

    async def fake_scan(*args: Any, **kwargs: Any) -> Any:
        return scanned

    diff = DiffScope(base="origin/main", changed_files=frozenset({"a.py", "b.py"}))
    monkeypatch.setattr("security_checker.cli.run_scan", fake_scan)
    monkeypatch.setattr("security_checker.cli._diff_scope", lambda *a, **k: (diff, []))
    result = runner.invoke(app, ["review", str(project(tmp_path)), "--dry-run"])
    assert result.exit_code == ExitCode.OK, result.output
    assert "origin/main との差分 (2 ファイル)" in result.stdout
    assert "対象外 0 件" in result.stdout
