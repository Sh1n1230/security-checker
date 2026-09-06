"""`security-checker init` — 環境検出と設定生成 (設計書 §9.8).

既定の Reviewer は 1 つも持たない。特定のベンダーを標準として押し付けないため。
検出できるものが無くても、コマンドを直接指定すれば設定を生成できる。
"""

from __future__ import annotations

import yaml
from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.config.schema import Config
from security_checker.errors import ExitCode

runner = CliRunner()


def test_init_without_presets_generates_nothing_and_says_why(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path)], input="\n")
    assert result.exit_code == ExitCode.OK
    assert not (tmp_path / "security-checker.yml").exists()
    assert "--command" in result.stdout


def test_init_with_a_direct_command_writes_a_usable_config(tmp_path):
    result = runner.invoke(
        app, ["init", str(tmp_path), "--command", "my-cmd --non-interactive --no-tools"]
    )
    assert result.exit_code == ExitCode.OK

    document = (tmp_path / "security-checker.yml").read_text(encoding="utf-8")
    config = Config.model_validate(yaml.safe_load(document))
    reviewer = config.reviewers[0]
    assert reviewer.name == "my-cmd"
    assert reviewer.transport == "process"
    assert reviewer.command == ["my-cmd", "--non-interactive", "--no-tools"]
    # 書き込み能力の無効化が利用者の責任であることを、生成物にも残す (§9.7)
    assert "書き込み能力" in document


def test_init_honours_an_explicit_name(tmp_path):
    runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd -q", "--name", "reviewer-a"])
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert payload["reviewers"][0]["name"] == "reviewer-a"


def test_init_refuses_to_overwrite_without_force(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert (tmp_path / "security-checker.yml").read_text(encoding="utf-8") == "version: 1\n"


def test_init_force_overwrites(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--force"])
    assert result.exit_code == ExitCode.OK
    assert "my-cmd" in (tmp_path / "security-checker.yml").read_text(encoding="utf-8")


def test_init_stdout_does_not_touch_the_filesystem(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--stdout"])
    assert result.exit_code == ExitCode.OK
    assert not (tmp_path / "security-checker.yml").exists()
    assert "my-cmd" in result.stdout


def test_init_rejects_a_missing_directory(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path / "nope"), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.CONFIG_ERROR


def test_init_local_writes_the_gitignored_overlay(tmp_path):
    """共有設定を残したまま、手元用の Reviewer だけを別ファイルに置く."""
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--local"])

    assert result.exit_code == ExitCode.OK
    assert (tmp_path / "security-checker.yml").read_text(encoding="utf-8") == "version: 1\n"
    payload = yaml.safe_load((tmp_path / "security-checker.local.yml").read_text(encoding="utf-8"))
    assert payload["reviewers"][0]["command"] == ["my-cmd"]


def test_init_suggests_local_when_the_shared_config_exists(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "--local" in result.stdout + str(result.stderr)
