"""E2E: 実スキャナでパイプライン全体を回す (設計書 §25.1).

スキャナは意図的にモックしない。導入されていない環境では skip する。
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from security_checker.config.schema import Config
from security_checker.errors import ExitCode
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.report.json_writer import write_json
from security_checker.run import run_scan

pytestmark = pytest.mark.e2e

# gitleaks に検出させる必要がある一方、完結した文字列をリポジトリに残すと
# GitHub push protection が本物の秘密として弾く。実行時に組み立てて両立させる。
SECRET_VALUE = "xoxb-" + "1234567890" + "-" + "0987654321" + "-" + "abcdefghijklmnopqrstuvwx"


@pytest.fixture
def workspace(tmp_path: Path, fixture_dir: Path) -> Path:
    """git 管理外の作業ディレクトリに脆弱サンプルを展開する.

    semgrep は git リポジトリ内では追跡済みファイルしか見ないため、リポジトリ外に置く。
    """
    root = tmp_path / "vulnerable-app"
    shutil.copytree(fixture_dir / "vulnerable-app", root)
    (root / "settings.py").write_text(f'SLACK_TOKEN = "{SECRET_VALUE}"\n', encoding="utf-8")
    return root


def build_config(fixture_dir: Path, output_dir: Path) -> Config:
    return Config.model_validate(
        {
            "scanners": {
                "semgrep": {"config": str(fixture_dir / "semgrep-rules.yml"), "timeout_s": 120},
                "gitleaks": {"enabled": True},
            },
            "output": {"dir": str(output_dir)},
            "policy": {"strict": False},
        }
    )


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep 未導入")
async def test_semgrep_end_to_end(workspace, fixture_dir, tmp_path):
    config = build_config(fixture_dir, tmp_path / "out")
    config.scanners.gitleaks.enabled = False
    outcome = await run_scan(config, workspace, base_dir=tmp_path)

    run = next(r for r in outcome.report.scanners if r.scanner == "semgrep")
    assert run.status is ScanStatus.OK, run.reason
    # ローカルルールを使うと check_id にルールファイルのパスが前置される
    titles = {c.title for c in outcome.report.candidates}
    assert titles == {"local-os-system-injection", "local-eval-detected"}

    finding = next(c for c in outcome.report.candidates if c.title == "local-os-system-injection")
    assert finding.category is Category.SAST
    assert finding.severity_reported is Severity.HIGH
    assert finding.cwe == ["CWE-78"]
    assert finding.location is not None
    assert finding.location.path == "app.py"
    assert not Path(finding.location.path).is_absolute()
    assert outcome.decision.exit_code is ExitCode.POLICY_VIOLATION


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks 未導入")
async def test_gitleaks_end_to_end_never_writes_secret_values(workspace, fixture_dir, tmp_path):
    config = build_config(fixture_dir, tmp_path / "out")
    config.scanners.semgrep.enabled = False
    outcome = await run_scan(config, workspace, base_dir=tmp_path)

    run = next(r for r in outcome.report.scanners if r.scanner == "gitleaks")
    assert run.status is ScanStatus.OK, run.reason
    assert any(c.category is Category.SECRET for c in outcome.report.candidates)

    # 成果物のどのファイルにも検出値そのものが現れないこと (§19.2)
    write_json(outcome.report, outcome.output_dir)
    for path in outcome.output_dir.rglob("*"):
        if path.is_file():
            assert SECRET_VALUE not in path.read_text(encoding="utf-8", errors="replace")


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep 未導入")
async def test_missing_tool_is_skipped_not_failed(workspace, fixture_dir, tmp_path, monkeypatch):
    """未導入は skipped (実行エラーではない) として扱う."""
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    config = build_config(fixture_dir, tmp_path / "out")
    outcome = await run_scan(config, workspace, base_dir=tmp_path)

    assert {r.status for r in outcome.report.scanners} == {ScanStatus.SKIPPED}
    assert outcome.decision.exit_code is ExitCode.OK
    assert outcome.report.score.partial is True


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep 未導入")
async def test_broken_scanner_config_is_failed(workspace, tmp_path):
    """存在しないルールファイルを指定 → failed。0 件成功に化けさせない (v1 のバグ)."""
    config = Config.model_validate(
        {
            "scanners": {
                "semgrep": {"config": str(tmp_path / "no-such-rules.yml"), "timeout_s": 60},
                "gitleaks": {"enabled": False},
            },
            "output": {"dir": str(tmp_path / "out")},
            "policy": {"strict": True},
        }
    )
    outcome = await run_scan(config, workspace, base_dir=tmp_path)

    run = next(r for r in outcome.report.scanners if r.scanner == "semgrep")
    assert run.status is ScanStatus.FAILED
    assert outcome.decision.exit_code is ExitCode.EXECUTION_ERROR
    assert outcome.report.score.partial is True
    payload = json.loads(write_json(outcome.report, outcome.output_dir).read_text())
    assert payload["scanners"][0]["status"] == "failed"
