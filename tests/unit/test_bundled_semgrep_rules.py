"""同梱の semgrep ルール (`bundled:<名前>`) を `semgrep --test` で検証する.

fixture は tests/fixtures/bundled-rules/<ルール名>.<拡張子> に置き、`# ruleid:` / `# ok:` の注釈で
期待を書く。semgrep が無い環境では skip する (CI では dogfooding job が semgrep を入れて回す)。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest
import yaml

from security_checker import rules
from security_checker.config.schema import SemgrepConfig

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "bundled-rules"


def test_every_bundled_rule_has_fixtures():
    for name in rules.bundled_semgrep_rules():
        assert list(FIXTURES.glob(f"{name}.*")), f"bundled:{name} の fixture がありません"


def test_default_config_uses_the_bundled_llm_rules():
    assert SemgrepConfig().configs == ["p/default", "bundled:llm", "bundled:ci-lock"]


@pytest.mark.parametrize(
    "path",
    [
        "tests/sample.py",
        "pkg/tests/sample.py",
        "test/sample.py",
        "pkg/test/sample.py",
        "conftest.py",
        "pkg/conftest.py",
        "test_llm.py",
        "pkg/llm_test.py",
    ],
)
def test_llm_python_rules_ignore_test_code_at_any_depth(path: str):
    config = yaml.safe_load((rules.SEMGREP_DIR / "llm.yml").read_text(encoding="utf-8"))
    python_rules = [rule for rule in config["rules"] if rule["languages"] == ["python"]]
    assert len(python_rules) == 2
    for rule in python_rules:
        assert any(PurePosixPath(path).match(pattern) for pattern in rule["paths"]["exclude"]), (
            rule["id"]
        )


def test_llm_python_rules_still_target_production_code():
    config = yaml.safe_load((rules.SEMGREP_DIR / "llm.yml").read_text(encoding="utf-8"))
    for rule in config["rules"]:
        if rule["languages"] == ["python"]:
            assert not any(
                PurePosixPath("pkg/handler.py").match(pattern)
                for pattern in rule["paths"]["exclude"]
            )


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep が入っていません")
def test_bundled_rules_pass_semgrep_test():
    result = subprocess.run(
        [
            "semgrep",
            "--test",
            "--metrics=off",
            "--config",
            str(rules.SEMGREP_DIR),
            str(FIXTURES),
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_no_rules_are_listed_when_the_bundled_directory_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(rules, "SEMGREP_DIR", tmp_path / "missing")
    assert rules.bundled_semgrep_rules() == []
