"""同梱の semgrep ルール (`bundled:<名前>`) を `semgrep --test` で検証する.

fixture は tests/fixtures/bundled-rules/<ルール名>.<拡張子> に置き、`# ruleid:` / `# ok:` の注釈で
期待を書く。semgrep が無い環境では skip する (CI では dogfooding job が semgrep を入れて回す)。
"""

from __future__ import annotations

import json
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
def test_llm_python_rules_ignore_test_code_at_any_depth(path: str) -> None:
    config = yaml.safe_load((rules.SEMGREP_DIR / "llm.yml").read_text(encoding="utf-8"))
    python_rules = [rule for rule in config["rules"] if rule["languages"] == ["python"]]
    assert len(python_rules) == 2
    for rule in python_rules:
        assert any(PurePosixPath(path).match(pattern) for pattern in rule["paths"]["exclude"]), (
            rule["id"]
        )


def test_llm_python_rules_still_target_production_code() -> None:
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


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep が入っていません")
def test_ci_lock_scans_composite_action_paths(tmp_path):
    fixture = (FIXTURES / "ci-lock.composite.test.yml").read_text(encoding="utf-8")
    paths = [
        "action.yml",
        "action.yaml",
        ".github/actions/setup/action.yml",
        ".github/actions/nested/setup/action.yaml",
    ]
    for relative in [*paths, "docs/action.yml", "unrelated.yml"]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(fixture, encoding="utf-8")
    relock = tmp_path / ".github/actions/relock/action.yml"
    relock.parent.mkdir(parents=True)
    relock.write_text(
        (FIXTURES / "ci-lock.composite-relock.test.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--config",
            str(rules.SEMGREP_DIR / "ci-lock.yml"),
            ".",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["errors"] == []
    assert sorted(
        (finding["path"], finding["check_id"].rsplit(".", 1)[-1]) for finding in report["results"]
    ) == sorted(
        (path, rule_id)
        for path in paths
        for rule_id in ("ci-uv-sync-without-locked", "ci-uv-sync-frozen-without-locked")
    )
