"""同梱の semgrep ルール (`bundled:<名前>`) を `semgrep --test` で検証する.

fixture は tests/fixtures/bundled-rules/<ルール名>.<拡張子> に置き、`# ruleid:` / `# ok:` の注釈で
期待を書く。semgrep が無い環境では skip する (CI では dogfooding job が semgrep を入れて回す)。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from security_checker import rules
from security_checker.config.schema import SemgrepConfig

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "bundled-rules"


def test_every_bundled_rule_has_fixtures():
    for name in rules.bundled_semgrep_rules():
        assert list(FIXTURES.glob(f"{name}.*")), f"bundled:{name} の fixture がありません"


def test_default_config_uses_the_bundled_llm_rules():
    assert SemgrepConfig().configs == ["p/default", "bundled:llm", "bundled:ci-lock"]


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
