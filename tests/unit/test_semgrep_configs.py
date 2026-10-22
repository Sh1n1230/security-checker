"""`scanners.semgrep.config` の複数指定と同梱ルール (`bundled:<名前>`)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from security_checker import rules
from security_checker.config.schema import SemgrepConfig
from security_checker.models.enums import ScanStatus
from security_checker.scanners.base import ScanContext, Target
from security_checker.scanners.semgrep import SemgrepScanner, resolve_config


@pytest.fixture
def bundled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """同梱ルールの置き場所を差し替える. 中身はルールの有無だけを見る."""
    directory: Path = tmp_path / "rules"
    directory.mkdir()
    (directory / "llm.yml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(rules, "SEMGREP_DIR", directory)
    return directory


def test_a_single_string_still_works():
    assert SemgrepConfig(config="p/default").configs == ["p/default"]


def test_a_list_is_accepted(bundled):
    config = SemgrepConfig(config=["p/default", "bundled:llm"])
    assert config.configs == ["p/default", "bundled:llm"]


def test_unknown_bundled_rule_is_a_config_error(bundled):
    with pytest.raises(ValidationError, match="bundled:llm"):
        SemgrepConfig(config=["bundled:no-such"])


def test_empty_list_is_rejected():
    with pytest.raises(ValidationError, match="空"):
        SemgrepConfig(config=[])


@pytest.mark.parametrize("name", ["../llm", "sub/llm", ".hidden", ""])
def test_bundled_names_cannot_point_outside_the_package(bundled, name):
    assert rules.bundled_semgrep_rule(name) is None


def test_bundled_resolves_inside_the_package_not_the_target(bundled, tmp_path):
    """検査対象に同名のファイルを置いても差し替えられない."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "llm.yml").write_text("rules: [evil]\n", encoding="utf-8")
    assert resolve_config("bundled:llm") == str(bundled / "llm.yml")
    assert resolve_config("p/default") == "p/default"
    assert resolve_config("./local.yml") == "./local.yml"


async def test_each_config_is_passed_as_its_own_flag(bundled, tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("偽のコマンドは #!/bin/sh のスクリプトで作るため POSIX のみ")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    args_file = tmp_path / "args.txt"
    script = bin_dir / "semgrep"
    script.write_text(
        "#!/bin/sh\n"
        'case "$1" in --version) echo "1.0.0"; exit 0;; esac\n'
        f"printf '%s\\n' \"$@\" > '{args_file}'\n"
        'echo \'{"results": [], "errors": []}\'\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    raw = tmp_path / "raw"
    raw.mkdir()

    scanner = SemgrepScanner(SemgrepConfig(config=["p/default", "bundled:llm"]))
    result = await scanner.scan(Target(root=tmp_path), ScanContext(raw_dir=raw, exclude=[]))

    assert result.status is ScanStatus.OK, result.reason
    args = args_file.read_text(encoding="utf-8").splitlines()
    configs = [args[i + 1] for i, arg in enumerate(args) if arg == "--config"]
    assert configs == ["p/default", str(bundled / "llm.yml")]
