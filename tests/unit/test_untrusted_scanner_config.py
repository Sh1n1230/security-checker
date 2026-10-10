"""信用できない検査対象では、スキャナ自身の設定も対象のツリーから読ませない (#43).

PR が `.gitleaks.toml` などを置くだけで自分の検出を消せないことを、各スキャナの argv で押さえる。
実スキャナでの確認は tests/e2e/test_untrusted_scanner_config.py。
"""

from __future__ import annotations

import os
import shlex
import stat
from pathlib import Path

import pytest

from security_checker.config.schema import (
    Config,
    GitleaksConfig,
    OsvConfig,
    SemgrepConfig,
    TrivyConfig,
)
from security_checker.policy.suppress import load_rules
from security_checker.scanners.base import BaseScanner, ScanContext, Target
from security_checker.scanners.gitleaks import GitleaksScanner
from security_checker.scanners.osv import OsvScanner
from security_checker.scanners.semgrep import SemgrepScanner
from security_checker.scanners.trivy import TrivyScanner
from security_checker.scanners.untrusted import (
    GITLEAKS_DEFAULT_CONFIG,
    prepare_overrides,
    residual_warnings,
)

VERSION_GUARD = 'case "$1" in --version|version) echo "fake 1.0"; exit 0;; esac\n'


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("偽のコマンドは #!/bin/sh のスクリプトで作るため POSIX のみ")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return bin_dir


def recorder(bin_dir: Path, name: str, log: Path, output: str) -> None:
    """argv を 1 行 1 引数で記録し、空の結果を返す偽コマンド."""
    path = bin_dir / name
    path.write_text(
        "#!/bin/sh\n"
        + VERSION_GUARD
        + f'for a in "$@"; do printf "%s\\n" "$a"; done > {shlex.quote(str(log))}\n'
        + output,
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def context(tmp_path: Path, *, untrusted: bool) -> ScanContext:
    raw = tmp_path / "raw"
    raw.mkdir(exist_ok=True)
    overrides = prepare_overrides(tmp_path / "overrides") if untrusted else None
    return ScanContext(raw_dir=raw, exclude=[], untrusted=overrides)


async def argv_of(
    scanner: BaseScanner, name: str, output: str, fake_bin: Path, tmp_path: Path, untrusted: bool
) -> list[str]:
    log = tmp_path / f"{name}.argv"
    recorder(fake_bin, name, log, output)
    target = tmp_path / "pr"
    target.mkdir(exist_ok=True)
    await scanner.scan(Target(root=target), context(tmp_path, untrusted=untrusted))
    lines = log.read_text(encoding="utf-8").split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def value_after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def assert_outside_file(argv: list[str], flag: str, tmp_path: Path, content: str) -> None:
    """flag の値が検査対象 (tmp_path/pr) の外にあり、中身が content であること."""
    path = Path(value_after(argv, flag))
    assert not path.is_relative_to(tmp_path / "pr")
    assert path.read_text(encoding="utf-8") == content


def assert_outside_dir(argv: list[str], flag: str, tmp_path: Path) -> None:
    path = Path(value_after(argv, flag))
    assert not path.is_relative_to(tmp_path / "pr")
    assert path.is_dir()


# --- 各スキャナの argv -------------------------------------------------------------


@pytest.mark.parametrize("untrusted", [False, True])
async def test_gitleaks(fake_bin, tmp_path, untrusted):
    # `dir --help` が成功する = 8.19+ として扱われる
    argv = await argv_of(
        GitleaksScanner(GitleaksConfig()), "gitleaks", "exit 0\n", fake_bin, tmp_path, untrusted
    )
    if not untrusted:
        assert "--config" not in argv
        assert "--ignore-gitleaks-allow" not in argv
        return
    assert_outside_file(argv, "--config", tmp_path, GITLEAKS_DEFAULT_CONFIG)
    assert_outside_dir(argv, "--gitleaks-ignore-path", tmp_path)
    assert "--ignore-gitleaks-allow" in argv


@pytest.mark.parametrize("untrusted", [False, True])
async def test_semgrep(fake_bin, tmp_path, untrusted):
    argv = await argv_of(
        SemgrepScanner(SemgrepConfig()),
        "semgrep",
        "echo '{\"results\": []}'\n",
        fake_bin,
        tmp_path,
        untrusted,
    )
    assert ("--disable-nosem" in argv) is untrusted


@pytest.mark.parametrize("untrusted", [False, True])
async def test_trivy(fake_bin, tmp_path, untrusted):
    argv = await argv_of(
        TrivyScanner(TrivyConfig()), "trivy", "exit 0\n", fake_bin, tmp_path, untrusted
    )
    if not untrusted:
        assert "--config" not in argv
        assert "--ignorefile" not in argv
        return
    assert_outside_file(argv, "--config", tmp_path, "")
    # 空文字列は trivy の「読み込まない」
    assert value_after(argv, "--ignorefile") == ""


@pytest.mark.parametrize("untrusted", [False, True])
async def test_osv(fake_bin, tmp_path, untrusted):
    argv = await argv_of(
        OsvScanner(OsvConfig()), "osv-scanner", "echo '{}'\nexit 0\n", fake_bin, tmp_path, untrusted
    )
    if not untrusted:
        assert "--config" not in argv
        return
    assert_outside_file(argv, "--config", tmp_path, "")


async def test_extra_args_from_trusted_config_come_last(fake_bin, tmp_path):
    """信頼できる設定の extra_args で渡した設定は、上書き用の設定より後ろ (= 優先) に来る."""
    argv = await argv_of(
        OsvScanner(OsvConfig(extra_args=["--config", "/trusted/osv.toml"])),
        "osv-scanner",
        "echo '{}'\nexit 0\n",
        fake_bin,
        tmp_path,
        True,
    )
    configs = [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]
    assert configs[-1] == "/trusted/osv.toml"


# --- 止められないものは警告にする -----------------------------------------------------


def test_residual_warnings_list_files_scanners_always_read(tmp_path):
    (tmp_path / ".gitleaksignore").write_text("x\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".semgrepignore").write_text("a.py\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / ".semgrepignore").write_text("*\n")
    warnings = residual_warnings(tmp_path)
    assert any(".gitleaksignore" in w for w in warnings)
    semgrep = next(w for w in warnings if ".semgrepignore" in w)
    assert "sub/.semgrepignore" in semgrep
    assert "node_modules" not in semgrep


def test_residual_warnings_are_empty_for_a_clean_tree(tmp_path):
    assert residual_warnings(tmp_path) == []


def test_suppression_rules_carry_the_untrusted_flag(tmp_path):
    assert load_rules(Config(), tmp_path, untrusted_target=True).untrusted_target is True
    assert load_rules(Config(), tmp_path).untrusted_target is False
