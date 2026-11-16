"""スキャナの失敗を「0 件の成功」にしない (設計書 §7.2・P9).

タイムアウト・壊れた出力・壊れたエントリを、コマンドの実行を差し替えて確かめる。
実ツールは使わない。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from security_checker.config.schema import GitleaksConfig, OsvConfig, SemgrepConfig, TrivyConfig
from security_checker.errors import ConfigError
from security_checker.models.enums import ScanStatus, Severity
from security_checker.scanners import base, gitleaks, osv, registry, semgrep, trivy, untrusted
from security_checker.scanners.base import (
    CommandResult,
    ScanContext,
    Target,
    ToolStatus,
    excerpt,
    probe_command,
    relative_path,
)
from security_checker.scanners.filters import is_excluded
from security_checker.scanners.gitleaks import GitleaksScanner
from security_checker.scanners.osv import OsvScanner, parse_osv, severity_from_score
from security_checker.scanners.semgrep import SemgrepScanner, resolve_config
from security_checker.scanners.trivy import TrivyScanner, parse_trivy

AVAILABLE = ToolStatus(available=True, version="fake 1.0")


def ctx(tmp_path: Path) -> ScanContext:
    raw = tmp_path / "raw"
    raw.mkdir(exist_ok=True)
    return ScanContext(raw_dir=raw, exclude=[])


def stub_run(
    monkeypatch: pytest.MonkeyPatch, module: Any, result: CommandResult
) -> list[list[str]]:
    """モジュールの run_command を差し替え、渡された argv を記録する."""
    calls: list[list[str]] = []

    async def fake(argv: list[str], **kwargs: Any) -> CommandResult:
        calls.append(argv)
        return result

    monkeypatch.setattr(module, "run_command", fake)
    return calls


TIMED_OUT = CommandResult(exit_code=None, stdout=b"", stderr=b"", timed_out=True)
SUCCEEDED = CommandResult(exit_code=0, stdout=b"", stderr=b"")


# --- 共通の部品 -------------------------------------------------------------------


def test_version_probe_failure_keeps_the_tool_available(monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda name: "/fake/bin/tool")

    def boom(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="tool", timeout=15)

    monkeypatch.setattr(base.subprocess, "run", boom)
    status = probe_command("tool")
    assert status.available is True
    assert status.version is None
    assert "バージョン取得に失敗しました" in (status.reason or "")


def test_whitespace_only_stderr_has_no_excerpt():
    assert excerpt(b" \n\t ") is None


def test_relative_path_drops_a_leading_dot_slash(tmp_path):
    assert relative_path("./src/app.py", tmp_path) == "src/app.py"


def test_question_mark_matches_one_character_but_not_a_separator():
    assert is_excluded("a1.py", ["a?.py"])
    assert not is_excluded("a/.py", ["a?.py"])
    assert not is_excluded("a12.py", ["a?.py"])


class _Entry:
    def __init__(self, name: str, loaded: Any) -> None:
        self.name = name
        self._loaded = loaded

    def load(self) -> Any:
        if isinstance(self._loaded, Exception):
            raise self._loaded
        return self._loaded


def test_broken_scanner_plugin_is_a_warning_and_the_rest_still_load(monkeypatch):
    entries = [_Entry("good", GitleaksScanner), _Entry("broken", ImportError("missing dep"))]
    monkeypatch.setattr(registry, "entry_points", lambda group: entries)
    found, warnings = registry.discover_plugin_scanners()
    assert found == {"good": GitleaksScanner}
    assert len(warnings) == 1
    assert "broken" in warnings[0]
    assert "missing dep" in warnings[0]


# --- タイムアウト -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "scanner", "tool"),
    [
        (semgrep, SemgrepScanner(SemgrepConfig(timeout_s=7)), "semgrep"),
        (gitleaks, GitleaksScanner(GitleaksConfig(timeout_s=7)), "gitleaks"),
        (osv, OsvScanner(OsvConfig(timeout_s=7)), "osv-scanner"),
        (trivy, TrivyScanner(TrivyConfig(timeout_s=7)), "trivy"),
    ],
)
async def test_timeout_is_failed_not_empty(monkeypatch, tmp_path, module, scanner, tool):
    monkeypatch.setattr(type(scanner), "probe", lambda self: AVAILABLE)
    stub_run(monkeypatch, module, TIMED_OUT)
    result = await scanner.scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED
    assert result.reason == f"{tool} が 7s でタイムアウトしました"
    assert result.candidates == []


# --- 壊れた出力 -------------------------------------------------------------------


async def test_semgrep_output_that_is_not_json_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(SemgrepScanner, "probe", lambda self: AVAILABLE)
    stub_run(monkeypatch, semgrep, SUCCEEDED)  # stdout_path には何も書かれない
    result = await SemgrepScanner(SemgrepConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED
    assert "semgrep の出力を解釈できません" in (result.reason or "")


async def test_osv_output_that_is_not_json_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(OsvScanner, "probe", lambda self: AVAILABLE)

    async def garbage(argv: list[str], *, stdout_path: Path, **kwargs: Any) -> CommandResult:
        stdout_path.write_text("{truncated", encoding="utf-8")
        return SUCCEEDED

    monkeypatch.setattr(osv, "run_command", garbage)
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED
    assert "osv-scanner の出力を解釈できません" in (result.reason or "")


async def test_gitleaks_report_that_is_not_json_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(GitleaksScanner, "probe", lambda self: AVAILABLE)
    monkeypatch.setattr(GitleaksScanner, "_supports_dir_subcommand", staticmethod(lambda: True))

    async def garbage(argv: list[str], **kwargs: Any) -> CommandResult:
        Path(argv[argv.index("--report-path") + 1]).write_text("{truncated", encoding="utf-8")
        return SUCCEEDED

    monkeypatch.setattr(gitleaks, "run_command", garbage)
    result = await GitleaksScanner(GitleaksConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED
    assert "gitleaks の出力を解釈できません" in (result.reason or "")


async def test_gitleaks_nonzero_exit_is_failed_with_stderr(monkeypatch, tmp_path):
    monkeypatch.setattr(GitleaksScanner, "probe", lambda self: AVAILABLE)
    monkeypatch.setattr(GitleaksScanner, "_supports_dir_subcommand", staticmethod(lambda: True))
    stub_run(monkeypatch, gitleaks, CommandResult(exit_code=1, stdout=b"", stderr=b"bad config"))
    result = await GitleaksScanner(GitleaksConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED
    assert "シークレット検査は行われていません" in (result.reason or "")
    assert result.stderr_excerpt == "bad config"


# --- gitleaks の旧版 --------------------------------------------------------------


async def test_old_gitleaks_without_dir_uses_detect_no_git(monkeypatch, tmp_path):
    monkeypatch.setattr(GitleaksScanner, "probe", lambda self: AVAILABLE)
    monkeypatch.setattr(GitleaksScanner, "_supports_dir_subcommand", staticmethod(lambda: False))
    calls = stub_run(monkeypatch, gitleaks, TIMED_OUT)
    await GitleaksScanner(GitleaksConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert calls[0][:5] == ["gitleaks", "detect", "--no-git", "--source", "."]


def test_dir_subcommand_is_unsupported_when_gitleaks_is_missing_or_cannot_run(monkeypatch):
    monkeypatch.setattr(gitleaks.shutil, "which", lambda name: None)
    assert GitleaksScanner._supports_dir_subcommand() is False

    monkeypatch.setattr(gitleaks.shutil, "which", lambda name: "/fake/bin/gitleaks")

    def boom(*args: Any, **kwargs: Any) -> None:
        raise OSError("exec format error")

    monkeypatch.setattr(gitleaks.subprocess, "run", boom)
    assert GitleaksScanner._supports_dir_subcommand() is False


# --- trivy ------------------------------------------------------------------------


async def test_trivy_missing_is_skipped(monkeypatch, tmp_path):
    monkeypatch.setattr(
        TrivyScanner, "probe", lambda self: ToolStatus(available=False, reason="trivy が無い")
    )
    result = await TrivyScanner(TrivyConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.SKIPPED
    assert result.reason == "trivy が無い"


def test_trivy_results_that_are_not_a_list_are_reported(tmp_path):
    candidates, warnings = parse_trivy({"Results": {"Target": "Dockerfile"}}, tmp_path)
    assert candidates == []
    assert warnings == ["trivy の出力の Results が配列ではありません"]


def test_trivy_skips_broken_entries_with_a_warning_each(tmp_path):
    payload = {
        "Results": [
            {"Misconfigurations": [{"Status": "FAIL", "ID": "DS-1"}]},  # Target が無い
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"Status": "PASS", "ID": "DS-0001"},  # 通過したチェックは候補にしない
                    {"Status": "FAIL", "Title": "ID が無い"},
                ],
                "Vulnerabilities": [{"PkgName": "left-pad"}, {"VulnerabilityID": "CVE-1"}],
            },
        ]
    }
    candidates, warnings = parse_trivy(payload, tmp_path)
    assert candidates == []
    assert warnings == [
        "trivy の結果に Target がありません",
        "Dockerfile: ID の無い誤設定を読み飛ばしました",
        "Dockerfile: ID かパッケージ名の無い脆弱性を読み飛ばしました",
        "Dockerfile: ID かパッケージ名の無い脆弱性を読み飛ばしました",
    ]


def test_trivy_drops_results_under_excluded_paths(tmp_path):
    payload = {
        "Results": [
            {
                "Target": "vendor/Dockerfile",
                "Misconfigurations": [{"Status": "FAIL", "ID": "DS-0002", "Severity": "HIGH"}],
            }
        ]
    }
    assert parse_trivy(payload, tmp_path, exclude=["vendor/**"]) == ([], [])


# --- osv --------------------------------------------------------------------------


def test_cvss_zero_is_none():
    assert severity_from_score(0.0) is Severity.NONE


def _osv_result(packages: list[dict[str, Any]], path: Any = "uv.lock") -> dict[str, Any]:
    return {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": packages}]}


def test_osv_skips_broken_entries_with_a_warning_each(tmp_path):
    payload = {
        "results": [
            {"source": {"type": "lockfile"}, "packages": []},  # source.path が無い
            {
                "source": {"path": "uv.lock", "type": "lockfile"},
                "packages": [
                    {"package": {"ecosystem": "PyPI"}, "vulnerabilities": [{"id": "GHSA-1"}]},
                ],
            },
        ]
    }
    candidates, warnings = parse_osv(payload, tmp_path)
    assert candidates == []
    assert warnings == [
        "osv-scanner の結果に source.path がありません",
        "uv.lock: パッケージ名の無い結果を読み飛ばしました",
    ]


def test_osv_group_without_ids_is_ignored(tmp_path):
    package = {
        "package": {"name": "p", "ecosystem": "PyPI", "version": "1.0"},
        "vulnerabilities": [{"id": "GHSA-1"}],
        "groups": [{"ids": []}, {"ids": ["GHSA-1"]}],
    }
    candidates, warnings = parse_osv(_osv_result([package]), tmp_path)
    assert [c.rule_id for c in candidates] == ["GHSA-1"]
    assert warnings == []


def test_osv_max_severity_that_is_not_a_number_falls_back_to_the_text(tmp_path):
    package = {
        "package": {"name": "p", "ecosystem": "PyPI", "version": "1.0"},
        "vulnerabilities": [{"id": "GHSA-1", "database_specific": {"severity": "HIGH"}}],
        "groups": [{"ids": ["GHSA-1"], "max_severity": "n/a"}],
    }
    candidates, _ = parse_osv(_osv_result([package]), tmp_path)
    assert candidates[0].severity_reported is Severity.HIGH


def test_osv_fixed_version_ignores_other_packages_in_the_same_advisory():
    vulns = [
        {
            "affected": [
                {
                    "package": {"name": "other"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9.9"}]}],
                },
                {
                    "package": {"name": "p"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.2.3"}]}],
                },
            ]
        }
    ]
    assert osv._fixed_version(vulns, "p", "1.0") == "1.2.3"


def test_osv_stderr_warnings_are_capped():
    stderr = "\n".join(
        f"warning: could not parse lock {n}" for n in range(osv.MAX_STDERR_WARNINGS + 4)
    )
    shown = osv._stderr_warnings(stderr.encode())
    assert len(shown) == osv.MAX_STDERR_WARNINGS + 1
    assert shown[-1] == "osv-scanner: ほか 4 行の警告 (stderr を参照)"


# --- semgrep ----------------------------------------------------------------------


def test_unknown_bundled_rule_is_a_config_error():
    with pytest.raises(ConfigError, match="未知の同梱ルール bundled:no-such-rule"):
        resolve_config("bundled:no-such-rule")


def test_semgrep_line_zero_has_no_source_text(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert semgrep._read_lines(tmp_path, "a.py", 0, 0) is None


# --- 信用しない検査対象 -----------------------------------------------------------


def test_annotation_scan_skips_huge_and_unreadable_files(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_bytes(b"# trivy:ignore:DS-0002\nFROM scratch\n")
    monkeypatch.setattr(untrusted, "_MAX_ANNOTATION_SCAN_BYTES", 4)
    assert untrusted._find_trivy_annotations(tmp_path) == []

    monkeypatch.setattr(untrusted, "_MAX_ANNOTATION_SCAN_BYTES", 1_000_000)
    assert untrusted._find_trivy_annotations(tmp_path) == ["Dockerfile"]

    def deny(self: Path) -> bytes:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_bytes", deny)
    assert untrusted._find_trivy_annotations(tmp_path) == []
