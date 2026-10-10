"""スキャナの版と sha256 を 1 か所に固定し、すべての経路がそこを使う (#45).

版を経路ごとに書くと、composite action と Docker イメージで結果が食い違う。
「最新版」を取りに行くと、スキャナのリリースが乗っ取られたときに次の CI で悪性のバイナリが動く。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "scripts" / "scanner-versions.sh"
INSTALLER = ROOT / "scripts" / "install-scanners.sh"

#: action.yml の input 名 → install-scanners.sh が読む環境変数名
INPUTS = {
    "gitleaks-version": "GITLEAKS_VERSION",
    "trivy-version": "TRIVY_VERSION",
    "osv-scanner-version": "OSV_SCANNER_VERSION",
    "semgrep-version": "SEMGREP_VERSION",
}
BINARIES = ("GITLEAKS", "TRIVY", "OSV_SCANNER")


def pinned() -> dict[str, str]:
    text = VERSIONS.read_text(encoding="utf-8")
    return dict(re.findall(r"^([A-Z0-9_]+)=(\S+)", text, flags=re.MULTILINE))


def action() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    return loaded


@pytest.mark.parametrize("name", [*BINARIES, "SEMGREP"])
def test_versions_are_pinned(name):
    assert re.fullmatch(r"\d+\.\d+\.\d+", pinned()[f"PINNED_{name}_VERSION"])


@pytest.mark.parametrize("name", BINARIES)
@pytest.mark.parametrize("arch", ["AMD64", "ARM64"])
def test_binaries_have_pinned_sha256_for_each_arch(name, arch):
    assert re.fullmatch(r"[0-9a-f]{64}", pinned()[f"{name}_SHA256_{arch}"])


@pytest.mark.parametrize(("input_name", "env_name"), sorted(INPUTS.items()))
def test_action_passes_version_inputs_and_defaults_to_pinned(input_name, env_name):
    spec = action()["inputs"][input_name]
    # 既定は空 (= 固定版)。latest や版を既定にすると、ここ以外に版の置き場所ができる
    assert spec["default"] == ""
    steps = action()["runs"]["steps"]
    install = next(s for s in steps if "install-scanners.sh" in s.get("run", ""))
    assert install["env"][env_name] == f"${{{{ inputs.{input_name} }}}}"


def test_dockerfile_uses_the_same_installer_without_its_own_versions():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "install-scanners.sh" in text
    for env_name in INPUTS.values():
        assert f'ARG {env_name}=""' in text


@pytest.mark.parametrize(
    "path",
    [
        ROOT / "action.yml",
        ROOT / "Dockerfile",
        *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
    ],
    ids=lambda p: p.name,
)
def test_nothing_fetches_latest_scanner_releases(path):
    assert "releases/latest" not in path.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="実行権限は POSIX のみ")
def test_installer_is_executable():
    """action・workflow・Dockerfile は bash を介さず直接実行する."""
    assert os.access(INSTALLER, os.X_OK)


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="bash が必要")
@pytest.mark.parametrize("value", ["foo;rm -rf /", "1.2", "latest; echo", "1.2.3-rc1"])
def test_installer_rejects_malformed_versions_before_downloading(tmp_path, value):
    result = subprocess.run(
        ["bash", str(INSTALLER), str(tmp_path / "bin")],
        env={**os.environ, "TRIVY_VERSION": value},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2
    assert "版の指定が不正" in result.stderr
    assert not (tmp_path / "bin").exists()
