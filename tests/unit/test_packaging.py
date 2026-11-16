"""配布物の作り方の整合 (ビルドバックエンドの固定・sdist の範囲・ライセンスの宣言)."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_build_backend_is_pinned_and_matches_the_locked_group():
    # build-system.requires は uv.lock の対象外. 同じ版を build グループにも書き、
    # ハッシュをロックファイルに持たせている。片方だけ上げると検証が素通りになる
    requires = PYPROJECT["build-system"]["requires"]
    assert requires == PYPROJECT["dependency-groups"]["build"]
    assert all("==" in requirement for requirement in requires)


def test_locked_build_group_is_used_wherever_the_package_is_built():
    for path in (".github/workflows/release.yml", ".github/workflows/ci.yml", "Dockerfile"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "--only-group build" in text, path
        assert "--require-hashes" in text, path


def test_sdist_is_an_allow_list_without_development_files():
    sdist = PYPROJECT["tool"]["hatch"]["build"]["targets"]["sdist"]
    included = {entry.strip("/") for entry in sdist["include"]}
    assert included.isdisjoint({".claude", ".github", "benchmarks", "ci", "contrib", "skills"})
    assert "/tests/fixtures/vulnerable-app" in sdist["exclude"]


def test_license_is_declared_as_an_spdx_expression():
    project = PYPROJECT["project"]
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert not any(c.startswith("License ::") for c in project["classifiers"])
