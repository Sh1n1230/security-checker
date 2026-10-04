"""自己適用 (dogfooding) の不変条件 (設計書 §31.5 L3).

このリポジトリ自身の security-checker.yml は、意図的に脆弱なフィクスチャを検査対象から外している。
除外パターンが広すぎて**本体パッケージまで検査から外れている**と、自己検査が形だけになる。
"""

from __future__ import annotations

from pathlib import Path

from security_checker.config.loader import load_config
from security_checker.scanners.filters import is_excluded

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "src" / "security_checker"


def test_no_package_file_is_excluded_from_self_scan():
    loaded = load_config(REPO, config_path=REPO / "security-checker.yml", environ={})
    patterns = loaded.config.target.exclude
    files = [p.relative_to(REPO).as_posix() for p in PACKAGE.rglob("*") if p.is_file()]
    files = [f for f in files if "__pycache__" not in f]
    assert files, "本体パッケージが見つかりません"
    excluded = [f for f in files if is_excluded(f, patterns)]
    assert excluded == [], f"本体のファイルが自己検査から外れています: {excluded[:5]}"


def test_intentionally_vulnerable_fixtures_are_excluded():
    """逆に、フィクスチャが検査対象に入ると自己検査が常に赤になり、誰も見なくなる."""
    loaded = load_config(REPO, config_path=REPO / "security-checker.yml", environ={})
    patterns = loaded.config.target.exclude
    assert is_excluded("tests/fixtures/vulnerable-app/app.py", patterns)
    assert is_excluded("benchmarks/datasets/handmade-v1/cases/0001.yaml", patterns)
