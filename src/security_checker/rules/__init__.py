"""security-checker が同梱するスキャナのルール.

設定からは `bundled:<名前>` で指す (例: `scanners.semgrep.config: [p/default, bundled:llm]`)。
解決先は常にこのパッケージの中で、検査対象のツリーには依存しない。検査対象に同名のファイルを
置いても差し替えられない (untrusted-target でも同じ)。
"""

from __future__ import annotations

from pathlib import Path

BUNDLED_PREFIX = "bundled:"

SEMGREP_DIR = Path(__file__).parent / "semgrep"


def bundled_semgrep_rules() -> list[str]:
    """同梱している semgrep ルールの名前 (`bundled:` の後ろに書くもの)."""
    if not SEMGREP_DIR.is_dir():
        return []
    return sorted(path.stem for path in SEMGREP_DIR.glob("*.yml"))


def bundled_semgrep_rule(name: str) -> Path | None:
    """`bundled:<name>` の解決先. 無ければ None."""
    # 名前にパス区切りを許さない (パッケージの外を指せないようにする)
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    path = SEMGREP_DIR / f"{name}.yml"
    return path if path.is_file() else None
