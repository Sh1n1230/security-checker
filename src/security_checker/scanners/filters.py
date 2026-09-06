"""パス除外 (設定 `target.exclude`) の判定."""

from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    """gitignore 風の glob を正規表現へ変換する (`**` はディレクトリ跨ぎ)."""
    index = 0
    out: list[str] = []
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif char == "*":
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(char))
            index += 1
    return re.compile("^" + "".join(out) + "$")


def is_excluded(path: str, patterns: list[str]) -> bool:
    """相対パスが除外パターンのいずれかに一致するか."""
    normalized = path.replace("\\", "/").removeprefix("./")
    for pattern in patterns:
        regex = _compile(pattern.removeprefix("./"))
        if regex.match(normalized):
            return True
        # "tests/fixtures/**" のようにディレクトリ配下全体を指す書き方への対応
        if pattern.endswith("/**") and normalized.startswith(pattern[:-3].removeprefix("./") + "/"):
            return True
    return False
