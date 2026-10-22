"""パス除外の判定. `target.exclude`・`.security-checker-ignore`・`rule:` のパス限定で共通に使う.

解釈は gitignore にそろえる (semgrep の `--exclude` も gitignore に近い)。スキャナによって
同じパターンの意味が変わると、除外が一部のスキャナにしか効かない。
"""

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


def normalize_pattern(pattern: str) -> str:
    """gitignore の書き方を、ルートからの glob にそろえる.

    - 先頭か途中に `/` があればルート起点 (`/build` → `build`、`src/gen` → `src/gen`)
    - それ以外はどの階層にも一致させる (`tests` → `**/tests`、`build/` → `**/build/**`)
    - 末尾の `/` はディレクトリの配下だけ (`build/` → `**/build/**`)
    """
    raw = pattern.strip().removeprefix("./")
    anchored = "/" in raw.rstrip("/")
    directory_only = raw.endswith("/")
    normalized = raw.strip("/")
    if not anchored:
        normalized = "**/" + normalized
    if directory_only:
        normalized += "/**"
    return normalized


def is_excluded(path: str, patterns: list[str]) -> bool:
    """相対パスが除外パターンのいずれかに一致するか.

    gitignore と同じく、ディレクトリが一致したらその配下もすべて一致とみなす
    (`tests` は `pkg/tests/test_a.py` も除外する)。
    """
    normalized = path.replace("\\", "/").removeprefix("./")
    parts = normalized.split("/")
    # パス自身と、その祖先ディレクトリ
    targets = ["/".join(parts[: index + 1]) for index in range(len(parts))]
    for pattern in patterns:
        regex = _compile(normalize_pattern(pattern))
        if any(regex.match(target) for target in targets):
            return True
    return False
