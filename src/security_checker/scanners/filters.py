"""パス除外の判定. `target.exclude`・`.security-checker-ignore`・`rule:` のパス限定で共通に使う.

解釈は gitignore にそろえる (semgrep の `--exclude` も gitignore に近い)。スキャナによって
同じパターンの意味が変わると、除外が一部のスキャナにしか効かない。
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def _glob_to_regex(pattern: str) -> str:
    """gitignore 風の glob を、錨の無い正規表現の本体へ変換する (`**` はディレクトリ跨ぎ)."""
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
    return "".join(out)


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


@lru_cache(maxsize=256)
def _compile_set(patterns: tuple[str, ...]) -> re.Pattern[str]:
    """除外パターンの組を、パス自身か祖先ディレクトリのどれかに一致する 1 つの正規表現にまとめる.

    パス全体が `(?:p1|p2|...)(?:/.*)?` に一致することは、「`/` の区切りで切ったパスの先頭部分の
    どれかが p に一致する」と同じ。祖先ごと・パターンごとに照合しなくて済む
    (リポジトリの走査では、ファイルとディレクトリのたびに呼ばれる)。

    パス全体との一致 (fullmatch) で判定し、`.` は改行にも一致させる。`$` は末尾の改行の手前でも
    一致するので、使うと改行を含むファイル名で結果が変わってしまう。
    """
    if not patterns:
        return re.compile(r"(?!)")  # 何にも一致しない
    bodies = "|".join(_glob_to_regex(normalize_pattern(p)) for p in patterns)
    return re.compile(f"(?:{bodies})(?:/.*)?", re.DOTALL)


def is_excluded(path: str, patterns: Sequence[str]) -> bool:
    """相対パスが除外パターンのいずれかに一致するか.

    gitignore と同じく、ディレクトリが一致したらその配下もすべて一致とみなす
    (`tests` は `pkg/tests/test_a.py` も除外する)。
    """
    normalized = path.replace("\\", "/").removeprefix("./")
    return _compile_set(tuple(patterns)).fullmatch(normalized) is not None


def exclude_globs(patterns: list[str]) -> list[str]:
    """スキャナの除外オプションに渡す、ルートからの glob (重複なし・順序は保つ).

    スキャナ側で除外すると、除外したディレクトリを読まずに済む (`node_modules` など)。
    スキャナの glob の解釈がこちらと少し違っても、結果側の `is_excluded` が最後に効く。
    """
    return list(dict.fromkeys(normalize_pattern(p) for p in patterns if p.strip()))
