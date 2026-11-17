"""配布物 (sdist・wheel) の中身を確かめる. CI とリリースの両方で実行する.

    python scripts/check-dist.py dist

- sdist に、開発用の設定・CI の定義・意図的に脆弱なデータを入れない (#261)
- wheel にはパッケージ本体とメタデータだけを入れる
- ライセンスは SPDX 式で宣言する (PEP 639) (#262)

標準ライブラリだけで動かす (ビルドした環境に依存を足さないため)。
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

#: sdist の最上位に置いてよいもの. ここに無い名前が入ったら失敗させる (許可リスト)
SDIST_TOP_LEVEL = frozenset(
    {
        ".gitignore",
        "CHANGELOG.md",
        "LICENSE",
        "PKG-INFO",
        "README.ja.md",
        "README.md",
        "pyproject.toml",
        "src",
        "tests",
        "uv.lock",
    }
)
#: sdist に入れないパス (最上位が許可されていても、その下で禁じるもの)
SDIST_FORBIDDEN = ("tests/fixtures/vulnerable-app/",)
PACKAGE = "security_checker"
EXPECTED_ARGS = 2


def check_sdist(path: Path) -> list[str]:
    """sdist の問題点を返す. 空なら問題なし."""
    with tarfile.open(path) as archive:
        names = [name.split("/", 1)[1] for name in archive.getnames() if "/" in name]
    problems = [
        f"{path.name}: 配布しないものが入っています: {name}"
        for name in sorted({name.split("/", 1)[0] for name in names} - SDIST_TOP_LEVEL)
    ]
    problems += [
        f"{path.name}: 配布しないものが入っています: {name}"
        for name in names
        if name.startswith(SDIST_FORBIDDEN)
    ]
    return problems


def check_wheel(path: Path) -> list[str]:
    """wheel の問題点を返す. 空なら問題なし."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    problems = [
        f"{path.name}: パッケージの外のファイルが入っています: {name}"
        for name in names
        if not name.startswith((f"{PACKAGE}/", f"{PACKAGE}-"))
    ]
    if "License-Expression: MIT" not in metadata.splitlines():
        problems.append(f"{path.name}: METADATA に License-Expression: MIT がありません")
    return problems


def main(directory: Path) -> int:
    """`directory` の配布物をすべて確かめ、問題があれば 1 を返す."""
    sdists = sorted(directory.glob("*.tar.gz"))
    wheels = sorted(directory.glob("*.whl"))
    problems = []
    if not sdists or not wheels:
        problems.append(f"{directory}: sdist と wheel の両方が必要です")
    for sdist in sdists:
        problems += check_sdist(sdist)
    for wheel in wheels:
        problems += check_wheel(wheel)
    for problem in problems:
        sys.stderr.write(problem + "\n")
    if not problems:
        sys.stdout.write(f"ok: {len(sdists)} sdist, {len(wheels)} wheel\n")
    return int(bool(problems))


if __name__ == "__main__":
    if len(sys.argv) != EXPECTED_ARGS:
        raise SystemExit("usage: check-dist.py <dist ディレクトリ>")
    raise SystemExit(main(Path(sys.argv[1])))
