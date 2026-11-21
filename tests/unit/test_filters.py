"""除外パターンのテスト."""

from __future__ import annotations

import pytest

from security_checker.scanners.filters import is_excluded, normalize_pattern

PATTERNS = ["**/vendor/**", "**/*.min.js", "tests/fixtures/**", "build/*"]


@pytest.mark.parametrize(
    "path",
    [
        "vendor/lib/x.py",
        "src/vendor/lib/x.py",
        "static/app.min.js",
        "tests/fixtures/vulnerable-app/app.py",
        "build/out.js",
        # gitignore と同じく、一致したディレクトリ (build/a) の配下も除外する
        "build/a/b.js",
    ],
)
def test_excluded(path):
    assert is_excluded(path, PATTERNS)


@pytest.mark.parametrize(
    "path",
    ["src/app.py", "vendors/app.py", "static/app.js", "tests/unit/test_x.py", "src/build.py"],
)
def test_not_excluded(path):
    assert not is_excluded(path, PATTERNS)


def test_windows_separator_is_normalized():
    assert is_excluded("src\\vendor\\x.py", PATTERNS)


@pytest.mark.parametrize(
    ("path", "pattern"),
    [
        ("build/out.js", "build/"),
        ("build/out.js", "build"),
        ("pkg/tests/test_a.py", "tests"),
        ("a/b/c.min.js", "*.min.js"),
        ("build/out.js", "/build"),
        ("build/out.js", "./build/"),
    ],
)
def test_gitignore_style_patterns(path, pattern):
    """semgrep の --exclude と同じく gitignore の感覚で書ける (#93).

    スキャナごとに意味が変わると、除外が一部のスキャナにしか効かない。
    """
    assert is_excluded(path, [pattern])


@pytest.mark.parametrize(
    ("path", "pattern"),
    [
        ("src/build/out.js", "/build"),  # 先頭の / はルート起点
        ("pkg/build/out.js", "src/build/"),  # 途中に / を含むパターンもルート起点
        ("buildx/out.js", "build"),
    ],
)
def test_patterns_that_do_not_match(path, pattern):
    assert not is_excluded(path, [pattern])


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("build/", "**/build/**"),
        ("tests", "**/tests"),
        ("/docs/", "docs/**"),
        ("/build", "build"),
        ("src/gen", "src/gen"),
        ("**/vendor/**", "**/vendor/**"),
    ],
)
def test_normalize_pattern(pattern, expected):
    assert normalize_pattern(pattern) == expected


def test_several_patterns_are_checked_together():
    patterns = ["docs/", "*.min.js", "/build"]
    assert is_excluded("a/docs/x.md", patterns)
    assert is_excluded("a/b.min.js", patterns)
    assert is_excluded("build/x", patterns)
    assert not is_excluded("src/build/x", patterns)
    assert not is_excluded("src/app.py", patterns)


def test_no_patterns_exclude_nothing():
    assert not is_excluded("anything", [])
    assert not is_excluded("", ())


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        # `$` は末尾の改行の手前でも一致する. パス全体との一致で判定し、改行で結果を変えない
        ("tests\n", "tests", False),
        ("tests/x\n", "tests", True),
        ("a\nb/c.py", "**/c.py", True),
        ("x\n/vendor/y", "vendor/", True),
    ],
)
def test_newlines_in_file_names(path, pattern, expected):
    assert is_excluded(path, [pattern]) is expected
