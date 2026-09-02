"""除外パターンのテスト."""

from __future__ import annotations

import pytest

from security_checker.scanners.filters import is_excluded

PATTERNS = ["**/vendor/**", "**/*.min.js", "tests/fixtures/**", "build/*"]


@pytest.mark.parametrize(
    "path",
    [
        "vendor/lib/x.py",
        "src/vendor/lib/x.py",
        "static/app.min.js",
        "tests/fixtures/vulnerable-app/app.py",
        "build/out.js",
    ],
)
def test_excluded(path):
    assert is_excluded(path, PATTERNS)


@pytest.mark.parametrize(
    "path",
    ["src/app.py", "vendors/app.py", "static/app.js", "tests/unit/test_x.py", "build/a/b.js"],
)
def test_not_excluded(path):
    assert not is_excluded(path, PATTERNS)


def test_windows_separator_is_normalized():
    assert is_excluded("src\\vendor\\x.py", PATTERNS)
