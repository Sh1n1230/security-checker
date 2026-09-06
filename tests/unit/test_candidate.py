"""安定 ID とパス不変条件のテスト (設計書 §6.1)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_checker.models.candidate import (
    IdFactory,
    Location,
    candidate_id,
    normalize_snippet,
)


def test_id_is_stable_across_line_moves():
    first = candidate_id("semgrep", "rules.x", "src/a.py", "os.system(cmd)")
    second = candidate_id("semgrep", "rules.x", "src/a.py", "  os.system(cmd)  ")
    assert first == second


def test_id_ignores_comments_and_case():
    assert normalize_snippet("Foo()  # 危険") == normalize_snippet("foo()")


def test_id_changes_with_path():
    assert candidate_id("semgrep", "r", "a.py", "x") != candidate_id("semgrep", "r", "b.py", "x")


def test_duplicate_snippets_get_sequence_suffix():
    factory = IdFactory()
    first = factory.make("semgrep", "r", "a.py", "eval(x)")
    second = factory.make("semgrep", "r", "a.py", "eval(x)")
    assert first != second
    assert second == f"{first}-1"


@pytest.mark.parametrize("path", ["/Users/foo/app.py", "C:\\Users\\foo\\app.py"])
def test_absolute_paths_are_rejected(path):
    with pytest.raises(ValidationError):
        Location(path=path, start_line=1, end_line=1)


def test_backslashes_are_normalized():
    assert Location(path="src\\app.py", start_line=1, end_line=1).path == "src/app.py"
