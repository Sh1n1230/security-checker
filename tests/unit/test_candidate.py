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


def test_string_literals_are_not_stripped_as_comments():
    # `//` inside a URL is not a comment. Stripping it made these two snippets
    # normalize to the same text, so two different findings shared one stable ID
    # and the numbering shuffled whenever a line was added above them.
    a = normalize_snippet('requests.get("https://a.example/x")')
    b = normalize_snippet('requests.get("https://b.example/x")')
    assert a != b
    assert "https://a.example/x" in a


def test_hash_and_dashes_inside_strings_survive():
    # C `#include`, a CSS colour, and a SQL `--` were all eaten the same way.
    assert "#include" in normalize_snippet('line = "#include <stdio.h>"')
    assert "#ff0000" in normalize_snippet('c = "#ff0000"')
    assert "--" in normalize_snippet('q = "a -- b"')


def test_a_line_comment_does_not_eat_the_rest_of_the_snippet():
    # `.` with re.DOTALL matches newlines, so `.*$` used to swallow every line
    # after the first comment. Two snippets that differ only below a comment
    # normalised to the same text.
    assert normalize_snippet("x = 1  # note\ny = 2") == "x = 1 y = 2"


def test_a_block_comment_still_crosses_lines():
    assert normalize_snippet("a() /* one\ntwo */ b()") == "a() b()"


def test_real_comments_are_still_dropped():
    assert normalize_snippet("foo()  # 危険") == normalize_snippet("foo()")
    assert normalize_snippet("foo() // note") == normalize_snippet("foo()")
    assert normalize_snippet("foo() /* note */") == normalize_snippet("foo()")


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
