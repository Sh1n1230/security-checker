"""安定 ID とパス不変条件のテスト (設計書 §6.1)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from security_checker.models.candidate import (
    Candidate,
    IdFactory,
    Location,
    PackageRef,
    candidate_id,
    normalize_snippet,
)
from security_checker.models.enums import Category


def test_id_is_stable_across_line_moves():
    first = candidate_id("semgrep", "rules.x", "src/a.py", "os.system(cmd)")
    second = candidate_id("semgrep", "rules.x", "src/a.py", "  os.system(cmd)  ")
    assert first == second


def test_id_ignores_comments_and_case():
    assert normalize_snippet("Foo()  # 危険") == normalize_snippet("foo()")


def test_findings_that_differ_only_in_case_still_get_distinct_ids():
    # 小文字化は依存のキーの表記揺れを吸収するためのもの. コード片が衝突したら、
    # 出現順の連番で区別する (ID は重ならないが、順序に依存する)
    factory = IdFactory()
    upper = factory.make("semgrep", "r", "a.py", "API_KEY = x")
    lower = factory.make("semgrep", "r", "a.py", "api_key = x")
    assert upper != lower
    assert candidate_id("osv", "GHSA-1", "uv.lock", "PyPI:Flask@3.0") == candidate_id(
        "osv", "GHSA-1", "uv.lock", "pypi:flask@3.0"
    )


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


def test_where_names_the_line_the_file_the_package_or_nothing():
    def make(**fields: Any) -> Candidate:
        return Candidate(
            id="c",
            scanner="s",
            category=Category.SAST,
            rule_id="r",
            title="t",
            message="m",
            **fields,
        )

    assert make(location=Location(path="a.py", start_line=3, end_line=3)).where == "a.py:3"
    # ファイル単位の候補 (行 0) は行番号を付けない
    assert make(location=Location(path="conf/app.pem", start_line=0, end_line=0)).where == (
        "conf/app.pem"
    )
    assert make(package=PackageRef(ecosystem="PyPI", name="p", version="1.0")).where == "PyPI:p@1.0"
    assert make(package=PackageRef(ecosystem="PyPI", name="p")).where == "PyPI:p@*"
    assert make().where == "-"
