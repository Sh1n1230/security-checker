"""process transport の隔離 (設計書 §9.7).

ここで検証しているのは「安全側の性質」であり、機能ではない。
壊れたら P3 (No Automatic Modification) が崩れる。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from security_checker.providers.process.sandbox import (
    PROMPT_FILE_PLACEHOLDER,
    created_paths,
    run_sandboxed,
)


def python(script: str, *args: str) -> list[str]:
    return [sys.executable, "-c", script, *args]


ECHO_CWD = "import os,sys;sys.stdin.read();print(os.getcwd())"
ECHO_STDIN = "import sys;print(sys.stdin.read(), end='')"
ECHO_ARGV = "import json,sys;sys.stdin.read();print(json.dumps(sys.argv[1:]))"
READ_FILE = (
    "import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), end='')"
)
WRITE_TREE = (
    "import pathlib,sys;"
    "sys.stdin.read();"
    "pathlib.Path('sub').mkdir();"
    "pathlib.Path('sub/out.txt').write_text('x', encoding='utf-8');"
    "print('done')"
)


async def test_stdout_and_exit_code_are_returned():
    result = await run_sandboxed(python(ECHO_STDIN), prompt="hello", timeout_s=30)
    assert result.exit_code == 0
    assert result.stdout == "hello"
    assert result.timed_out is False


def assert_outside_and_cleaned(reported_cwd: str) -> None:
    cwd = Path(reported_cwd.strip()).resolve()
    assert Path.cwd().resolve() not in cwd.parents
    # 実行後に片づけられている (毎回作り直す)
    assert not cwd.exists()


async def test_cwd_is_a_fresh_directory_outside_the_repository():
    result = await run_sandboxed(python(ECHO_CWD), prompt="x", timeout_s=30)
    assert_outside_and_cleaned(result.stdout)


async def test_prompt_is_never_placed_in_argv():
    """引数に入れると ps で他ユーザーに見え、フラグとしても解釈されうる (§9.7 の 3)."""
    prompt = "--not-a-flag; rm -rf /"
    result = await run_sandboxed(python(ECHO_ARGV), prompt=prompt, timeout_s=30)
    assert prompt not in result.stdout
    assert prompt not in " ".join(result.argv)


async def test_prompt_via_file_uses_the_placeholder():
    command = python(READ_FILE, PROMPT_FILE_PLACEHOLDER)
    result = await run_sandboxed(command, prompt="from-file", prompt_via="file", timeout_s=30)
    assert result.stdout == "from-file"
    assert PROMPT_FILE_PLACEHOLDER not in " ".join(result.argv)


async def test_prompt_via_file_appends_the_path_when_no_placeholder():
    result = await run_sandboxed(
        python(READ_FILE), prompt="appended", prompt_via="file", timeout_s=30
    )
    assert result.stdout == "appended"


async def test_prompt_file_is_not_counted_as_a_write():
    """一時ファイルは cwd の外に置く. 自分の書き込みを検知してはいけない."""
    result = await run_sandboxed(python(READ_FILE), prompt="x", prompt_via="file", timeout_s=30)
    assert result.created_paths == ()


async def test_writes_are_detected_including_subdirectories():
    result = await run_sandboxed(python(WRITE_TREE), prompt="x", timeout_s=30)
    assert result.created_paths == ("sub/", "sub/out.txt")


async def test_timeout_marks_the_result_and_does_not_raise():
    result = await run_sandboxed(python("import time;time.sleep(60)"), prompt="x", timeout_s=1.0)
    assert result.timed_out is True
    assert result.stdout == ""


async def test_environment_is_passed_through_by_default():
    """process transport の存在意義は、そのコマンド側の既存ログインを使うこと (§9.7)."""
    script = "import os,sys;sys.stdin.read();print(os.environ.get('SC_TEST_MARKER', ''))"
    os.environ["SC_TEST_MARKER"] = "inherited"
    try:
        result = await run_sandboxed(python(script), prompt="x", timeout_s=30)
    finally:
        del os.environ["SC_TEST_MARKER"]
    assert result.stdout.strip() == "inherited"


async def test_explicit_environment_replaces_the_inherited_one():
    script = "import os,sys;sys.stdin.read();print(os.environ.get('SC_TEST_MARKER', 'absent'))"
    result = await run_sandboxed(
        python(script), prompt="x", timeout_s=30, environ={"PATH": os.environ.get("PATH", "")}
    )
    assert result.stdout.strip() == "absent"


async def test_missing_command_raises_oserror():
    with pytest.raises(OSError):
        await run_sandboxed(["security-checker-no-such-command"], prompt="x", timeout_s=5)


def test_created_paths_reports_relative_posix_paths(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.txt").write_text("x", encoding="utf-8")
    assert created_paths(tmp_path) == ("a/", "a/b.txt")
