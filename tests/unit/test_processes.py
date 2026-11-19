"""起動した外部プロセスの回収 (設計書 §9.7). POSIX 以外の経路は差し替えて確かめる."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Any

import pytest

from security_checker import processes
from security_checker.providers.process.sandbox import run_sandboxed

if TYPE_CHECKING:
    from pathlib import Path


class FakeProcess:
    def __init__(self, returncode: int | None = None) -> None:
        self.pid = 4242
        self.returncode = returncode
        self.killed = 0

    def kill(self) -> None:
        self.killed += 1
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode or 0


async def test_non_posix_terminates_a_running_process_once(monkeypatch):
    monkeypatch.setattr(processes, "POSIX", False)
    running = FakeProcess()
    await processes.terminate(running)  # type: ignore[arg-type]
    assert running.killed == 1

    finished = FakeProcess(returncode=0)
    await processes.terminate(finished)  # type: ignore[arg-type]
    assert finished.killed == 0


def test_a_group_we_may_not_signal_still_counts_as_alive(monkeypatch):
    if not processes.POSIX:
        pytest.skip("プロセスグループは POSIX のみ")

    def denied(*args: Any) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("os.killpg", denied)
    assert processes._group_alive(FakeProcess()) is True  # type: ignore[arg-type]
    # シグナルを送れなくても例外にしない
    processes._signal_group(FakeProcess(), signal.SIGTERM)  # type: ignore[arg-type]


class FakeKiller:
    def __init__(self, code: int) -> None:
        self.code = code

    async def wait(self) -> int:
        return self.code


@pytest.mark.parametrize(("code", "fallback_kills"), [(0, 0), (128, 1)])
async def test_non_posix_kills_the_whole_tree_with_taskkill(monkeypatch, code, fallback_kills):
    """Windows では親だけでなく子孫ごと止める (#612). taskkill が失敗したら親だけでも止める."""
    monkeypatch.setattr(processes, "POSIX", False)
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*argv: str, **kwargs: Any) -> FakeKiller:
        calls.append(argv)
        return FakeKiller(code)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    running = FakeProcess()
    await processes.terminate(running)  # type: ignore[arg-type]
    assert len(calls) == 1
    program, *args = calls[0]
    # PATH から探さない (検査対象が置いた偽物を実行しない)
    assert program.lower().endswith(os.path.join("system32", "taskkill.exe"))
    assert args == ["/T", "/F", "/PID", "4242"]
    assert running.killed == fallback_kills


GRANDCHILD_PARENT = r"""
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
open(sys.argv[1], "w").write(str(child.pid))
time.sleep(120)
"""


def _windows_pid_alive(pid: int) -> bool:
    listed = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False
    )
    return str(pid) in listed.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows のプロセスツリーの回収")
async def test_windows_timeout_leaves_no_grandchild(tmp_path: Path) -> None:
    """タイムアウトしたコマンドが起動した孫プロセスも残らない (#612)."""
    script = tmp_path / "parent.py"
    script.write_text(GRANDCHILD_PARENT, encoding="utf-8")
    pid_file = tmp_path / "grandchild.pid"
    result = await run_sandboxed(
        [sys.executable, str(script), str(pid_file)], prompt="", timeout_s=5.0
    )
    assert result.timed_out
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 10
    while _windows_pid_alive(grandchild) and time.monotonic() < deadline:  # noqa: ASYNC110
        await asyncio.sleep(0.2)
    assert not _windows_pid_alive(grandchild)
