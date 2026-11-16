"""起動した外部プロセスの回収 (設計書 §9.7). POSIX 以外の経路は差し替えて確かめる."""

from __future__ import annotations

import signal
from typing import Any

import pytest

from security_checker import processes


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
