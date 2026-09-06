"""process transport の隔離 (設計書 §9.7).

起動対象は**任意のコマンド**であり、その中にはファイルを書き換える能力を持つものが含まれる。
P3 (No Automatic Modification) は transport の性質によらず守る必要があるため、
対象が何であるかを問わず次を一律に強制する。

1. リポジトリの外で起動する — cwd は毎回作り直す空の一時ディレクトリ
2. シェルを経由しない — argv のリストで起動し、`shell=False` 固定
3. プロンプトは stdin か一時ファイルで渡す — コマンドライン引数に埋め込まない
   (長さ制限・`ps` からの可視性・フラグとしての誤解釈を避ける)
4. 実行後に一時 cwd の差分を検査する — 書き込みは warning と trace に残す
5. プロセスグループごと kill する — タイムアウト時に子プロセスを残さない
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

POSIX = os.name == "posix"
TERM_GRACE_S = 3.0
CREATED_PATHS_LIMIT = 20
OUTPUT_LIMIT = 200_000

PromptVia = Literal["stdin", "file"]

#: `prompt_via: file` のとき、argv 中のこの文字列が一時ファイルのパスに置換される。
#: 置換対象がなければパスを末尾に追加する。
PROMPT_FILE_PLACEHOLDER = "{prompt_file}"


@dataclass(frozen=True)
class SandboxResult:
    """1 回のサンドボックス実行の結果."""

    exit_code: int | None
    stdout: str
    stderr: str
    argv: tuple[str, ...]
    timed_out: bool = False
    created_paths: tuple[str, ...] = ()
    duration_ms: int = 0


async def run_sandboxed(
    argv: Sequence[str],
    *,
    prompt: str,
    prompt_via: PromptVia = "stdin",
    timeout_s: float = 300.0,
    environ: Mapping[str, str] | None = None,
) -> SandboxResult:
    """コマンドを隔離した一時ディレクトリで実行し、stdout を回収する.

    `environ` を省略すると呼び出し元の環境をそのまま引き継ぐ。
    process transport の存在意義は「そのコマンド側の既存ログインを使う」ことなので、
    資格情報を含む環境を落とさない (§9.7)。
    """
    started = time.monotonic()
    with (
        tempfile.TemporaryDirectory(prefix="sc-cwd-", ignore_cleanup_errors=True) as cwd_name,
        tempfile.TemporaryDirectory(prefix="sc-prompt-", ignore_cleanup_errors=True) as prompt_name,
    ):
        cwd = Path(cwd_name)
        resolved, stdin_data = _prepare_input(argv, prompt, prompt_via, Path(prompt_name))
        process = await asyncio.create_subprocess_exec(
            *resolved,
            cwd=str(cwd),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(environ) if environ is not None else None,
            # POSIX では新しいセッション = 新しいプロセスグループ。killpg で一掃するために必要。
            start_new_session=POSIX,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=stdin_data), timeout=timeout_s
            )
        except TimeoutError:
            timed_out = True
            stdout, stderr = b"", b""
            await terminate(process)

        return SandboxResult(
            exit_code=process.returncode,
            stdout=_decode(stdout),
            stderr=_decode(stderr),
            argv=tuple(resolved),
            timed_out=timed_out,
            created_paths=created_paths(cwd),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def _prepare_input(
    argv: Sequence[str],
    prompt: str,
    prompt_via: PromptVia,
    prompt_dir: Path,
) -> tuple[list[str], bytes]:
    """プロンプトの渡し方を決める. どちらの経路でも argv には本文が入らない.

    一時ファイルは cwd の**外**に置く。cwd に置くと、書込検知 (§9.7 の 4) が
    自分自身の書き込みを Reviewer の書き込みとして誤検知する。
    """
    if prompt_via == "stdin":
        return list(argv), prompt.encode("utf-8")

    path = prompt_dir / "prompt.txt"
    path.write_text(prompt, encoding="utf-8")
    if any(PROMPT_FILE_PLACEHOLDER in arg for arg in argv):
        resolved = [arg.replace(PROMPT_FILE_PLACEHOLDER, str(path)) for arg in argv]
    else:
        resolved = [*argv, str(path)]
    return resolved, b""


def created_paths(cwd: Path) -> tuple[str, ...]:
    """実行後の一時 cwd に何が作られたかを見る.

    空で始まったディレクトリなので、残っているものはすべて Reviewer の書き込みである。
    P3 が守られていることの唯一の実測値 (§25.2 の契約テスト 9 番)。
    """
    found: list[str] = []
    for path in sorted(cwd.rglob("*")):
        suffix = "/" if path.is_dir() else ""
        found.append(path.relative_to(cwd).as_posix() + suffix)
        if len(found) >= CREATED_PATHS_LIMIT:
            break
    return tuple(found)


async def terminate(process: asyncio.subprocess.Process) -> None:
    """プロセスグループごと片づける. SIGTERM を試してから SIGKILL に上げる."""
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        if process.returncode is not None:
            return
        _signal_group(process, signal_number)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=TERM_GRACE_S)
            return


def _signal_group(process: asyncio.subprocess.Process, signal_number: int) -> None:
    """POSIX ではプロセスグループ全体に、それ以外ではプロセス単体に送る."""
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        if POSIX:
            os.killpg(os.getpgid(process.pid), signal_number)
            return
        process.kill()


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", "replace")
    return text if len(text) <= OUTPUT_LIMIT else text[:OUTPUT_LIMIT] + "\n…(truncated)"
