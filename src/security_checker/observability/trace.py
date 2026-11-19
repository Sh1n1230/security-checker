"""監査証跡 (設計書 §24.2).

既定ではプロンプト全文を保存せずハッシュのみ。コードが平文でディスクに残るのを避ける。
`output.save_prompts: true` で全文保存に切り替わる (その場合は警告を出す)。
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
from typing import TYPE_CHECKING, Any

from security_checker.context.redact import redact_known_patterns

if TYPE_CHECKING:
    from pathlib import Path


def sha256_text(text: str) -> str:
    """文字列の SHA-256 (16 進)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TraceWriter:
    """run 単位のトレース出力."""

    def __init__(self, output_dir: Path, run_id: str, *, enabled: bool = True) -> None:
        self.root = output_dir / "trace" / run_id
        self.enabled = enabled
        self._index = 0

    def write_run(self, payload: dict[str, Any]) -> Path | None:
        """実行全体の記録 (run.json) を書く. 無効なら何もしない."""
        if not self.enabled:
            return None
        _private_dir(self.root)
        path = self.root / "run.json"
        _write_private(path, _dump(payload))
        return path

    def write_call(self, payload: dict[str, Any]) -> Path | None:
        """LLM 呼び出し 1 回分の記録を calls/ に書く. 無効なら何もしない."""
        if not self.enabled:
            return None
        calls = self.root / "calls"
        _private_dir(calls)
        path = calls / _call_file_name(self._index, payload)
        self._index += 1
        _write_private(path, _dump(payload))
        return path


#: ファイル名に入れる識別子の 1 つあたりの上限. 長い候補 ID でもパスの長さ制限に掛からないように
_NAME_PART_LIMIT = 40
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _call_file_name(index: int, payload: dict[str, Any]) -> str:
    """`NNNN-<reviewer>-<候補 ID>.json`. 開かなくても、どの呼び出しの記録か分かるようにする (#449).

    先頭の連番で、並べたときの順序は送信順のまま。ファイル名に使えない文字は `_` にする。
    explain は中身の candidate_id で突き合わせるので、連番だけの古い名前も読める。
    """
    parts = [f"{index:04d}"]
    for key in ("reviewer", "candidate_id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            parts.append(_UNSAFE_NAME_CHARS.sub("_", value)[:_NAME_PART_LIMIT])
    return "-".join(parts) + ".json"


#: トレースは LLM の応答 (コードを引用する) を含み、save_prompts ではコードそのものを含む.
#: 共有の開発機や self-hosted runner で、同じマシンの他のユーザーに読ませない (§24.2)
_DIR_MODE = 0o700
_FILE_MODE = 0o600


def _private_dir(path: Path) -> None:
    """所有者だけが入れるディレクトリを作る. Windows では権限の指定は効かない."""
    path.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    # 既にあるディレクトリと、umask で広がった場合に備えてそろえる (trace/ の配下だけ)
    for directory in (path, *path.parents):
        with contextlib.suppress(OSError):
            directory.chmod(_DIR_MODE)
        if directory.name == "trace":
            break


def _write_private(path: Path, text: str) -> None:
    """所有者だけが読めるファイルとして書く."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    with contextlib.suppress(OSError):
        path.chmod(_FILE_MODE)


def _dump(payload: dict[str, Any]) -> str:
    """マスキングフィルタを必ず通す (§19.1)."""
    text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    return redact_known_patterns(text) + "\n"
