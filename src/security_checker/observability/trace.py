"""監査証跡 (設計書 §24.2).

既定ではプロンプト全文を保存せずハッシュのみ。コードが平文でディスクに残るのを避ける。
`output.save_prompts: true` で全文保存に切り替わる (その場合は警告を出す)。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from security_checker.context.redact import redact_known_patterns


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TraceWriter:
    """run 単位のトレース出力."""

    def __init__(self, output_dir: Path, run_id: str, *, enabled: bool = True) -> None:
        self.root = output_dir / "trace" / run_id
        self.enabled = enabled
        self._index = 0

    def write_run(self, payload: dict[str, Any]) -> Path | None:
        if not self.enabled:
            return None
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / "run.json"
        path.write_text(_dump(payload), encoding="utf-8")
        return path

    def write_call(self, payload: dict[str, Any]) -> Path | None:
        if not self.enabled:
            return None
        calls = self.root / "calls"
        calls.mkdir(parents=True, exist_ok=True)
        path = calls / f"{self._index:04d}.json"
        self._index += 1
        path.write_text(_dump(payload), encoding="utf-8")
        return path


def _dump(payload: dict[str, Any]) -> str:
    """マスキングフィルタを必ず通す (§19.1)."""
    text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    return redact_known_patterns(text) + "\n"
