"""レポート出力レイヤ (設計書 §18)."""

from __future__ import annotations

from security_checker.report.json_writer import write_json
from security_checker.report.terminal import render

__all__ = ["render", "write_json"]
