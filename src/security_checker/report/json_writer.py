"""機械可読レポートの書き出し (設計書 §18.1)."""

from __future__ import annotations

import json
from pathlib import Path

from security_checker.models.report import Report


def write_json(report: Report, output_dir: Path) -> Path:
    """report.json を書き出してパスを返す."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.json"
    path.write_text(
        json.dumps(report.dump(), ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return path
