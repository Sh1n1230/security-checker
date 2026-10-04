"""Baseline — 既知の候補を記録し、CI を落とさない (設計書 §17.2).

既存のリポジトリに導入すると、初回は過去の負債がまとめて出る。それを全部直すまで
CI を赤にしておくのは現実的でない。baseline に記録した候補は `suppressed` として
レポートに残しつつ、レビューとゲートの対象から外す。新しく増えたものだけが落ちる。

キーは Candidate の安定 ID (§6.1)。行番号を含まないので、無関係な編集で baseline が壊れない。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_checker.errors import ConfigError
from security_checker.models.candidate import Candidate

BASELINE_VERSION = 1


def load_baseline(path: Path) -> frozenset[str]:
    """baseline ファイルから候補 ID の集合を読む. 壊れていれば ConfigError (黙って空にしない)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(
            f"policy.baseline のファイルが見つかりません: {path}。"
            "`security-checker baseline update` で作成できます"
        ) from exc
    except (OSError, ValueError) as exc:
        raise ConfigError(f"baseline を読めません ({path}): {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise ConfigError(f"baseline の形式が不正です ({path}): version {BASELINE_VERSION} が必要")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ConfigError(f"baseline の形式が不正です ({path}): entries がありません")
    ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ConfigError(f"baseline の形式が不正です ({path}): id の無い entry があります")
        ids.add(entry["id"])
    return frozenset(ids)


def render_baseline(candidates: list[Candidate], *, tool_version: str) -> dict[str, Any]:
    """baseline の中身. 人間がレビューできるよう、ID だけでなく場所とルールも書く."""
    entries = sorted(
        (
            {
                "id": candidate.id,
                "scanner": candidate.scanner,
                "rule_id": candidate.rule_id,
                "where": candidate.where,
                "title": candidate.title,
            }
            for candidate in candidates
        ),
        key=lambda entry: (entry["where"], entry["rule_id"], entry["id"]),
    )
    return {
        "version": BASELINE_VERSION,
        "tool": "security-checker",
        "tool_version": tool_version,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "entries": entries,
    }


def write_baseline(path: Path, candidates: list[Candidate], *, tool_version: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = render_baseline(candidates, tool_version=tool_version)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
