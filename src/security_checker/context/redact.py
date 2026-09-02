"""シークレットのマスキング (設計書 §19.2).

検出されたシークレットの値は Candidate にもレポートにも載せない。
形式が分かる程度に伏せた表現 (`AKIA****************`) に置換する。
値そのものを外部 LLM に送るのは二次漏洩であり、設計上の禁止事項。
"""

from __future__ import annotations

import re

VISIBLE_PREFIX = 4
MAX_MASK = 20


def mask_secret(value: str) -> str:
    """値の先頭だけを残し、残りを伏せる. 形式(prefix)は判定に必要なので残す."""
    if not value:
        return ""
    if len(value) <= VISIBLE_PREFIX:
        return "*" * len(value)
    hidden = min(len(value) - VISIBLE_PREFIX, MAX_MASK)
    return value[:VISIBLE_PREFIX] + "*" * hidden


def redact_text(text: str, secrets: list[str]) -> str:
    """テキスト中に現れるシークレット値をマスク済み表現に置き換える."""
    redacted = text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        redacted = redacted.replace(secret, mask_secret(secret))
    return redacted


_GENERIC_KEY_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{8,})"
)


def redact_known_patterns(text: str) -> str:
    """既知の API キー形式をログ・例外メッセージから伏せる (§19.1 のマスキングフィルタ)."""
    return _GENERIC_KEY_RE.sub(lambda m: mask_secret(m.group(0)), text)
