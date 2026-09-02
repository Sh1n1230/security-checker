"""Run ID (ULID) の生成. 全ログ・全トレースがこの ID で紐づく (設計書 §3)."""

from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        value, remainder = divmod(value, 32)
        chars.append(_CROCKFORD[remainder])
    return "".join(reversed(chars))


def new_run_id(now_ms: int | None = None, randomness: bytes | None = None) -> str:
    """ULID を生成する (時刻 48bit + 乱数 80bit の Crockford Base32)."""
    timestamp = now_ms if now_ms is not None else int(time.time() * 1000)
    entropy = randomness if randomness is not None else os.urandom(10)
    return _encode(timestamp, 10) + _encode(int.from_bytes(entropy, "big"), 16)
