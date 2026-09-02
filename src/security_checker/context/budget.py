"""トークン予算 (設計書 §8.3).

tiktoken があれば使い、なければ文字数からの概算にフォールバックする。
概算で構わない: 実測 usage で事後補正するため (§22.1)。
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

CHARS_PER_TOKEN = 4


@lru_cache(maxsize=1)
def _encode_fn() -> Callable[[str], list[int]] | None:
    """tiktoken があればその encode を返す. なければ None (概算にフォールバック)."""
    try:  # tiktoken は任意依存 (extras)
        import tiktoken  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        encoder = tiktoken.get_encoding("cl100k_base")
    except Exception:  # 辞書のダウンロードに失敗する環境では概算に落とす
        return None
    encode: Callable[[str], list[int]] = encoder.encode
    return encode


def estimate_tokens(text: str) -> int:
    """入力トークン数の見積り."""
    if not text:
        return 0
    encode = _encode_fn()
    if encode is not None:
        return len(encode(text))
    return max(1, -(-len(text) // CHARS_PER_TOKEN))
