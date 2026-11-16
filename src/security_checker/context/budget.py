"""トークン予算 (設計書 §8.3).

tiktoken があれば使い、なければ文字数からの概算にフォールバックする。
概算で構わない: 実測 usage で事後補正するため (§22.1)。
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

CHARS_PER_TOKEN = 4
#: プロンプトのうちコード本文以外 (system・Finding の欄・facts・Notes・Schema) の見積り
PROMPT_OVERHEAD_TOKENS = 1500


@lru_cache(maxsize=1)
def _encode_fn() -> Callable[[str], list[int]] | None:
    """tiktoken があればその encode を返す. なければ None (概算にフォールバック)."""
    try:  # tiktoken は任意依存 (extras). 入っているときだけ読み込む
        import tiktoken  # type: ignore[import-not-found]  # noqa: PLC0415
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
