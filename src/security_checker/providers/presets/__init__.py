"""ベンダー知識を置く唯一の場所 (設計書 §9).

ここにあるのは **データ (YAML)** であり、コードではない。
同梱プリセットが 1 つもなくても、設定に dialect / base_url / command を直接書けば動く。
利用者は `~/.config/security-checker/presets/` に置いて追加・上書きできる。
"""

from __future__ import annotations

from security_checker.providers.presets.loader import (
    HttpPreset,
    load_http_presets,
    resolve_http_preset,
    user_preset_dir,
)

__all__ = ["HttpPreset", "load_http_presets", "resolve_http_preset", "user_preset_dir"]
