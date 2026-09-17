"""まだ実装していない設定項目を、黙って無視しない (設計書 P9).

スキーマが受け付ける項目のうち、実装が追いついていないものがある。
黙って無視すると「設定したのに効かない」ことに気づけない — これは v1 で
「スキャナが失敗しても満点に見えた」のと同じ種類の事故である。

ここで検出して警告に積み、レポートとターミナルの両方に残す。
実装が入ったらエントリを消す。**エントリを消し忘れても害はないが、
実装と食い違ったままにしない**ために、対応するテストを一緒に置いてある。
"""

from __future__ import annotations

from collections.abc import Mapping

from security_checker.config.schema import Config

DEFAULT_LAYER = "default"


def _user_set(origins: Mapping[str, str], prefix: str) -> bool:
    """その節を利用者が明示的に設定したか (既定値のままなら警告しない)."""
    return any(key.startswith(prefix) and layer != DEFAULT_LAYER for key, layer in origins.items())


def unimplemented_warnings(config: Config, origins: Mapping[str, str] | None = None) -> list[str]:
    """受け付けたが効かない設定の一覧を返す. 呼び出し側は必ず警告として残すこと."""
    layers: Mapping[str, str] = origins or {}
    warnings: list[str] = []

    if "sarif" in config.output.formats:
        warnings.append(
            "output.formats の 'sarif' はまだ実装されていません (移行計画 P4)。"
            "SARIF ファイルは生成されないため、Code Scanning へのアップロードは行えません。"
            "terminal / json / markdown は通常どおり出力されます"
        )

    if config.policy.baseline is not None:
        warnings.append(
            f"policy.baseline ({config.policy.baseline}) はまだ実装されていません (移行計画 P5)。"
            "既知の Finding は抑制されず、すべて報告されます"
        )

    if config.target.mode == "diff":
        warnings.append(
            "target.mode: diff はまだ実装されていません (移行計画 P4)。"
            "変更行に関係しない候補も含めて、全件をスキャンします"
        )

    if _user_set(layers, "github."):
        warnings.append(
            "github.* の設定はまだ実装されていません (移行計画 P4)。PR コメントの投稿は行われません"
        )

    if _user_set(layers, "logging."):
        warnings.append(
            "logging.* の設定はまだ実装されていません (移行計画 P5)。構造化ログは出力されません"
        )

    for reviewer in config.reviewers:
        # num_ctx / keep_alive は ollama_chat 方言にしかない概念。
        # 別の方言に書いても効かないので、そのことを伝える。
        if reviewer.dialect == "ollama_chat":
            continue
        for field in ("num_ctx", "keep_alive"):
            if getattr(reviewer, field) is not None:
                warnings.append(
                    f"reviewer '{reviewer.name}': {field} は ollama_chat 方言専用です。"
                    f"dialect: {reviewer.dialect or '(未指定)'} では無視されます"
                )

    return warnings
