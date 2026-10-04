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


def unimplemented_warnings(config: Config, origins: Mapping[str, str] | None = None) -> list[str]:
    """受け付けたが効かない設定の一覧を返す. 呼び出し側は必ず警告として残すこと.

    `origins` (どの層で値が決まったか) は、既定値のままの項目を警告しないために受け取る。
    P5 時点で残っているのは方言の組み合わせの検査だけで、使っていない。
    """
    del origins
    warnings: list[str] = []

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
