"""`init` 用の環境検出 (設計書 §9.8).

導入を楽にする最も安直な方法は「おすすめの Reviewer を既定値にする」ことだが、
それはそのベンダーを事実上の標準として押し付けることになる。OSS としてこれは採らない。
**既定設定に Reviewer は 1 つも入っていない。**

代わりに、利用者の環境で実際に使えるものを検出する。検出の材料は
**プリセットデータ (YAML) と環境変数だけ**であり、このコードにコマンド名も
ベンダー名も現れない。結果は名前のアルファベット順で提示し、推奨マークを付けない。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from security_checker.providers.presets.loader import (
    HttpPreset,
    ProcessPreset,
    load_http_presets,
    load_process_presets,
)

VERSION_TIMEOUT_S = 10
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")  # noqa: S104 - 判定用の文字列


@dataclass(frozen=True)
class CommandStatus:
    """コマンドの導入状況."""

    available: bool
    version: str | None = None
    reason: str | None = None


def command_version(command: str) -> CommandStatus:
    """コマンドの有無とバージョンを調べる. 失敗しても例外にしない.

    バージョンは trace に残す (§9.7 の監査証跡)。取れなくても実行は妨げない。
    """
    path = shutil.which(command)
    if path is None:
        return CommandStatus(available=False, reason=f"{command} が見つかりません")
    try:
        completed = subprocess.run(  # argv 直指定・shell 不使用
            [path, "--version"],
            capture_output=True,
            timeout=VERSION_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandStatus(available=True, reason=f"バージョン取得に失敗しました: {exc}")
    output = (completed.stdout or completed.stderr).decode("utf-8", "replace").strip()
    return CommandStatus(available=True, version=output.splitlines()[0] if output else None)


@dataclass(frozen=True)
class Detection:
    """1 件の検出結果. 順位づけは持たない (§9.8)."""

    transport: Literal["http", "process"]
    name: str
    available: bool
    detail: str
    #: 検出されたものを reviewers ブロックにするための最小限の情報
    config: dict[str, object]


def detect_process(
    presets: Mapping[str, ProcessPreset] | None = None,
) -> list[Detection]:
    """process transport で使えるコマンドを、プリセットデータを頼りに探す."""
    available = presets if presets is not None else load_process_presets()
    found: list[Detection] = []
    for name in sorted(available):
        preset = available[name]
        binary = preset.command[0] if preset.command else ""
        status = command_version(binary)
        detail = (
            f"{binary}: {status.version or 'バージョン不明'}"
            if status.available
            else status.reason or f"{binary} が見つかりません"
        )
        found.append(
            Detection(
                transport="process",
                name=name,
                available=status.available,
                detail=detail,
                config={"name": name, "transport": "process", "preset": name},
            )
        )
    return found


def detect_http(
    presets: Mapping[str, HttpPreset] | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[Detection]:
    """http transport で使える資格情報を探す.

    「どの環境変数を見るか」もプリセットデータ側の情報であり、ここには書かれていない。
    ローカルエンドポイント (api_key_env を持たない localhost) は資格情報なしで使える
    ものとして扱う。
    """
    available = presets if presets is not None else load_http_presets()
    source = environ if environ is not None else os.environ
    found: list[Detection] = []
    for name in sorted(available):
        preset = available[name]
        config: dict[str, object] = {"name": name, "transport": "http", "preset": name}
        if preset.api_key_env is None:
            local = _is_local(preset.base_url)
            found.append(
                Detection(
                    transport="http",
                    name=name,
                    available=local,
                    detail=(
                        f"{preset.base_url} (ローカルエンドポイント・資格情報不要)"
                        if local
                        else "api_key_env が未指定です"
                    ),
                    config=config,
                )
            )
            continue
        has_key = bool(source.get(preset.api_key_env))
        found.append(
            Detection(
                transport="http",
                name=name,
                available=has_key,
                detail=f"{preset.api_key_env}: {'設定済み' if has_key else '未設定'}",
                config=config,
            )
        )
    return found


def detect_all(environ: Mapping[str, str] | None = None) -> list[Detection]:
    """process → http の順に、それぞれ名前のアルファベット順で返す."""
    return [*detect_process(), *detect_http(environ=environ)]


def _is_local(base_url: str | None) -> bool:
    if not base_url:
        return False
    return (urlparse(base_url).hostname or "") in LOCAL_HOSTS
