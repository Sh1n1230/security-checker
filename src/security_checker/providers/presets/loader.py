"""プリセットデータの読み込み (設計書 §9.3, §9.7).

同梱データとユーザーデータを同じ形式で読む。ユーザー側が同名で上書きできる。
一致するエントリがなければ、最も互換性の高いモードにフォールバックする
(「知らないエンドポイントでも、まず動く」ことを保証するため)。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_checker.errors import ConfigError

BUNDLED_HTTP_DIR = Path(__file__).parent / "http"
BUNDLED_PROCESS_DIR = Path(__file__).parent / "process"


def user_preset_dir() -> Path:
    """利用者のプリセット置き場. XDG_CONFIG_HOME を尊重する."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "security-checker" / "presets"


class PresetMatch(BaseModel):
    """どのエンドポイント / モデルに適用するか."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str | None = None
    model: str | None = None  # 正規表現

    def matches(self, base_url: str, model: str) -> bool:
        if self.host is not None:
            host = urlparse(base_url).hostname or ""
            if host != self.host:
                return False
        if self.model is not None and not re.search(self.model, model):
            return False
        return self.host is not None or self.model is not None


class BasePreset(BaseModel):
    """transport 共通の部分. capability の供給源であることは両者に共通する."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    source: str = "bundled"


class HttpPreset(BasePreset):
    """`http` transport 用のプリセット (名前 → dialect + base_url + capability)."""

    dialect: str
    base_url: str | None = None
    api_key_env: str | None = None
    match: PresetMatch = PresetMatch()


class ProcessPreset(BasePreset):
    """`process` transport 用のプリセット (名前 → command + parse + capability).

    プリセットは**省略記法にすぎない**。設定に `command` を直接書けば、
    プリセットが 1 つもなくても同じように動く (設計書 §9.7)。
    """

    command: list[str]
    prompt_via: Literal["stdin", "file"] = "stdin"
    parse: str = "json_in_stdout"
    #: §9.7 の安全要件 (非対話 + ツール無効/読み取り専用) を満たしていることの申告。
    #: false のプリセットは、command 直書きと同じ扱いで警告する。
    requires_readonly_flags: bool = False


PresetT = TypeVar("PresetT", bound=BasePreset)


def _read_presets(directory: Path, source: str, model: type[PresetT]) -> dict[str, PresetT]:
    presets: dict[str, PresetT] = {}
    if not directory.is_dir():
        return presets
    for path in sorted(directory.glob("*.yml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"プリセット {path} を読み込めません: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"プリセット {path} のトップレベルはマッピングである必要があります")
        raw.setdefault("name", path.stem)
        try:
            preset = model.model_validate({**raw, "source": source})
        except ValidationError as exc:
            raise ConfigError(f"プリセット {path} が不正です: {exc}") from exc
        presets[preset.name] = preset
    return presets


def load_http_presets(user_dir: Path | None = None) -> dict[str, HttpPreset]:
    """同梱 → ユーザーの順に読み、同名はユーザー側が勝つ."""
    directory = user_dir if user_dir is not None else user_preset_dir() / "http"
    presets = _read_presets(BUNDLED_HTTP_DIR, "bundled", HttpPreset)
    presets.update(_read_presets(directory, "user", HttpPreset))
    return presets


def load_process_presets(user_dir: Path | None = None) -> dict[str, ProcessPreset]:
    """`process` 用も同じ規則で読む. 利用者は PR なしでプリセットを追加・上書きできる."""
    directory = user_dir if user_dir is not None else user_preset_dir() / "process"
    presets = _read_presets(BUNDLED_PROCESS_DIR, "bundled", ProcessPreset)
    presets.update(_read_presets(directory, "user", ProcessPreset))
    return presets


def resolve_process_preset(
    presets: dict[str, ProcessPreset], *, name: str | None
) -> ProcessPreset | None:
    """`process` は host / model のような照合材料を持たないため、名前指定のみ."""
    if name is None:
        return None
    preset = presets.get(name)
    if preset is None:
        available = ", ".join(sorted(presets)) or "(同梱プリセットはありません)"
        raise ConfigError(
            f"preset '{name}' は見つかりません。利用可能: {available}。"
            "command を直接指定することもできます"
        )
    return preset


def resolve_http_preset(
    presets: dict[str, HttpPreset],
    *,
    name: str | None,
    base_url: str | None,
    model: str | None,
) -> HttpPreset | None:
    """名前指定があればそれを、なければ host / model パターンで引く."""
    if name is not None:
        preset = presets.get(name)
        if preset is None:
            available = ", ".join(sorted(presets)) or "(同梱プリセットはありません)"
            raise ConfigError(
                f"preset '{name}' は見つかりません。利用可能: {available}。"
                "dialect と base_url を直接指定することもできます"
            )
        return preset
    if base_url is None or model is None:
        return None
    for preset in presets.values():
        if preset.match.matches(base_url, model):
            return preset
    return None
