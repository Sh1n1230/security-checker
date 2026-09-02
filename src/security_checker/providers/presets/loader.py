"""プリセットデータの読み込み (設計書 §9.3, §9.7).

同梱データとユーザーデータを同じ形式で読む。ユーザー側が同名で上書きできる。
一致するエントリがなければ、最も互換性の高いモードにフォールバックする
(「知らないエンドポイントでも、まず動く」ことを保証するため)。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
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


class HttpPreset(BaseModel):
    """`http` transport 用のプリセット (名前 → dialect + base_url + capability)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    dialect: str
    base_url: str | None = None
    api_key_env: str | None = None
    match: PresetMatch = PresetMatch()
    capabilities: dict[str, Any] = Field(default_factory=dict)
    source: str = "bundled"


def _read_presets(directory: Path, source: str) -> dict[str, HttpPreset]:
    presets: dict[str, HttpPreset] = {}
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
            preset = HttpPreset.model_validate({**raw, "source": source})
        except ValidationError as exc:
            raise ConfigError(f"プリセット {path} が不正です: {exc}") from exc
        presets[preset.name] = preset
    return presets


def load_http_presets(user_dir: Path | None = None) -> dict[str, HttpPreset]:
    """同梱 → ユーザーの順に読み、同名はユーザー側が勝つ."""
    directory = user_dir if user_dir is not None else user_preset_dir() / "http"
    presets = _read_presets(BUNDLED_HTTP_DIR, "bundled")
    presets.update(_read_presets(directory, "user"))
    return presets


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
