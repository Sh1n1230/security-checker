"""設定の探索・合成・検証 (設計書 §12).

合成順序 (後勝ち):
  組み込み既定値 ← preset ← 設定ファイル ← ローカル設定 ← 環境変数 ← CLI フラグ

「ローカル設定」は git 管理しない個人用の上書き層 (`security-checker.local.yml`)。
共有する設定と、手元でだけ使う Reviewer 定義を混ぜないためにある。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from security_checker.config.schema import Config
from security_checker.errors import ConfigError

CONFIG_FILENAMES = (
    "security-checker.yml",
    "security-checker.yaml",
    ".security-checker.yml",
    ".security-checker.yaml",
    ".github/security-checker.yml",
)
#: git 管理しない個人用の上書き層. 共有設定より後に適用される (後勝ち).
LOCAL_CONFIG_FILENAMES = (
    "security-checker.local.yml",
    "security-checker.local.yaml",
)
ENV_PREFIX = "SECURITY_CHECKER__"
PRESET_DIR = Path(__file__).parent / "presets"

Layer = str


@dataclass
class LoadedConfig:
    """解決済み設定と、どの層で値が決まったかの記録 (`config show --explain` 用)."""

    config: Config
    origins: dict[str, Layer] = field(default_factory=dict)
    config_path: Path | None = None
    preset: str | None = None
    local_config_path: Path | None = None


def find_config_file(root: Path) -> Path | None:
    """対象ディレクトリ配下から設定ファイルを探す."""
    for name in CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def find_local_config_file(root: Path) -> Path | None:
    """個人用の上書き設定を探す. `--config` の指定とは独立に、対象直下だけを見る."""
    for name in LOCAL_CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def available_presets() -> list[str]:
    return sorted(path.stem for path in PRESET_DIR.glob("*.yml"))


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} の YAML を解釈できません: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path} を読み込めません: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} のトップレベルはマッピングである必要があります")
    return raw


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def env_overrides(environ: dict[str, str] | None = None) -> dict[str, Any]:
    """`SECURITY_CHECKER__POLICY__FAIL_ON=critical` 形式を入れ子 dict に変換する."""
    source = environ if environ is not None else dict(os.environ)
    overrides: dict[str, Any] = {}
    for raw_key, raw_value in source.items():
        if not raw_key.startswith(ENV_PREFIX):
            continue
        parts = [part.lower() for part in raw_key[len(ENV_PREFIX) :].split("__") if part]
        if not parts:
            continue
        try:
            value = yaml.safe_load(raw_value)
        except yaml.YAMLError:
            value = raw_value
        cursor = overrides
        for part in parts[:-1]:
            nested = cursor.setdefault(part, {})
            if not isinstance(nested, dict):
                nested = {}
                cursor[part] = nested
            cursor = nested
        cursor[parts[-1]] = value
    return overrides


def _reject_plaintext_keys(data: dict[str, Any]) -> None:
    """`api_key:` の平文フィールドはスキーマに存在しない (§19.1). 誤記を明確に伝える."""
    reviewers = data.get("reviewers")
    if not isinstance(reviewers, list):
        return
    for reviewer in reviewers:
        if isinstance(reviewer, dict) and "api_key" in reviewer:
            name = reviewer.get("name", "?")
            raise ConfigError(
                f"reviewer '{name}': 平文の api_key は設定できません。"
                "環境変数名を api_key_env で指定してください (例: api_key_env: MY_API_KEY)"
            )


def load_config(
    root: Path,
    *,
    config_path: Path | None = None,
    preset: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
) -> LoadedConfig:
    """設定を合成して検証する. 失敗時は必ず ConfigError (exit 2)."""
    layers: list[tuple[Layer, dict[str, Any]]] = [("default", Config().model_dump(mode="json"))]

    if preset is not None:
        preset_path = PRESET_DIR / f"{preset}.yml"
        if not preset_path.is_file():
            raise ConfigError(
                f"preset '{preset}' は存在しません。利用可能: {', '.join(available_presets())}"
            )
        layers.append((f"preset:{preset}", _read_yaml(preset_path)))

    resolved_path = config_path
    if resolved_path is None:
        resolved_path = find_config_file(root)
    elif not resolved_path.is_file():
        raise ConfigError(f"設定ファイルが見つかりません: {resolved_path}")
    if resolved_path is not None:
        file_data = _read_yaml(resolved_path)
        _reject_plaintext_keys(file_data)
        layers.append((f"file:{resolved_path}", file_data))

    # 共有設定の後に、git 管理しない個人用の層を重ねる。
    # 「手元でだけ使う Reviewer」を共有設定に混ぜずに済ませるための経路。
    local_path = find_local_config_file(root)
    if local_path is not None:
        local_data = _read_yaml(local_path)
        _reject_plaintext_keys(local_data)
        layers.append((f"local:{local_path}", local_data))

    layers.append(("env", env_overrides(environ)))
    layers.append(("cli", cli_overrides or {}))

    merged: dict[str, Any] = {}
    origins: dict[str, Layer] = {}
    for name, data in layers:
        if not data:
            continue
        merged = _deep_merge(merged, data)
        for key in _flatten(data):
            origins[key] = name

    try:
        config = Config.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc

    return LoadedConfig(
        config=config,
        origins=origins,
        config_path=resolved_path,
        preset=preset,
        local_config_path=local_path,
    )


def _format_validation_error(exc: ValidationError) -> str:
    lines = ["設定が不正です:"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "(root)"
        lines.append(f"  - {location}: {error['msg']}")
    return "\n".join(lines)
