"""内蔵 Scanner と entry_points プラグインの解決 (設計書 §29)."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points
from typing import Any

from security_checker.config.schema import Config, ScannerConfig
from security_checker.scanners.base import Scanner
from security_checker.scanners.gitleaks import GitleaksScanner
from security_checker.scanners.semgrep import SemgrepScanner

ENTRY_POINT_GROUP = "security_checker.scanners"

BUILTIN_SCANNERS: dict[str, Callable[[Any], Scanner]] = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
}


def discover_plugin_scanners() -> tuple[dict[str, Callable[[Any], Scanner]], list[str]]:
    """外部パッケージが提供する Scanner を探す. 読み込み失敗は警告にして続行する."""
    found: dict[str, Callable[[Any], Scanner]] = {}
    warnings: list[str] = []
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        try:
            factory = entry.load()
        except Exception as exc:  # プラグイン側の任意の失敗を封じ込める
            warnings.append(f"scanner プラグイン '{entry.name}' の読み込みに失敗しました: {exc}")
            continue
        found[entry.name] = factory
    return found, warnings


def build_scanners(config: Config) -> tuple[list[Scanner], list[str]]:
    """設定で有効化されている Scanner を組み立てる."""
    plugins, warnings = discover_plugin_scanners()
    factories: dict[str, Callable[[Any], Scanner]] = {**plugins, **BUILTIN_SCANNERS}

    scanners: list[Scanner] = []
    settings: dict[str, ScannerConfig] = config.scanner_settings()
    for name, scanner_settings in settings.items():
        if not scanner_settings.enabled:
            continue
        factory = factories.get(name)
        if factory is None:
            # P1 時点では osv / trivy のアダプタは未実装 (P5 で追加する)。
            warnings.append(f"scanner '{name}' は未実装のため無効化しました")
            continue
        scanners.append(factory(scanner_settings))
    return scanners, warnings
