"""集約戦略の解決 (設計書 §13, §29)."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points

from security_checker.aggregate.base import Aggregator
from security_checker.aggregate.consensus import ConsensusAggregator
from security_checker.errors import ConfigError

ENTRY_POINT_GROUP = "security_checker.aggregators"

# weighted / judge は P3 で追加する
BUILTIN_AGGREGATORS: dict[str, Callable[[], Aggregator]] = {
    ConsensusAggregator.name: ConsensusAggregator,
}


def discover_plugin_aggregators() -> tuple[dict[str, Callable[[], Aggregator]], list[str]]:
    found: dict[str, Callable[[], Aggregator]] = {}
    warnings: list[str] = []
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        try:
            found[entry.name] = entry.load()
        except Exception as exc:  # プラグイン側の任意の失敗を封じ込める
            warnings.append(f"aggregator プラグイン '{entry.name}' の読み込みに失敗しました: {exc}")
    return found, warnings


def build_aggregator(strategy: str) -> tuple[Aggregator, list[str]]:
    plugins, warnings = discover_plugin_aggregators()
    factories = {**plugins, **BUILTIN_AGGREGATORS}
    factory = factories.get(strategy)
    if factory is None:
        raise ConfigError(
            f"未知の aggregation.strategy '{strategy}'。利用可能: {', '.join(sorted(factories))}"
        )
    return factory(), warnings
