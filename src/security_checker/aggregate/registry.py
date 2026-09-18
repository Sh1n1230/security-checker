"""集約戦略の解決 (設計書 §13, §29)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from importlib.metadata import entry_points

from security_checker.aggregate.base import Aggregator
from security_checker.aggregate.consensus import ConsensusAggregator
from security_checker.aggregate.weighted import WeightedAggregator
from security_checker.errors import ConfigError

ENTRY_POINT_GROUP = "security_checker.aggregators"

# judge は P5 で追加する
BUILTIN_AGGREGATORS: dict[str, Callable[..., Aggregator]] = {
    ConsensusAggregator.name: ConsensusAggregator,
    WeightedAggregator.name: WeightedAggregator,
}


def discover_plugin_aggregators() -> tuple[dict[str, Callable[..., Aggregator]], list[str]]:
    found: dict[str, Callable[..., Aggregator]] = {}
    warnings: list[str] = []
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        try:
            found[entry.name] = entry.load()
        except Exception as exc:  # プラグイン側の任意の失敗を封じ込める
            warnings.append(f"aggregator プラグイン '{entry.name}' の読み込みに失敗しました: {exc}")
    return found, warnings


def build_aggregator(
    strategy: str, *, weights: Mapping[str, float] | None = None
) -> tuple[Aggregator, list[str]]:
    """戦略名から Aggregator を作る.

    `weights` は Reviewer 名 → 重み。**戦略ごとの分岐を作らない**ため、
    どの戦略にも同じものを渡し、使わない戦略は受け取って無視する
    (Provider 側で DialectOptions を全方言に渡しているのと同じ考え方)。
    """
    plugins, warnings = discover_plugin_aggregators()
    factories = {**plugins, **BUILTIN_AGGREGATORS}
    factory = factories.get(strategy)
    if factory is None:
        raise ConfigError(
            f"未知の aggregation.strategy '{strategy}'。利用可能: {', '.join(sorted(factories))}"
        )
    try:
        return factory(weights=weights), warnings
    except TypeError:
        # weights を受け取らない実装 (外部プラグインの旧シグネチャ) も動かし続ける
        return factory(), warnings
