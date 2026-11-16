"""Aggregator の解決とプラグインの発見 (設計書 §13・§29.1)."""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.aggregate import registry
from security_checker.aggregate.base import aggregate_severity
from security_checker.aggregate.consensus import ConsensusAggregator
from security_checker.errors import ConfigError
from security_checker.models.enums import Severity


class _Entry:
    def __init__(self, name: str, loaded: Any) -> None:
        self.name = name
        self._loaded = loaded

    def load(self) -> Any:
        if isinstance(self._loaded, Exception):
            raise self._loaded
        return self._loaded


def _register(monkeypatch: pytest.MonkeyPatch, *entries: _Entry) -> None:
    monkeypatch.setattr(registry, "entry_points", lambda group: list(entries))


def test_plugin_aggregators_are_discovered_and_a_broken_one_is_only_a_warning(monkeypatch):
    _register(
        monkeypatch,
        _Entry("mine", ConsensusAggregator),
        _Entry("broken", ImportError("no module named x")),
    )
    found, warnings = registry.discover_plugin_aggregators()
    assert found == {"mine": ConsensusAggregator}
    assert len(warnings) == 1
    assert "broken" in warnings[0]
    assert "no module named x" in warnings[0]


def test_judge_is_not_a_standalone_aggregator():
    with pytest.raises(ConfigError, match="judge は単独の Aggregator ではありません"):
        registry.build_aggregator("judge")


def test_unknown_strategy_lists_the_available_ones():
    with pytest.raises(ConfigError, match="consensus"):
        registry.build_aggregator("no-such-strategy")


def test_plugin_with_the_old_signature_still_builds(monkeypatch):
    class Legacy:
        name = "legacy"

        def __init__(self) -> None:  # weights を受け取らない旧シグネチャ
            self.built = True

    _register(monkeypatch, _Entry("legacy", Legacy))
    aggregator, warnings = registry.build_aggregator("legacy", weights={"a": 2.0})
    assert isinstance(aggregator, Legacy)
    assert warnings == []


def test_severity_of_no_vulnerable_verdicts_is_none():
    assert aggregate_severity([], "median", lambda verdict: 1.0) is Severity.NONE
