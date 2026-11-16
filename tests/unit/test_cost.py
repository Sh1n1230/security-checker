"""コスト計測 (設計書 §24.3). 未知のモデルは推測しない."""

from __future__ import annotations

import pytest

from security_checker.errors import ConfigError
from security_checker.models.verdict import Usage
from security_checker.observability.cost import ModelPrice, PriceTable, load_price_table
from security_checker.observability.estimate import Estimate, ReviewerEstimate


def test_unknown_model_is_cost_unknown():
    table = PriceTable()
    usage = table.apply(Usage(input_tokens=1000, output_tokens=500), "unknown-model")
    assert usage.cost_known is False
    assert usage.estimated_usd is None


def test_known_model_is_priced():
    table = PriceTable(prices={"m": ModelPrice(input_per_1m=3.0, output_per_1m=15.0)})
    usage = table.apply(Usage(input_tokens=1_000_000, output_tokens=100_000), "m")
    assert usage.estimated_usd == pytest.approx(3.0 + 1.5)
    assert usage.cost_known is True


def test_usage_merge_keeps_unknown_sticky():
    known = Usage(input_tokens=10, estimated_usd=0.5, cost_known=True)
    unknown = Usage(input_tokens=10, cost_known=False)
    merged = known.merge(unknown)
    assert merged.cost_known is False
    assert merged.estimated_usd is None
    assert merged.input_tokens == 20


def test_load_price_table(tmp_path):
    (tmp_path / "pricing.yml").write_text(
        "models:\n  my-model:\n    input_per_1m: 1.0\n    output_per_1m: 2.0\n", encoding="utf-8"
    )
    table = load_price_table(tmp_path)
    price = table.lookup("my-model")
    assert price is not None
    assert price.output_per_1m == 2.0


def test_missing_price_file_yields_empty_table(tmp_path):
    assert load_price_table(tmp_path, explicit=tmp_path / "nope.yml").prices == {}


def test_broken_price_file_is_config_error(tmp_path):
    path = tmp_path / "pricing.yml"
    path.write_text("models:\n  m:\n    input_per_1m: とても高い\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_price_table(tmp_path, explicit=path)


def test_broken_pricing_yaml_is_a_config_error(tmp_path):
    path = tmp_path / "pricing.yml"
    path.write_text("models: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="読み込めません"):
        load_price_table(explicit=path)


def test_models_must_be_a_mapping(tmp_path):
    path = tmp_path / "pricing.yml"
    path.write_text("models:\n  - m\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="models はマッピング"):
        load_price_table(explicit=path)


def test_estimate_totals_are_known_only_when_every_reviewer_is_priced():
    def reviewer(name: str, usd: float | None) -> ReviewerEstimate:
        return ReviewerEstimate(name=name, calls=1, input_tokens=100, max_output_tokens=10, usd=usd)

    priced = Estimate(tasks=1, reviewers=[reviewer("a", 0.5), reviewer("b", 0.25)])
    assert priced.total_usd == 0.75
    assert priced.total_input_tokens == 200
    assert Estimate(tasks=1, reviewers=[reviewer("a", 0.5), reviewer("b", None)]).total_usd is None
