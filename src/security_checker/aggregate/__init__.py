"""Aggregation レイヤ (設計書 §13-16)."""

from __future__ import annotations

from security_checker.aggregate.agreement import compute_agreement
from security_checker.aggregate.base import AggregationOutcome, Aggregator
from security_checker.aggregate.consensus import ConsensusAggregator
from security_checker.aggregate.findings import build_findings
from security_checker.aggregate.registry import BUILTIN_AGGREGATORS, build_aggregator

__all__ = [
    "BUILTIN_AGGREGATORS",
    "AggregationOutcome",
    "Aggregator",
    "ConsensusAggregator",
    "build_aggregator",
    "build_findings",
    "compute_agreement",
]
