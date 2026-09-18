"""評価 (eval) — LLM レビューが本当に効いているかを測る (設計書 §26-27)."""

from __future__ import annotations

from security_checker.eval.dataset import Dataset, EvalCase, GroundTruth, load_dataset
from security_checker.eval.metrics import CaseOutcome, Metrics, evaluate_outcomes

__all__ = [
    "CaseOutcome",
    "Dataset",
    "EvalCase",
    "GroundTruth",
    "Metrics",
    "evaluate_outcomes",
    "load_dataset",
]
