"""Weighted 戦略 (設計書 §14.2).

各 Reviewer の判定を重み × 確信度で符号付きに足し合わせ、-1.0〜+1.0 のスコアにする。

重みの用途は 2 つ。
  1. モデルの実力差を反映する
  2. 安いモデルを多数決に参加させつつ、影響を抑える

**重みは勘で決めない。** `security-checker eval` の結果を根拠にすること (§14.2)。
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping

from security_checker.aggregate.agreement import compute_agreement
from security_checker.aggregate.base import (
    NUMBER_SEVERITY,
    SEVERITY_NUMBER,
    AggregationOutcome,
)
from security_checker.aggregate.consensus import _describe, _headline
from security_checker.config.schema import AggregationConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Agreement, FindingStatus, Severity
from security_checker.models.verdict import ReviewVerdict, VerdictStatus

#: threshold をどれだけ上回れば confirmed とするか (§14.2)
CONFIRMED_MARGIN = 0.2
DEFAULT_WEIGHT = 1.0


class WeightedAggregator:
    """重み付きスコアで status を決める."""

    name = "weighted"

    def __init__(self, weights: Mapping[str, float] | None = None) -> None:
        # 設定に書かれていない Reviewer は等倍。重みの解決はここに閉じる
        self.weights = dict(weights or {})

    def weight_of(self, verdict: ReviewVerdict) -> float:
        return self.weights.get(verdict.reviewer, DEFAULT_WEIGHT)

    def aggregate(
        self,
        candidate: Candidate,
        verdicts: list[ReviewVerdict],
        cfg: AggregationConfig,
    ) -> AggregationOutcome:
        valid = [verdict for verdict in verdicts if verdict.status is VerdictStatus.OK]
        if not valid:
            return AggregationOutcome(
                status=FindingStatus.ERROR,
                severity=candidate.severity_reported or Severity.INFO,
                confidence=0.0,
                agreement=Agreement.NOT_APPLICABLE,
                summary="有効な判定が得られませんでした (Reviewer 側のエラー)。",
                detail={
                    "strategy": self.name,
                    "valid_verdicts": 0,
                    "total_verdicts": len(verdicts),
                },
            )

        total_weight = sum(self.weight_of(verdict) for verdict in valid)
        if total_weight <= 0:
            # 全員の重みが 0 なら、多数決の材料が無い。黙って 0 点にしない
            return AggregationOutcome(
                status=FindingStatus.REVIEW_REQUIRED,
                severity=candidate.severity_reported or Severity.INFO,
                confidence=0.0,
                agreement=compute_agreement(valid),
                summary="すべての Reviewer の重みが 0 のため、集約できませんでした。",
                detail={
                    "strategy": self.name,
                    "valid_verdicts": len(valid),
                    "total_weight": total_weight,
                },
            )

        if all(verdict.needs_more_context for verdict in valid) and not any(
            verdict.vulnerable for verdict in valid
        ):
            return self._outcome(
                FindingStatus.INCONCLUSIVE,
                valid,
                candidate,
                score=0.0,
                summary="文脈が不足しているため判断できませんでした。人間の確認を推奨します。",
                extra={"reason": "all_reviewers_requested_more_context"},
            )

        score = (
            sum(
                self.weight_of(verdict) * verdict.confidence * (1.0 if verdict.vulnerable else -1.0)
                for verdict in valid
            )
            / total_weight
        )
        threshold = cfg.weighted.threshold
        vulnerable = [verdict for verdict in valid if verdict.vulnerable]

        if score >= threshold:
            status = (
                FindingStatus.CONFIRMED
                if score >= threshold + CONFIRMED_MARGIN
                else FindingStatus.LIKELY
            )
            return self._outcome(
                status,
                valid,
                candidate,
                score=score,
                severity=self._severity(vulnerable, cfg),
                summary=self._summary(vulnerable, score),
                extra={"threshold": threshold},
            )
        if score <= -threshold:
            return self._outcome(
                FindingStatus.FALSE_POSITIVE,
                valid,
                candidate,
                score=score,
                severity=Severity.NONE,
                summary="重み付きの判定は「脆弱ではない」に傾きました。",
                extra={"threshold": threshold},
            )
        return self._outcome(
            FindingStatus.REVIEW_REQUIRED,
            valid,
            candidate,
            score=score,
            severity=self._severity(vulnerable, cfg) if vulnerable else None,
            summary="判断が分かれました。人間による確認を推奨します。",
            extra={"threshold": threshold},
        )

    # --- 内部 -------------------------------------------------------------

    def _severity(self, vulnerable: list[ReviewVerdict], cfg: AggregationConfig) -> Severity:
        """「脆弱」と答えた Reviewer の severity から決める.

        weighted_mean のときだけ重みを使う。median / max は外れ値の扱いの話であって、
        重みの話ではないため。
        """
        if not vulnerable:
            return Severity.NONE
        numbers = [SEVERITY_NUMBER[verdict.severity] for verdict in vulnerable]
        mode = cfg.consensus.severity
        if mode == "max":
            value = float(max(numbers))
        elif mode == "weighted_mean":
            weights = [self.weight_of(verdict) for verdict in vulnerable]
            total = sum(weights)
            value = (
                sum(number * weight for number, weight in zip(numbers, weights, strict=True))
                / total
                if total > 0
                else statistics.fmean(numbers)
            )
        else:
            value = float(statistics.median(numbers))
        return NUMBER_SEVERITY[round(value)]

    def _summary(self, vulnerable: list[ReviewVerdict], score: float) -> str:
        if not vulnerable:
            return f"重み付きスコア {score:+.2f}。"
        return f"{_headline(vulnerable[0])} (重み付きスコア {score:+.2f})"

    def _outcome(
        self,
        status: FindingStatus,
        valid: list[ReviewVerdict],
        candidate: Candidate,
        *,
        score: float,
        severity: Severity | None = None,
        summary: str = "",
        extra: dict[str, object] | None = None,
    ) -> AggregationOutcome:
        agreement = compute_agreement(valid)
        # 計算過程を必ず残す。「なぜこの status になったか」を後から再現できること (P4)
        detail: dict[str, object] = {
            "strategy": self.name,
            "valid_verdicts": len(valid),
            "score": round(score, 4),
            "weights": {verdict.reviewer: self.weight_of(verdict) for verdict in valid},
            "reviewers": {verdict.reviewer: _describe(verdict) for verdict in valid},
        }
        detail.update(extra or {})

        # スコアの絶対値をそのまま confidence として使う (符号は status が持っている)
        confidence = min(abs(score), 1.0)
        # agreement が低いときは confidence を引き下げる方向にだけ効かせる (§15)
        if agreement is Agreement.LOW:
            confidence = min(confidence, 0.5)
        return AggregationOutcome(
            status=status,
            severity=severity
            if severity is not None
            else (candidate.severity_reported or Severity.INFO),
            confidence=round(confidence, 4),
            agreement=agreement if len(valid) > 1 else Agreement.NOT_APPLICABLE,
            summary=summary,
            detail=detail,
        )
