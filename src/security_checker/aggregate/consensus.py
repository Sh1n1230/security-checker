"""Consensus 戦略 (設計書 §14.1, §13.2).

意見が割れたときに無理に 1 つの答えを出さない。`review_required` は敗北ではなく正しい出力。
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
from security_checker.config.schema import AggregationConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Agreement, FindingStatus, Severity
from security_checker.models.verdict import ReviewVerdict, VerdictStatus

#: 見出しに使う長さ. reasoning から作る場合の上限 (文の区切りで詰める)。
SUMMARY_LIMIT = 200
SUMMARY_HEAD_LIMIT = 160
SINGLE_CONFIRMED_CONFIDENCE = 0.8
SINGLE_LIKELY_CONFIDENCE = 0.5


class ConsensusAggregator:
    """「脆弱」と判定した Reviewer 数と比率で status を決める."""

    name = "consensus"

    def __init__(self, weights: Mapping[str, float] | None = None) -> None:
        # 多数決に重みの概念は無い。registry に戦略ごとの分岐を作らないため、
        # 受け取るだけ受け取って使わない (§13)。
        self.weights = dict(weights or {})

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

        if all(verdict.needs_more_context for verdict in valid) and not any(
            verdict.vulnerable for verdict in valid
        ):
            return self._outcome(
                FindingStatus.INCONCLUSIVE,
                valid,
                candidate,
                summary="文脈が不足しているため判断できませんでした。人間の確認を推奨します。",
                extra={"reason": "all_reviewers_requested_more_context"},
            )

        agreement = compute_agreement(valid)
        # min_confidence の閾値判定は Policy 側の責務。ここでは票数と比率だけを見る。
        vulnerable = [verdict for verdict in valid if verdict.vulnerable]
        votes = len(vulnerable)
        ratio = votes / len(valid)

        if len(valid) == 1:
            return self._single(valid[0], candidate, ratio)

        if votes >= cfg.consensus.min_votes and ratio >= cfg.consensus.min_ratio:
            mean_confidence = statistics.fmean(v.confidence for v in vulnerable)
            status = (
                FindingStatus.CONFIRMED
                if agreement is Agreement.HIGH and mean_confidence >= 0.8
                else FindingStatus.LIKELY
            )
            return self._outcome(
                status,
                valid,
                candidate,
                severity=self._severity(vulnerable, cfg),
                confidence=mean_confidence,
                agreement=agreement,
                summary=self._summary(vulnerable, votes, len(valid)),
                extra={"votes": votes, "ratio": ratio, "mean_confidence": mean_confidence},
            )
        if votes == 0:
            return self._outcome(
                FindingStatus.FALSE_POSITIVE,
                valid,
                candidate,
                severity=Severity.NONE,
                confidence=statistics.fmean(v.confidence for v in valid),
                agreement=agreement,
                summary="すべての Reviewer が「脆弱ではない」と判断しました。",
                extra={"votes": 0, "ratio": 0.0},
            )
        return self._outcome(
            FindingStatus.REVIEW_REQUIRED,
            valid,
            candidate,
            severity=self._severity(vulnerable, cfg),
            confidence=statistics.fmean(v.confidence for v in valid),
            agreement=agreement,
            summary="判断が分かれました。人間による確認を推奨します。",
            extra={"votes": votes, "ratio": ratio},
        )

    # --- 内部 -------------------------------------------------------------

    def _single(
        self, verdict: ReviewVerdict, candidate: Candidate, ratio: float
    ) -> AggregationOutcome:
        """Reviewer が 1 個のときは confidence だけで status を決める (§13.2)."""
        if not verdict.vulnerable:
            status = FindingStatus.FALSE_POSITIVE
        elif verdict.confidence >= SINGLE_CONFIRMED_CONFIDENCE:
            status = FindingStatus.CONFIRMED
        elif verdict.confidence >= SINGLE_LIKELY_CONFIDENCE:
            status = FindingStatus.LIKELY
        else:
            status = FindingStatus.REVIEW_REQUIRED
        summary = (
            _headline(verdict)
            if verdict.vulnerable
            else "Reviewer は「脆弱ではない」と判断しました。"
        )
        return AggregationOutcome(
            status=status,
            severity=verdict.severity if verdict.vulnerable else Severity.NONE,
            confidence=verdict.confidence,
            agreement=Agreement.NOT_APPLICABLE,
            summary=summary,
            detail={
                "strategy": self.name,
                "mode": "single_reviewer",
                "votes": 1 if verdict.vulnerable else 0,
                "ratio": ratio,
                "reviewers": {verdict.reviewer: _describe(verdict)},
            },
        )

    def _severity(self, vulnerable: list[ReviewVerdict], cfg: AggregationConfig) -> Severity:
        numbers = [SEVERITY_NUMBER[verdict.severity] for verdict in vulnerable]
        if not numbers:
            return Severity.NONE
        mode = cfg.consensus.severity
        if mode == "max":
            value = max(numbers)
        elif mode == "weighted_mean":
            value = round(statistics.fmean(numbers))
        else:  # median: 1 モデルの過大評価でノイズが増えるのを防ぐ
            value = round(statistics.median(numbers))
        return NUMBER_SEVERITY[int(value)]

    def _summary(self, vulnerable: list[ReviewVerdict], votes: int, total: int) -> str:
        head = _headline(vulnerable[0], limit=SUMMARY_HEAD_LIMIT)
        return f"{head} ({votes}/{total} の Reviewer が脆弱と判断)"

    def _outcome(
        self,
        status: FindingStatus,
        valid: list[ReviewVerdict],
        candidate: Candidate,
        *,
        severity: Severity | None = None,
        confidence: float | None = None,
        agreement: Agreement | None = None,
        summary: str = "",
        extra: dict[str, object] | None = None,
    ) -> AggregationOutcome:
        detail: dict[str, object] = {
            "strategy": self.name,
            "valid_verdicts": len(valid),
            "reviewers": {verdict.reviewer: _describe(verdict) for verdict in valid},
        }
        detail.update(extra or {})
        resolved_agreement = agreement or compute_agreement(valid)
        resolved_confidence = (
            confidence if confidence is not None else statistics.fmean(v.confidence for v in valid)
        )
        # agreement が低いときは confidence を引き下げる方向にだけ効かせる (§15)
        if resolved_agreement is Agreement.LOW:
            resolved_confidence = min(resolved_confidence, 0.5)
        return AggregationOutcome(
            status=status,
            severity=severity
            if severity is not None
            else (candidate.severity_reported or Severity.INFO),
            confidence=round(resolved_confidence, 4),
            agreement=resolved_agreement,
            summary=summary,
            detail=detail,
        )


def _headline(verdict: ReviewVerdict, limit: int = SUMMARY_LIMIT) -> str:
    """Finding の 1 行見出し.

    種別名 (`vulnerability_type`) を優先する。無い場合だけ reasoning を使うが、
    **文字数で機械的に切らない**。reasoning は数百字の説明文なので、
    途中で切れると読めない断片がレポートの見出しに残る。
    """
    if verdict.vulnerability_type:
        return verdict.vulnerability_type.strip()
    return _first_sentence(verdict.reasoning, limit)


def _first_sentence(text: str, limit: int) -> str:
    """先頭の 1 文を返す. 収まらなければ文・節の区切りまで戻して詰める."""
    line = " ".join(text.split("\n")[0].split()).strip()
    if len(line) <= limit:
        return line
    window = line[:limit]
    for terminator in ("。", ". ", "! ", "? ", "、", " "):
        cut = window.rfind(terminator)
        if cut > limit // 2:
            return window[: cut + len(terminator)].strip() + " …"
    return window + " …"


def _describe(verdict: ReviewVerdict) -> dict[str, object]:
    return {
        "vulnerable": verdict.vulnerable,
        "severity": verdict.severity.value,
        "confidence": verdict.confidence,
        "false_positive_probability": verdict.false_positive_probability,
        "status": verdict.status.value,
    }
