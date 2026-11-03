"""Consensus 戦略 (設計書 §14.1, §13.2).

意見が割れたときに無理に 1 つの答えを出さない。`review_required` は敗北ではなく正しい出力。
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping

from security_checker.aggregate.agreement import compute_agreement
from security_checker.aggregate.base import (
    DECISIVE_CONFIDENCE,
    AggregationOutcome,
    aggregate_severity,
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
        # 票の数え方に重みは使わない。使うのは severity: weighted_mean のときだけ (§14.1)
        self.weights = dict(weights or {})

    def weight_of(self, verdict: ReviewVerdict) -> float:
        return self.weights.get(verdict.reviewer, 1.0)

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

        if len(verdicts) == 1:
            return single_outcome(self.name, valid[0], candidate)
        if len(valid) == 1:
            return partial_outcome(self.name, valid[0], verdicts, candidate)

        # 半々は「過半数」ではなく判断が割れた状態 (§13.1)。min_ratio が低くても likely にしない
        if votes >= cfg.consensus.min_votes and ratio >= cfg.consensus.min_ratio and ratio > 0.5:
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
                severity=aggregate_severity(vulnerable, cfg.consensus.severity, self.weight_of),
                confidence=mean_confidence,
                agreement=agreement,
                summary=self._summary(vulnerable, votes, len(valid)),
                extra={"votes": votes, "ratio": ratio, "mean_confidence": mean_confidence},
            )
        if votes == 0:
            mean_confidence = statistics.fmean(v.confidence for v in valid)
            if mean_confidence >= DECISIVE_CONFIDENCE and not any(
                v.needs_more_context for v in valid
            ):
                return self._outcome(
                    FindingStatus.FALSE_POSITIVE,
                    valid,
                    candidate,
                    severity=Severity.NONE,
                    confidence=mean_confidence,
                    agreement=agreement,
                    summary="すべての Reviewer が「脆弱ではない」と判断しました。",
                    extra={"votes": 0, "ratio": 0.0},
                )
            # 自信の無い「脆弱ではない」で候補を消さない
            return self._outcome(
                FindingStatus.REVIEW_REQUIRED,
                valid,
                candidate,
                confidence=mean_confidence,
                agreement=agreement,
                summary="「脆弱ではない」という判定の確信度が低いため、人間による確認を推奨します。",
                extra={"votes": 0, "ratio": 0.0, "mean_confidence": mean_confidence},
            )
        return self._outcome(
            FindingStatus.REVIEW_REQUIRED,
            valid,
            candidate,
            severity=aggregate_severity(vulnerable, cfg.consensus.severity, self.weight_of),
            confidence=statistics.fmean(v.confidence for v in valid),
            agreement=agreement,
            summary="判断が分かれました。人間による確認を推奨します。",
            extra={"votes": votes, "ratio": ratio},
        )

    # --- 内部 -------------------------------------------------------------

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


def single_outcome(
    strategy: str, verdict: ReviewVerdict, candidate: Candidate
) -> AggregationOutcome:
    """Reviewer が 1 個のときは confidence だけで status を決める (§13.2).

    どの戦略を選んでも、Reviewer が 1 体なら同じ結果になる。
    """
    severity = verdict.severity
    if not verdict.vulnerable:
        if verdict.confidence >= DECISIVE_CONFIDENCE and not verdict.needs_more_context:
            status = FindingStatus.FALSE_POSITIVE
            severity = Severity.NONE
            summary = "Reviewer は「脆弱ではない」と判断しました。"
        else:
            status = FindingStatus.REVIEW_REQUIRED
            severity = candidate.severity_reported or Severity.INFO
            summary = "「脆弱ではない」という判定の確信度が低いため、人間による確認を推奨します。"
    else:
        summary = _headline(verdict)
        if verdict.confidence >= SINGLE_CONFIRMED_CONFIDENCE:
            status = FindingStatus.CONFIRMED
        elif verdict.confidence >= SINGLE_LIKELY_CONFIDENCE:
            status = FindingStatus.LIKELY
        else:
            status = FindingStatus.REVIEW_REQUIRED
    return AggregationOutcome(
        status=status,
        severity=severity,
        confidence=verdict.confidence,
        agreement=Agreement.NOT_APPLICABLE,
        summary=summary,
        detail={
            "strategy": strategy,
            "mode": "single_reviewer",
            "votes": 1 if verdict.vulnerable else 0,
            "ratio": 1.0 if verdict.vulnerable else 0.0,
            "reviewers": {verdict.reviewer: _describe(verdict)},
        },
    )


def partial_outcome(
    strategy: str,
    survivor: ReviewVerdict,
    verdicts: list[ReviewVerdict],
    candidate: Candidate,
) -> AggregationOutcome:
    """複数の Reviewer に割り当てたが、有効な判定が 1 つしか残らなかったとき.

    単独 Reviewer の規則 (§13.2) をそのまま当てると、他の Reviewer が落ちただけで
    残った 1 体の「脆弱ではない」が false_positive になり候補が消える。
    割れたら答えを出さない原則と P9 に従い、false_positive にも confirmed にもしない。
    """
    failed = len(verdicts) - 1
    if survivor.vulnerable and survivor.confidence >= SINGLE_LIKELY_CONFIDENCE:
        status = FindingStatus.LIKELY
    else:
        status = FindingStatus.REVIEW_REQUIRED
    if survivor.vulnerable:
        head = _headline(survivor, limit=SUMMARY_HEAD_LIMIT)
        summary = f"{head} ({len(verdicts)} 中 1 の Reviewer のみ判定)"
        severity = survivor.severity
    else:
        summary = (
            f"{len(verdicts)} 中 {failed} の Reviewer が判定できず、残った 1 つの判定だけでは"
            "決められません。人間による確認を推奨します。"
        )
        severity = candidate.severity_reported or Severity.INFO
    return AggregationOutcome(
        status=status,
        severity=severity,
        confidence=survivor.confidence,
        agreement=Agreement.NOT_APPLICABLE,
        summary=summary,
        detail={
            "strategy": strategy,
            "mode": "partial_reviewers",
            "valid_verdicts": 1,
            "failed_verdicts": failed,
            "votes": 1 if survivor.vulnerable else 0,
            "reviewers": {verdict.reviewer: _describe(verdict) for verdict in verdicts},
        },
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
