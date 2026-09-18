"""評価指標 (設計書 §27.2).

**Recall を主指標に置く。** FP を減らすのは簡単で (全部 false_positive と言えばよい)、
FP 削減率だけを見ると容易に自己欺瞞に陥る。意味のある問いは
**「見逃しを増やさずに FP をどれだけ削れたか」**だけである。

`review_required` は TP でも FN でもない。「人間に渡した」という第 3 の結果として
別に数える。ここを混ぜると、判断を保留しただけで数字が良く見えてしまう。
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from security_checker.aggregate.base import SEVERITY_NUMBER
from security_checker.models.enums import FindingStatus, Severity

#: 「脆弱と報告した」とみなす status
REPORTED_AS_VULNERABLE = (FindingStatus.CONFIRMED, FindingStatus.LIKELY)
#: 「脆弱ではないと切り捨てた」とみなす status
DISMISSED = (FindingStatus.FALSE_POSITIVE,)
#: 人間に渡した (どちらにも数えない)
DEFERRED = (FindingStatus.REVIEW_REQUIRED, FindingStatus.INCONCLUSIVE)


class CaseOutcome(BaseModel):
    """1 ケースの評価結果."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    expected_vulnerable: bool
    expected_severity: Severity
    expected_cwe: list[str] = Field(default_factory=list)

    status: FindingStatus
    severity: Severity
    cwe: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    latency_ms: int = 0
    usd: float | None = None
    cost_known: bool = True
    summary: str = ""

    @property
    def reported(self) -> bool:
        return self.status in REPORTED_AS_VULNERABLE

    @property
    def dismissed(self) -> bool:
        return self.status in DISMISSED

    @property
    def deferred(self) -> bool:
        return self.status in DEFERRED

    @property
    def errored(self) -> bool:
        return self.status is FindingStatus.ERROR


class Metrics(BaseModel):
    """データセット全体の指標."""

    model_config = ConfigDict(frozen=True)

    cases: int = 0
    errors: int = 0

    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    deferred_positives: int = 0
    deferred_negatives: int = 0

    recall: float | None = None
    precision: float | None = None
    f1: float | None = None
    #: スキャナ単体の FP を、LLM レビューがどれだけ削ったか
    fp_reduction: float | None = None
    #: 真陽性を誤って切り捨てた件数. **ここが 0 に近いことが必須条件** (§27.2)
    missed_true_positives: int = 0
    review_required_rate: float = 0.0
    severity_mae: float | None = None
    cwe_match_rate: float | None = None

    total_usd: float | None = None
    cost_known: bool = True
    mean_latency_ms: float = 0.0

    #: 見逃したケースの id. 数字だけでなく必ず実物を列挙する (§27.2)
    missed_case_ids: list[str] = Field(default_factory=list)


def evaluate_outcomes(outcomes: Sequence[CaseOutcome]) -> Metrics:
    """ケースごとの結果から指標を計算する."""
    if not outcomes:
        return Metrics()

    graded = [outcome for outcome in outcomes if not outcome.errored]
    errors = len(outcomes) - len(graded)

    true_positives = sum(1 for o in graded if o.expected_vulnerable and o.reported)
    false_negatives = sum(1 for o in graded if o.expected_vulnerable and o.dismissed)
    false_positives = sum(1 for o in graded if not o.expected_vulnerable and o.reported)
    true_negatives = sum(1 for o in graded if not o.expected_vulnerable and o.dismissed)
    deferred_positives = sum(1 for o in graded if o.expected_vulnerable and o.deferred)
    deferred_negatives = sum(1 for o in graded if not o.expected_vulnerable and o.deferred)

    recall = _ratio(true_positives, true_positives + false_negatives)
    precision = _ratio(true_positives, true_positives + false_positives)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )

    # スキャナ単体なら「陰性ケースはすべて FP として報告されていた」ことになる。
    # そこからどれだけ削れたかを見る (§27.2)
    scanner_false_positives = sum(1 for o in graded if not o.expected_vulnerable)
    fp_reduction = (
        (scanner_false_positives - false_positives) / scanner_false_positives
        if scanner_false_positives
        else None
    )

    severity_pairs = [
        (o.expected_severity, o.severity) for o in graded if o.expected_vulnerable and o.reported
    ]
    severity_mae = (
        sum(
            abs(SEVERITY_NUMBER[expected] - SEVERITY_NUMBER[actual])
            for expected, actual in severity_pairs
        )
        / len(severity_pairs)
        if severity_pairs
        else None
    )

    cwe_targets = [o for o in graded if o.expected_cwe and o.reported]
    cwe_match_rate = (
        sum(1 for o in cwe_targets if set(o.expected_cwe) & set(o.cwe)) / len(cwe_targets)
        if cwe_targets
        else None
    )

    known_costs = [o.usd for o in outcomes if o.cost_known and o.usd is not None]
    cost_known = all(o.cost_known for o in outcomes)

    return Metrics(
        cases=len(outcomes),
        errors=errors,
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        deferred_positives=deferred_positives,
        deferred_negatives=deferred_negatives,
        recall=recall,
        precision=precision,
        f1=f1,
        fp_reduction=fp_reduction,
        missed_true_positives=false_negatives,
        review_required_rate=(deferred_positives + deferred_negatives) / len(graded)
        if graded
        else 0.0,
        severity_mae=severity_mae,
        cwe_match_rate=cwe_match_rate,
        total_usd=sum(known_costs) if known_costs and cost_known else None,
        cost_known=cost_known,
        mean_latency_ms=sum(o.latency_ms for o in outcomes) / len(outcomes),
        missed_case_ids=[o.case_id for o in graded if o.expected_vulnerable and o.dismissed],
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    """母数が 0 のときは 0.0 ではなく None を返す.

    「該当ケースが無かった」を「スコア 0」と表示すると読み違える。
    """
    if denominator == 0:
        return None
    return numerator / denominator
