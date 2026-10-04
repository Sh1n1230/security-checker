"""`review --estimate` — 実行前の費用見積り (設計書 §24.3).

「候補 N 件 × Reviewer M 個 ≈ 概算 $X」を、**1 件も送信せずに**出す。
入力は実際に送るプロンプトから数え、出力は max_output_tokens を上限として数える。
したがって金額は**上限寄りの見積り**である。

推測はしない。価格表に無いモデルと process transport は「不明」と表示し、
合計も不明にする (一部だけ足した合計は、実際より安く見えるため)。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from security_checker.config.schema import Config
from security_checker.context.budget import estimate_tokens
from security_checker.language import resolve_language
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import Usage
from security_checker.observability.cost import PriceTable
from security_checker.review import prompts
from security_checker.review.structured import verdict_schema


@dataclass
class ReviewerEstimate:
    name: str
    calls: int
    input_tokens: int
    max_output_tokens: int
    usd: float | None
    note: str = ""


@dataclass
class Estimate:
    tasks: int
    reviewers: list[ReviewerEstimate] = field(default_factory=list)

    @property
    def total_usd(self) -> float | None:
        if any(r.usd is None for r in self.reviewers):
            return None
        return sum(r.usd or 0.0 for r in self.reviewers)

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self.reviewers)


def estimate_run(
    tasks: list[ReviewTask],
    config: Config,
    price_table: PriceTable,
    environ: dict[str, str] | None = None,
) -> Estimate:
    """送信予定のプロンプトから使用量と金額を見積もる."""
    schema = verdict_schema()
    language = resolve_language(config.output.language, environ)
    system_tokens = estimate_tokens(prompts.render_system(language))
    per_task = [system_tokens + estimate_tokens(prompts.render_user(t, schema)) for t in tasks]
    review_input = sum(per_task)

    judge_name = (
        config.aggregation.judge.reviewer if config.aggregation.strategy == "judge" else None
    )
    estimate = Estimate(tasks=len(tasks))
    for reviewer in config.reviewers:
        is_judge = reviewer.name == judge_name
        # Judge は意見の分だけ入力が増える。割れた候補だけに回す設定でも、上限として全件で数える
        input_tokens = int(review_input * 1.5) if is_judge else review_input
        output_tokens = reviewer.max_output_tokens * len(tasks)
        note = "Judge (上限: 全候補が割れた場合)" if is_judge else ""
        usd: float | None = None
        if reviewer.transport == "process":
            note = (note + " " if note else "") + "process transport は使用量を計測できません"
        else:
            price = price_table.lookup(reviewer.model or "")
            if price is None:
                note = (note + " " if note else "") + f"価格表に {reviewer.model} がありません"
            else:
                usd = price.estimate(Usage(input_tokens=input_tokens, output_tokens=output_tokens))
        estimate.reviewers.append(
            ReviewerEstimate(
                name=reviewer.name,
                calls=len(tasks),
                input_tokens=input_tokens,
                max_output_tokens=output_tokens,
                usd=usd,
                note=note,
            )
        )
    return estimate
