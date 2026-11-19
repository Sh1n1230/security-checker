"""`review --estimate` — 実行前の費用見積り (設計書 §24.3).

「候補 N 件 × Reviewer M 個 ≈ 概算 $X」を、**1 件も送信せずに**出す。
入力は実際に送るプロンプトから数え、出力は max_output_tokens を上限として数える。

金額は 2 つ出す (#314)。

- **見積り**: 各候補を 1 回ずつ送った場合。修復の再送は無いものとする
- **上限**: 全呼び出しがスキーマ違反で修復の再送 (1 回まで) をした場合

Judge の入力には、Judge 以外の Reviewer の意見が入る。意見の長さは、その Reviewer の
max_output_tokens を上限として数える (意見は Reviewer の出力から作るため)。
トークン数は推定値なので、上限も厳密な保証ではない (トークナイザの差が残る)。

推測はしない。価格表に無いモデルと process transport は「不明」と表示し、
合計も不明にする (一部だけ足した合計は、実際より安く見えるため)。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from security_checker.context.budget import estimate_tokens
from security_checker.language import resolve_language
from security_checker.models.verdict import Usage
from security_checker.review import prompts
from security_checker.review.structured import verdict_schema

if TYPE_CHECKING:
    from security_checker.config.schema import Config
    from security_checker.models.task import ReviewTask
    from security_checker.observability.cost import PriceTable


@dataclass
class ReviewerEstimate:
    """Reviewer 1 体分の見積り. `upper_*` は修復の再送をすべて含めた上限."""

    name: str
    calls: int
    input_tokens: int
    max_output_tokens: int
    usd: float | None
    upper_calls: int = 0
    upper_input_tokens: int = 0
    upper_output_tokens: int = 0
    upper_usd: float | None = None
    note: str = ""


@dataclass
class Estimate:
    """実行全体の見積り."""

    tasks: int
    reviewers: list[ReviewerEstimate] = field(default_factory=list)

    @property
    def total_usd(self) -> float | None:
        """合計の金額. 価格の分からない Reviewer が混ざれば None."""
        if any(r.usd is None for r in self.reviewers):
            return None
        return sum(r.usd or 0.0 for r in self.reviewers)

    @property
    def total_upper_usd(self) -> float | None:
        """修復の再送をすべて含めた上限の合計. 価格の分からない Reviewer が混ざれば None."""
        if any(r.upper_usd is None for r in self.reviewers):
            return None
        return sum(r.upper_usd or 0.0 for r in self.reviewers)

    @property
    def total_input_tokens(self) -> int:
        """入力トークン数の合計."""
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
    judge_name = (
        config.aggregation.judge.reviewer if config.aggregation.strategy == "judge" else None
    )
    peers_output = [r.max_output_tokens for r in config.reviewers if r.name != judge_name]

    estimate = Estimate(tasks=len(tasks))
    for reviewer in config.reviewers:
        is_judge = reviewer.name == judge_name
        if is_judge:
            # 割れた候補だけに回す設定でも、上限として全件で数える
            first, repair = _judge_input(tasks, schema, language, peers_output)
        else:
            first, repair = _review_input(tasks, schema, language)
        calls = len(tasks)
        output_tokens = reviewer.max_output_tokens * calls
        # 修復の入力には前回の出力 (max_output_tokens まで) が入る
        upper_input = first + repair + output_tokens
        upper_output = output_tokens * 2
        note = "Judge (上限: 全候補が割れた場合)" if is_judge else ""
        usd: float | None = None
        upper_usd: float | None = None
        if reviewer.transport == "process":
            note = (note + " " if note else "") + "process transport は使用量を計測できません"
        else:
            price = price_table.lookup(reviewer.model or "")
            if price is None:
                note = (note + " " if note else "") + f"価格表に {reviewer.model} がありません"
            else:
                usd = price.estimate(Usage(input_tokens=first, output_tokens=output_tokens))
                upper_usd = price.estimate(
                    Usage(input_tokens=upper_input, output_tokens=upper_output)
                )
        estimate.reviewers.append(
            ReviewerEstimate(
                name=reviewer.name,
                calls=calls,
                input_tokens=first,
                max_output_tokens=output_tokens,
                usd=usd,
                upper_calls=calls * 2,
                upper_input_tokens=upper_input,
                upper_output_tokens=upper_output,
                upper_usd=upper_usd,
                note=note,
            )
        )
    return estimate


def _review_input(
    tasks: list[ReviewTask], schema: dict[str, object], language: str
) -> tuple[int, int]:
    """(1 回目の入力, 修復の入力から前回出力を除いた分) を全候補で足して返す."""
    system = estimate_tokens(prompts.render_system(language))
    first = repair = 0
    for task in tasks:
        user = prompts.render_user(task, schema)
        first += system + estimate_tokens(user)
        repair += system + _repair_tokens(user, schema, language)
    return first, repair


def _judge_input(
    tasks: list[ReviewTask], schema: dict[str, object], language: str, peers_output: list[int]
) -> tuple[int, int]:
    """Judge の (1 回目の入力, 修復の入力から前回出力を除いた分). 意見は出力の上限で数える."""
    system = estimate_tokens(prompts.render_judge_system(language))
    opinions = [_EMPTY_OPINION] * len(peers_output)
    # 意見の中身を除いた枠 (ラベルや項目名) の分は、空の意見を描画して数える
    opinions_bound = sum(peers_output)
    first = repair = 0
    for task in tasks:
        user = prompts.render_judge_user(task, schema, opinions)
        first += system + estimate_tokens(user) + opinions_bound
        repair += system + _repair_tokens(user, schema, language) + opinions_bound
    return first, repair


def _repair_tokens(original_user: str, schema: dict[str, object], language: str) -> int:
    """修復プロンプトのうち、前回の出力を除いた分 (元の user と指示とエラー)."""
    return estimate_tokens(
        prompts.render_repair("", "", schema, language, original_user=original_user)
    )


_EMPTY_OPINION = prompts.PeerOpinion(
    label="Auditor",
    vulnerable=False,
    severity="none",
    confidence=0.0,
    false_positive_probability=0.0,
    exploitability="unknown",
    reasoning="",
)
