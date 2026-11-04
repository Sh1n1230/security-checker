"""Reviewer = Provider + プロンプト + ポリシー (設計書 §11, §10.2).

Reviewer は 1 候補について 1 つの ReviewVerdict を返す。
他の Reviewer の存在・出力を一切知らない (P6: 独立性)。
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from security_checker.language import DEFAULT_LANGUAGE
from security_checker.models.enums import Severity
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import ReviewVerdict, Usage, VerdictStatus
from security_checker.observability.cost import ModelPrice
from security_checker.observability.trace import sha256_text
from security_checker.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
    StructuredMode,
)
from security_checker.review import prompts
from security_checker.review.structured import (
    SchemaViolationError,
    drop_hallucinated_evidence,
    parse_judgement,
    verdict_schema,
)

#: レビューは再現性を優先する (§11.5)
REVIEW_TEMPERATURE = 0.0


class SendCancelledError(Exception):
    """送信の直前に止められた (予算超過・無効化・デッドライン). 提供元には何も送っていない."""


#: 1 回の送信の直前に呼ぶフック. レート制御と停止の判定はスケジューラが受け持つ (§22)
BeforeSend = Callable[[], Awaitable[None]]


class ReviewOutcome:
    """Verdict と、それに付随する警告・トレース記録."""

    def __init__(
        self,
        verdict: ReviewVerdict,
        *,
        warnings: list[str] | None = None,
        raw_text: str = "",
        attempts: int = 1,
        trace: dict[str, Any] | None = None,
    ) -> None:
        """ReviewOutcome を初期化する."""
        self.verdict = verdict
        self.warnings = warnings or []
        self.raw_text = raw_text
        self.attempts = attempts
        self.trace = trace or {}


class Reviewer:
    """1 つの Provider を Security Auditor として使う."""

    def __init__(
        self,
        name: str,
        provider: LLMProvider,
        *,
        weight: float = 1.0,
        max_output_tokens: int = 2000,
        timeout_s: float = 120.0,
        seed: int | None = None,
        price: ModelPrice | None = None,
        save_prompts: bool = False,
        language: str = DEFAULT_LANGUAGE,
    ) -> None:
        """Reviewer を初期化する (設計書 §11)."""
        self.name = name
        self.provider = provider
        self.weight = weight
        self.max_output_tokens = max_output_tokens
        self.timeout_s = timeout_s
        self.seed = seed
        self.price = price
        self.save_prompts = save_prompts
        self.language = language

    @property
    def model(self) -> str:
        """使用中のモデル名を返す。不明な場合は 'unknown'."""
        return getattr(self.provider, "model", "unknown")

    async def review(
        self,
        task: ReviewTask,
        *,
        opinions: Sequence[prompts.PeerOpinion] | None = None,
        before_send: BeforeSend | None = None,
    ) -> ReviewOutcome:
        """1 候補をレビューする. スキーマ返後は 1 回まで修正を試みる (§10.2).

        `opinions` があると Judge のように動く (§16)。他の Reviewer の判定結果を
        知らないまま自分の判定を出す。出力のスキーマは必要なら
        修正を試みる。

        `before_send` は送信直前のフックを呼ぶ。レート制御と停止の判定はスケジューラが受け持つ
        (§22)。http/tp/rpd の提供元には何も送らない。
        1 回まで修正を試み、スキーマ違反が残ったら `SendCancelledError` を出す。
        """
        schema = verdict_schema()
        if opinions is None:
            system = prompts.render_system(self.language)
            user = prompts.render_user(task, schema)
        else:
            system = prompts.render_judge_system(self.language)
            user = prompts.render_judge_user(task, schema, opinions)
        started = time.monotonic()
        self._last_prompt = (system, user)

        if before_send is not None:
            await before_send()
        response = await self._complete(system, user, schema)
        usage = response.usage
        try:
            judgement = parse_judgement(response.parsed, response.text)
        except SchemaViolationError as violation:
            repair_user = prompts.render_repair(
                violation.raw_text, str(violation), schema, self.language
            )
            if before_send is not None:
                try:
                    await before_send()
                except SendCancelledError as cancelled:
                    # 1回目の修正の前に止められた。提供元には何も送っていない。
                    return self.error_outcome(
                        task,
                        VerdictStatus.SCHEMA_ERROR,
                        f"スキーマ違反の修正を試みる前に止められた: {cancelled}",
                        started,
                        usage=usage,
                    )
            repaired = await self._complete(system, repair_user, schema)
            usage = usage.merge(repaired.usage)
            try:
                judgement = parse_judgement(repaired.parsed, repaired.text)
            except SchemaViolationError as second:
                # 修正は 1 回まで。失敗したらモデルに予算を消費させない。
                return self.error_outcome(
                    task,
                    VerdictStatus.SCHEMA_ERROR,
                    f"スキーマ違反の修正に失敗: {second}",
                    started,
                    usage=usage,
                    attempt=2,
                )
            return self._ok_outcome(task, judgement, usage, started, attempt=2, response=repaired)

        return self._ok_outcome(task, judgement, usage, started, attempt=1, response=response)

    # --- 内部 --- 

    async def _complete(
        self, system: str, user: str, schema: dict[str, object]
    ) -> CompletionResponse:
        capabilities = self.provider.capabilities
        return await self.provider.complete(
            CompletionRequest(
                system=system,
                user=user,
                json_schema=schema,
                structured_mode=capabilities.structured_output,
                max_output_tokens=self.max_output_tokens,
                temperature=REVIEW_TEMPERATURE,
                seed=self.seed if capabilities.supports_seed else None,
                timeout_s=self.timeout_s,
            )
        )

    def _ok_outcome(
        self,
        task: ReviewTask,
        judgement: object,
        usage: Usage,
        started: float,
        *,
        attempt: int,
        response: CompletionResponse,
    ) -> ReviewOutcome:
        checked, warnings = drop_hallucinated_evidence(judgement, task)  # type: ignore[arg-type]
        usage = self._priced(usage)
        # transport が残った警告 (process の場合は別途径) を追加する (§9.7)。
        warnings.extend(response.warnings)
        if response.degraded_to is not None and response.degraded_to != StructuredMode.JSON_SCHEMA:
            warnings.append(
                f"{self.name}: 構造化出力を {response.degraded_to.value} に降格しました"
            )
        verdict = ReviewVerdict(
            **checked.model_dump(),
            candidate_id=task.candidate.id,
            reviewer=self.name,
            model=response.model_reported or self.model,
            attempt=attempt,
            usage=usage,
            latency_ms=int((time.monotonic() - started) * 1000),
            status=VerdictStatus.OK,
        )
        return ReviewOutcome(
            verdict,
            warnings=warnings,
            raw_text=response.text,
            attempts=attempt,
            trace=self._trace(task, response, verdict, attempt),
        )

    def error_outcome(
        self,
        task: ReviewTask,
        status: VerdictStatus,
        message: str,
        started: float | None = None,
        *,
        usage: Usage | None = None,
        attempt: int = 1,
    ) -> ReviewOutcome:
        """判定不能または「黒って消した」. スキーマ違反の場合は Verdict を返す (P9)."""
        verdict = ReviewVerdict(
            candidate_id=task.candidate.id,
            reviewer=self.name,
            model=self.model,
            attempt=attempt,
            usage=self._priced(usage or Usage()),
            latency_ms=int((time.monotonic() - started) * 1000) if started else 0,
            status=status,
            vulnerable=False,
            severity=Severity.NONE,
            confidence=0.0,
            false_positive_probability=0.0,
            reasoning=message,
        )
        return ReviewOutcome(
            verdict,
            warnings=[f"{self.name}: {message}"],
            attempts=attempt,
            trace=self._trace(task, None, verdict, attempt, error=message),
        )

    def _priced(self, usage: Usage) -> Usage:
        """価格情報から使用量を推定する. 不明なら cost unknown (§24.3)."""
        if self.price is None:
            return usage.model_copy(update={"estimated_usd": None, "cost_known": False})
        return usage.model_copy(
            update={"estimated_usd": self.price.estimate(usage), "cost_known": True}
        )

    def _trace(
        self,
        task: ReviewTask,
        response: CompletionResponse | None,
        verdict: ReviewVerdict,
        attempt: int,
        *,
        error: str | None = None,
    ) -> dict[str, Any]:
        """1 回のトレースを作る (§24.2). プロンプトのハッシュのみ."""
        system, user = getattr(self, "_last_prompt", ("", ""))
        prompt: dict[str, Any] = {
            "system_sha256": sha256_text(system),
            "user_sha256": sha256_text(user),
            "input_tokens": verdict.usage.input_tokens,
        }
        if self.save_prompts:
            prompt["system"] = system
            prompt["user"] = user
        # 設定値ではなく実際に送った値を残す. 再現性のため (§24.2)
        capabilities = self.provider.capabilities
        params: dict[str, Any] = {
            "transport": self.provider.transport,
            "dialect": self.provider.dialect,
            "temperature": REVIEW_TEMPERATURE if capabilities.supports_temperature else None,
            "seed": self.seed if capabilities.supports_seed else None,
            "seed_configured": self.seed,
            "max_output_tokens": self.max_output_tokens,
            "structured_mode": self.provider.capabilities.structured_output.value,
            "language": self.language,
        }
        response_trace: dict[str, Any] = {
            "raw": response.text if response is not None else None,
            "finish_reason": response.finish_reason if response is not None else None,
            "error": error,
        }
        if response is not None:
            params.update(response.trace_params)
            response_trace.update(response.trace_response)
        return {
            "candidate_id": task.candidate.id,
            "reviewer": self.name,
            "model": verdict.model,
            "params": params,
            "prompt": prompt,
            "response": response_trace,
            "usage": verdict.usage.model_dump(mode="json"),
            "latency_ms": verdict.latency_ms,
            "attempt": attempt,
            "status": verdict.status.value,
            "degraded_to": response.degraded_to.value
            if response is not None and response.degraded_to is not None
            else None,
        }
