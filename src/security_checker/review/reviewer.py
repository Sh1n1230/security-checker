"""Reviewer = Provider + プロンプト + ポリシー (設計書 §11, §10.2).

Reviewer は 1 候補について 1 つの ReviewVerdict を返す。
他の Reviewer の存在・出力を一切知らない (P6: 独立性)。
"""

from __future__ import annotations

import time
from typing import Any

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
    ) -> None:
        self.name = name
        self.provider = provider
        self.weight = weight
        self.max_output_tokens = max_output_tokens
        self.timeout_s = timeout_s
        self.seed = seed
        self.price = price
        self.save_prompts = save_prompts

    @property
    def model(self) -> str:
        return getattr(self.provider, "model", "unknown")

    async def review(self, task: ReviewTask) -> ReviewOutcome:
        """1 候補をレビューする. スキーマ違反は 1 回だけ修復を試みる (§10.2)."""
        schema = verdict_schema()
        system = prompts.render_system()
        user = prompts.render_user(task, schema)
        started = time.monotonic()
        self._last_prompt = (system, user)

        response = await self._complete(system, user, schema)
        usage = response.usage
        try:
            judgement = parse_judgement(response.parsed, response.text)
        except SchemaViolationError as violation:
            repair_user = prompts.render_repair(violation.raw_text, str(violation), schema)
            repaired = await self._complete(system, repair_user, schema)
            usage = usage.merge(repaired.usage)
            try:
                judgement = parse_judgement(repaired.parsed, repaired.text)
            except SchemaViolationError as second:
                # 修復は 1 回まで。失敗し続けるモデルに予算を吸わせない。
                return self.error_outcome(
                    task,
                    VerdictStatus.SCHEMA_ERROR,
                    f"スキーマ検証に失敗しました: {second}",
                    started,
                    usage=usage,
                    attempt=2,
                )
            return self._ok_outcome(task, judgement, usage, started, attempt=2, response=repaired)

        return self._ok_outcome(task, judgement, usage, started, attempt=1, response=response)

    # --- 内部 -------------------------------------------------------------

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
                temperature=0.0,
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
        # transport 固有の警告 (process の書込検知など) を落とさずに持ち上げる (§9.7)。
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
        """判定不能も「黙って消さない」. レポートに残る Verdict として返す (P9)."""
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
        """価格表があればコストを載せる. 無ければ cost unknown (§24.3)."""
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
        """1 呼び出し分の監査証跡 (§24.2). 既定はプロンプトのハッシュのみ."""
        system, user = getattr(self, "_last_prompt", ("", ""))
        prompt: dict[str, Any] = {
            "system_sha256": sha256_text(system),
            "user_sha256": sha256_text(user),
            "input_tokens": verdict.usage.input_tokens,
        }
        if self.save_prompts:
            prompt["system"] = system
            prompt["user"] = user
        params: dict[str, Any] = {
            "transport": self.provider.transport,
            "dialect": self.provider.dialect,
            "temperature": 0.0,
            "seed": self.seed,
            "max_output_tokens": self.max_output_tokens,
            "structured_mode": self.provider.capabilities.structured_output.value,
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
