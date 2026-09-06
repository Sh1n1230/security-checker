"""全 LLM 呼び出しの統括 (設計書 §22, §23).

Provider にはレート制御もリトライも持たせない。ここに集約することで、
Provider ごとの挙動のばらつきを防ぎ、コストと予算の監視を一箇所にまとめる。
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from security_checker.config.schema import BudgetConfig, ReviewerConfig
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import ReviewVerdict, Usage, VerdictStatus
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
)
from security_checker.review.reviewer import Reviewer, ReviewOutcome

MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 60.0
CIRCUIT_BREAKER_FAILURES = 5
DEFAULT_DEADLINE_S = 1800.0


class RateLimiter:
    """rpm のトークンバケット. 送信直前に 1 リクエスト分を確保する."""

    def __init__(self, rpm: int) -> None:
        self.rpm = rpm
        self._events: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._events and now - self._events[0] >= 60.0:
                    self._events.popleft()
                if len(self._events) < self.rpm:
                    self._events.append(now)
                    return
                wait_for = 60.0 - (now - self._events[0])
            await asyncio.sleep(max(0.05, wait_for))


@dataclass
class ReviewerRuntime:
    """1 Reviewer 分の実行状態 (並列度・レート・サーキットブレーカ)."""

    reviewer: Reviewer
    semaphore: asyncio.Semaphore
    limiter: RateLimiter | None = None
    consecutive_failures: int = 0
    disabled_reason: str | None = None

    @property
    def name(self) -> str:
        return self.reviewer.name


@dataclass
class ScheduleResult:
    """スケジューラの成果. 中断しても部分結果を必ず返す (§20.2)."""

    verdicts: dict[str, list[ReviewVerdict]] = field(default_factory=dict)
    traces: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    reviewed_candidate_ids: set[str] = field(default_factory=set)
    disabled_reviewers: dict[str, str] = field(default_factory=dict)
    stopped_reason: str | None = None
    calls: int = 0


def build_runtime(
    reviewer: Reviewer,
    config: ReviewerConfig,
    *,
    default_concurrency: int,
) -> ReviewerRuntime:
    """設定から実行状態を作る. rate_limit の宣言をスケジューラが尊重する."""
    concurrency = min(config.concurrency, default_concurrency)
    limiter = RateLimiter(config.rate_limit.rpm) if config.rate_limit.rpm else None
    return ReviewerRuntime(
        reviewer=reviewer,
        semaphore=asyncio.Semaphore(max(1, concurrency)),
        limiter=limiter,
    )


class ReviewScheduler:
    """候補 × Reviewer の呼び出しを、レート・並列・予算・時間の制約下で捌く."""

    def __init__(
        self,
        runtimes: list[ReviewerRuntime],
        *,
        budget: BudgetConfig,
        deadline_s: float = DEFAULT_DEADLINE_S,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self.runtimes = runtimes
        self.budget = budget
        self.deadline_s = deadline_s
        self._sleep: Callable[[float], Awaitable[None]] = sleep or asyncio.sleep
        self._stop = asyncio.Event()
        self._result = ScheduleResult()
        self._lock = asyncio.Lock()
        self._started = time.monotonic()

    async def run(self, tasks: list[ReviewTask]) -> ScheduleResult:
        """全候補をレビューする. 予算・デッドライン超過時は部分結果を返す."""
        if not self.runtimes:
            self._result.warnings.append("有効な Reviewer がありません")
            return self._result

        await asyncio.gather(
            *(self._review_candidate(runtime, task) for task in tasks for runtime in self.runtimes)
        )
        return self._result

    # --- 内部 -------------------------------------------------------------

    async def _review_candidate(self, runtime: ReviewerRuntime, task: ReviewTask) -> None:
        if self._stop.is_set() or runtime.disabled_reason is not None:
            return
        if self._deadline_exceeded():
            await self._stop_run("実行時間の上限に達しました")
            return

        outcome = await self._attempt_with_retries(runtime, task)
        async with self._lock:
            self._result.verdicts.setdefault(task.candidate.id, []).append(outcome.verdict)
            self._result.reviewed_candidate_ids.add(task.candidate.id)
            self._result.warnings.extend(outcome.warnings)
            if outcome.trace:
                self._result.traces.append(outcome.trace)
            self._result.usage = self._result.usage.merge(outcome.verdict.usage)
            self._result.calls += 1
        await self._check_budget()

    async def _attempt_with_retries(
        self, runtime: ReviewerRuntime, task: ReviewTask
    ) -> ReviewOutcome:
        last_error = "不明なエラー"
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if runtime.limiter is not None:
                await runtime.limiter.acquire()
            try:
                async with runtime.semaphore:
                    outcome = await runtime.reviewer.review(task)
            except ProviderAuthError as exc:
                # 認証失敗は 1 回で当該 Reviewer を無効化する (§23)
                await self._disable(runtime, str(exc))
                return runtime.reviewer.error_outcome(
                    task, VerdictStatus.PROVIDER_ERROR, str(exc), attempt=attempt
                )
            except ProviderError as exc:
                last_error = str(exc)
                if not exc.retryable or attempt == MAX_ATTEMPTS:
                    await self._record_failure(runtime, last_error)
                    return runtime.reviewer.error_outcome(
                        task, VerdictStatus.PROVIDER_ERROR, last_error, attempt=attempt
                    )
                await self._sleep(_backoff_delay(attempt, exc))
                continue

            if outcome.verdict.status is VerdictStatus.OK:
                runtime.consecutive_failures = 0
            else:
                await self._record_failure(runtime, outcome.verdict.reasoning)
            return outcome

        return runtime.reviewer.error_outcome(
            task, VerdictStatus.PROVIDER_ERROR, last_error, attempt=MAX_ATTEMPTS
        )

    async def _record_failure(self, runtime: ReviewerRuntime, message: str) -> None:
        runtime.consecutive_failures += 1
        if runtime.consecutive_failures >= CIRCUIT_BREAKER_FAILURES:
            await self._disable(
                runtime,
                f"{CIRCUIT_BREAKER_FAILURES} 回連続で失敗したため無効化しました: {message}",
            )

    async def _disable(self, runtime: ReviewerRuntime, reason: str) -> None:
        if runtime.disabled_reason is not None:
            return
        runtime.disabled_reason = reason
        async with self._lock:
            self._result.disabled_reviewers[runtime.name] = reason
            self._result.warnings.append(f"{runtime.name}: {reason}")

    async def _check_budget(self) -> None:
        usage = self._result.usage
        if (
            self.budget.max_total_tokens is not None
            and usage.total_tokens > self.budget.max_total_tokens
        ):
            await self._stop_run(
                f"トークン上限 {self.budget.max_total_tokens} を超えました "
                f"(実績 {usage.total_tokens})"
            )
        if (
            self.budget.max_usd is not None
            and usage.estimated_usd is not None
            and usage.estimated_usd > self.budget.max_usd
        ):
            await self._stop_run(
                f"予算 ${self.budget.max_usd} を超えました (概算 ${usage.estimated_usd:.4f})"
            )

    async def _stop_run(self, reason: str) -> None:
        if self.budget.on_exceed == "warn_and_continue" and "予算" in reason:
            async with self._lock:
                self._result.warnings.append(f"{reason} (warn_and_continue のため続行します)")
            return
        if self._stop.is_set():
            return
        self._stop.set()
        async with self._lock:
            self._result.stopped_reason = reason
            self._result.warnings.append(f"{reason}。ここまでの結果を出力します")

    def _deadline_exceeded(self) -> bool:
        return (time.monotonic() - self._started) > self.deadline_s


def _backoff_delay(attempt: int, exc: ProviderError) -> float:
    """指数バックオフ + フルジッター. Retry-After があれば必ず尊重する (§22.2)."""
    if isinstance(exc, ProviderRateLimitError) and exc.retry_after is not None:
        return max(0.0, exc.retry_after)
    ceiling = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2.0 ** (attempt - 1)))
    jitter: float = random.random()  # noqa: S311 - 暗号用途ではない
    return jitter * ceiling
