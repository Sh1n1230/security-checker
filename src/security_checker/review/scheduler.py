"""全 LLM 呼び出しの統括 (設計書 §22, §23).

Provider にはレート制御もリトライも持たせない。ここに集約することで、
Provider ごとの挙動のばらつきを防ぎ、コストと予算の監視を一箇所にまとめる。
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from security_checker.config.schema import BudgetConfig, ReviewerConfig
from security_checker.context.budget import estimate_tokens
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import ReviewVerdict, Usage, VerdictStatus
from security_checker.observability import logging as log
from security_checker.observability.quota import QuotaStore, quota_key
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
)
from security_checker.review import prompts
from security_checker.review.prompts import PeerOpinion
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


class TokenLimiter:
    """tpm のスライディングウィンドウ. 送信前に見積もったトークン数を確保する (§22.1).

    1 回で上限を超える依頼は、窓が空になるのを待ってから単独で通す (永久に待たない)。
    """

    def __init__(self, tpm: int) -> None:
        self.tpm = tpm
        self._events: deque[tuple[float, int]] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._events and now - self._events[0][0] >= 60.0:
                    self._events.popleft()
                used = sum(count for _, count in self._events)
                if not self._events or used + tokens <= self.tpm:
                    self._events.append((now, tokens))
                    return
                wait_for = 60.0 - (now - self._events[0][0])
            await asyncio.sleep(max(0.05, wait_for))


@dataclass
class DailyQuota:
    """rpd. 記録はプロセスをまたいで残る (observability/quota.py)."""

    store: QuotaStore
    key: str
    limit: int

    def remaining(self) -> int:
        return self.store.remaining(self.key, self.limit)


@dataclass
class ReviewerRuntime:
    """1 Reviewer 分の実行状態 (並列度・レート・サーキットブレーカ)."""

    reviewer: Reviewer
    semaphore: asyncio.Semaphore
    limiter: RateLimiter | None = None
    consecutive_failures: int = 0
    disabled_reason: str | None = None
    token_limiter: TokenLimiter | None = None
    daily: DailyQuota | None = None

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
    quota_store: QuotaStore | None = None,
) -> ReviewerRuntime:
    """設定から実行状態を作る. rate_limit の宣言をスケジューラが尊重する."""
    concurrency = min(config.concurrency, default_concurrency)
    limits = config.rate_limit
    return ReviewerRuntime(
        reviewer=reviewer,
        semaphore=asyncio.Semaphore(max(1, concurrency)),
        limiter=RateLimiter(limits.rpm) if limits.rpm else None,
        token_limiter=TokenLimiter(limits.tpm) if limits.tpm else None,
        daily=DailyQuota(
            store=quota_store or QuotaStore(),
            key=quota_key(config.name, config.model),
            limit=limits.rpd,
        )
        if limits.rpd
        else None,
    )


def _request_tokens(runtime: ReviewerRuntime, task: ReviewTask) -> int:
    """tpm 用の見積り. 入力は実際のプロンプトから、出力は上限で数える."""
    user = prompts.render_user(task, {})
    return estimate_tokens(user) + 1500 + runtime.reviewer.max_output_tokens


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
        self._opinions: Mapping[str, Sequence[PeerOpinion]] | None = None

    async def run(
        self,
        tasks: list[ReviewTask],
        *,
        opinions: Mapping[str, Sequence[PeerOpinion]] | None = None,
    ) -> ScheduleResult:
        """全候補をレビューする. 予算・デッドライン超過時は部分結果を返す.

        `opinions` (候補 ID → 匿名化した意見) を渡すと、Reviewer は Judge として呼ばれる (§16)。
        """
        self._opinions = opinions
        if not self.runtimes:
            self._result.warnings.append("有効な Reviewer がありません")
            return self._result
        for runtime in self.runtimes:
            if runtime.daily is not None and runtime.daily.remaining() < len(tasks):
                self._result.warnings.append(
                    f"{runtime.name}: 1 日の上限 (rpd {runtime.daily.limit}) の残りが "
                    f"{runtime.daily.remaining()} 回で、候補 {len(tasks)} 件に足りません。"
                    "上限に達した時点でこの Reviewer を止めます"
                )

        await asyncio.gather(
            *(self._review_candidate(runtime, task) for task in tasks for runtime in self.runtimes)
        )
        for runtime in self.runtimes:
            if runtime.daily is not None:
                self._result.warnings.extend(dict.fromkeys(runtime.daily.store.errors))
        return self._result

    # --- 内部 -------------------------------------------------------------

    async def _review_candidate(self, runtime: ReviewerRuntime, task: ReviewTask) -> None:
        if self._stop.is_set() or runtime.disabled_reason is not None:
            return
        if self._deadline_exceeded():
            await self._stop_run("実行時間の上限に達しました")
            return

        outcome = await self._attempt_with_retries(runtime, task)
        verdict = outcome.verdict
        log.event(
            "review.call",
            level="info" if verdict.status is VerdictStatus.OK else "warn",
            reviewer=runtime.name,
            model=verdict.model,
            candidate_id=task.candidate.id,
            judge=self._opinions is not None,
            attempt=verdict.attempt,
            latency_ms=verdict.latency_ms,
            input_tokens=verdict.usage.input_tokens,
            output_tokens=verdict.usage.output_tokens,
            status=verdict.status.value,
        )
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
            if runtime.daily is not None and runtime.daily.remaining() <= 0:
                reason = f"1 日の上限 (rpd {runtime.daily.limit}) に達しました"
                await self._disable(runtime, reason)
                return runtime.reviewer.error_outcome(
                    task, VerdictStatus.SKIPPED, reason, attempt=attempt
                )
            if runtime.limiter is not None:
                await runtime.limiter.acquire()
            if runtime.token_limiter is not None:
                await runtime.token_limiter.acquire(_request_tokens(runtime, task))
            if runtime.daily is not None:
                # 送る前に数える. 失敗した呼び出しも提供元の上限には数えられる
                runtime.daily.store.consume(runtime.daily.key)
            try:
                async with runtime.semaphore:
                    outcome = await runtime.reviewer.review(
                        task,
                        opinions=self._opinions.get(task.candidate.id)
                        if self._opinions is not None
                        else None,
                    )
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
        log.event("reviewer.disabled", level="warn", reviewer=runtime.name, reason=reason)
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
