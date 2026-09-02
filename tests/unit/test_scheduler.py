"""スケジューラのリトライ・サーキットブレーカ・予算 (設計書 §22, §23)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

import pytest

from security_checker.config.schema import BudgetConfig, RateLimit, ReviewerConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category
from security_checker.models.task import CodeContext, RepoFacts, ReviewTask, TokenBudget
from security_checker.models.verdict import Usage, VerdictStatus
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderRateLimitError,
    ProviderServerError,
)
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import (
    RateLimiter,
    ReviewScheduler,
    build_runtime,
)
from security_checker.testing import ScriptedProvider, verdict_payload


def make_task(index: int = 0) -> ReviewTask:
    candidate = Candidate(
        id=f"c{index}",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="r",
        title="t",
        message="m",
    )
    return ReviewTask(
        candidate=candidate,
        code_context=CodeContext(),
        repo_facts=RepoFacts(),
        budget=TokenBudget(max_tokens_per_task=8000),
    )


def make_scheduler(
    script: Sequence[Any],
    *,
    budget: BudgetConfig | None = None,
    rpm: int | None = None,
) -> tuple[ReviewScheduler, Any, ScriptedProvider, list[float]]:
    provider = ScriptedProvider(script)
    reviewer = Reviewer("r1", provider)
    config = ReviewerConfig(
        name="r1",
        transport="http",
        dialect="openai_chat",
        base_url="http://x/v1",
        model="m",
        rate_limit=RateLimit(rpm=rpm),
    )
    runtime = build_runtime(reviewer, config, default_concurrency=4)
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    scheduler = ReviewScheduler([runtime], budget=budget or BudgetConfig(), sleep=fake_sleep)
    return scheduler, runtime, provider, slept


async def test_successful_run_collects_verdicts():
    scheduler, _, provider, _ = make_scheduler([verdict_payload(), verdict_payload()])
    result = await scheduler.run([make_task(0), make_task(1)])

    assert set(result.verdicts) == {"c0", "c1"}
    assert result.calls == 2
    assert result.usage.total_tokens == 300
    assert len(provider.requests) == 2


async def test_retries_transient_errors():
    scheduler, _, provider, slept = make_scheduler([ProviderServerError("500"), verdict_payload()])
    result = await scheduler.run([make_task()])

    assert result.verdicts["c0"][0].status is VerdictStatus.OK
    assert len(provider.requests) == 2
    assert len(slept) == 1  # バックオフが 1 回


async def test_gives_up_after_max_attempts():
    scheduler, _, provider, _ = make_scheduler([ProviderServerError("500")] * 3)
    result = await scheduler.run([make_task()])

    verdict = result.verdicts["c0"][0]
    assert verdict.status is VerdictStatus.PROVIDER_ERROR
    assert len(provider.requests) == 3  # 初回 + 2 リトライ


async def test_rate_limit_error_respects_retry_after():
    scheduler, _, _, slept = make_scheduler(
        [ProviderRateLimitError("429", retry_after=7.5), verdict_payload()]
    )
    await scheduler.run([make_task()])
    assert slept == [7.5]


async def test_auth_error_disables_reviewer_immediately():
    """認証失敗はリトライせず、その Reviewer を run 全体で無効化する (§23)."""
    scheduler, runtime, provider, _ = make_scheduler(
        [ProviderAuthError("401"), verdict_payload(), verdict_payload()]
    )
    result = await scheduler.run([make_task(0), make_task(1), make_task(2)])

    assert runtime.disabled_reason is not None
    assert "r1" in result.disabled_reviewers
    assert len(provider.requests) == 1  # 以降は呼ばない


async def test_circuit_breaker_after_consecutive_failures():
    scheduler, runtime, _, _ = make_scheduler([ProviderServerError("500")] * 30)
    await scheduler.run([make_task(index) for index in range(10)])

    assert runtime.disabled_reason is not None
    assert "連続で失敗" in runtime.disabled_reason


async def test_schema_error_counts_as_failure_but_is_reported():
    scheduler, _, _, _ = make_scheduler(["壊れた応答", "また壊れた応答"])
    result = await scheduler.run([make_task()])

    verdict = result.verdicts["c0"][0]
    assert verdict.status is VerdictStatus.SCHEMA_ERROR
    assert result.calls == 1  # 判定不能でもレポートには残る


async def test_token_budget_stops_run_and_keeps_partial_results():
    budget = BudgetConfig(max_total_tokens=200, max_usd=None)
    scheduler, _, provider, _ = make_scheduler([verdict_payload()] * 5, budget=budget)
    result = await scheduler.run([make_task(index) for index in range(5)])

    assert result.stopped_reason is not None
    assert "トークン上限" in result.stopped_reason
    assert result.verdicts  # 部分結果は捨てない
    assert len(provider.requests) < 5


async def test_no_reviewers_is_reported():
    scheduler = ReviewScheduler([], budget=BudgetConfig())
    result = await scheduler.run([make_task()])
    assert result.verdicts == {}
    assert any("Reviewer" in warning for warning in result.warnings)


async def test_rate_limiter_allows_burst_up_to_rpm():
    limiter = RateLimiter(rpm=3)
    await asyncio.wait_for(asyncio.gather(*(limiter.acquire() for _ in range(3))), timeout=1.0)


async def test_rate_limiter_blocks_beyond_rpm():
    limiter = RateLimiter(rpm=1)
    await limiter.acquire()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(limiter.acquire(), timeout=0.2)


async def test_usage_is_priced_as_unknown_without_table():
    scheduler, _, _, _ = make_scheduler([verdict_payload()])
    result = await scheduler.run([make_task()])
    assert result.usage.cost_known is False
    assert result.usage == Usage(
        input_tokens=100, output_tokens=50, estimated_usd=None, cost_known=False
    )
