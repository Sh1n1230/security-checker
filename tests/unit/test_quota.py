"""rate_limit.rpd / tpm (設計書 §22.1)."""

from __future__ import annotations

import asyncio
import json
from datetime import date
from pathlib import Path
from typing import Any

from security_checker.config.schema import BudgetConfig, RateLimit, ReviewerConfig
from security_checker.models.verdict import VerdictStatus
from security_checker.observability.quota import QuotaStore, quota_key
from security_checker.providers.check import probe_task
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import (
    ReviewerRuntime,
    ReviewScheduler,
    TokenLimiter,
    build_runtime,
)
from security_checker.testing import ScriptedProvider, verdict_payload


def store(tmp_path: Path, day: date = date(2026, 10, 4)) -> QuotaStore:
    return QuotaStore(tmp_path / "quota.json", today=lambda: day)


def test_store_counts_per_day_and_key(tmp_path):
    first = store(tmp_path)
    assert first.consume("a:m") == 1
    assert first.consume("a:m") == 2
    assert first.consume("b:m") == 1
    # 別プロセス相当: 同じファイルを読み直しても数えた分が残る
    assert store(tmp_path).used("a:m") == 2
    # 日付が変われば数え直し
    tomorrow = store(tmp_path, date(2026, 10, 5))
    assert tomorrow.used("a:m") == 0
    assert tomorrow.remaining("a:m", 5) == 5


def test_store_keeps_only_recent_days(tmp_path):
    for day in range(1, 12):
        store(tmp_path, date(2026, 10, day)).consume("k")
    assert len(json.loads((tmp_path / "quota.json").read_text(encoding="utf-8"))) == 7


def test_store_survives_a_broken_file(tmp_path):
    (tmp_path / "quota.json").write_text("{broken", encoding="utf-8")
    broken = store(tmp_path)
    assert broken.used("k") == 0
    assert broken.errors


def test_quota_key_separates_reviewers():
    assert quota_key("a", "m") != quota_key("b", "m")


def runtime(
    tmp_path: Path, rpd: int, script: list[Any]
) -> tuple[ReviewerRuntime, ScriptedProvider]:
    config = ReviewerConfig(
        name="free",
        transport="http",
        dialect="openai_chat",
        base_url="http://x/v1",
        model="m",
        rate_limit=RateLimit(rpd=rpd),
    )
    provider = ScriptedProvider(script)
    return build_runtime(
        Reviewer("free", provider), config, default_concurrency=1, quota_store=store(tmp_path)
    ), provider


async def test_scheduler_stops_a_reviewer_at_its_daily_limit(tmp_path):
    rt, provider = runtime(tmp_path, rpd=2, script=[verdict_payload()] * 3)
    tasks = [
        probe_task().model_copy(
            update={"candidate": probe_task().candidate.model_copy(update={"id": f"c{i}"})}
        )
        for i in range(3)
    ]
    result = await ReviewScheduler([rt], budget=BudgetConfig()).run(tasks)
    assert len(provider.requests) == 2
    statuses = sorted(v[0].status.value for v in result.verdicts.values())
    assert statuses.count(VerdictStatus.SKIPPED.value) == 1
    assert "rpd 2" in result.disabled_reviewers["free"]
    # 開始時点で足りないことを警告する
    assert any("足りません" in w for w in result.warnings)
    assert store(tmp_path).used(quota_key("free", "m")) == 2


async def test_scheduler_refuses_when_the_quota_is_already_used_up(tmp_path):
    rt, provider = runtime(tmp_path, rpd=1, script=[verdict_payload()])
    store(tmp_path).consume(quota_key("free", "m"))
    result = await ReviewScheduler([rt], budget=BudgetConfig()).run([probe_task()])
    assert provider.requests == []
    assert "free" in result.disabled_reviewers


async def test_token_limiter_waits_for_the_window(monkeypatch):
    clock = {"now": 0.0}
    monkeypatch.setattr("security_checker.review.scheduler.time.monotonic", lambda: clock["now"])
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr("security_checker.review.scheduler.asyncio.sleep", fake_sleep)
    limiter = TokenLimiter(tpm=1000)
    await limiter.acquire(600)
    await limiter.acquire(600)  # 窓が空くまで待つ
    assert slept and round(sum(slept)) == 60
    # 1 回で上限を超える依頼も、窓が空いていれば通す (永久に待たない)
    await asyncio.wait_for(TokenLimiter(tpm=10).acquire(500), timeout=1)
