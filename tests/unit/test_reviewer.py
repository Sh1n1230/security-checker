"""Reviewer の Verdict 生成と修復リトライ (設計書 §10.2, §24)."""

from __future__ import annotations

import json

from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, Severity
from security_checker.models.task import CodeContext, CodeSlice, RepoFacts, ReviewTask, TokenBudget
from security_checker.models.verdict import VerdictStatus
from security_checker.observability.cost import ModelPrice
from security_checker.review.reviewer import Reviewer
from security_checker.testing import ScriptedProvider, verdict_payload


def make_task(category: Category = Category.SAST) -> ReviewTask:
    candidate = Candidate(
        id="c1",
        scanner="semgrep",
        category=category,
        rule_id="rules.x",
        title="t",
        message="ユーザー入力がシェルに渡る",
        location=Location(path="src/app.py", start_line=10, end_line=10),
        severity_reported=Severity.HIGH,
        cwe=["CWE-78"],
    )
    return ReviewTask(
        candidate=candidate,
        code_context=CodeContext(
            primary=CodeSlice(
                path="src/app.py", start_line=5, end_line=15, text="\n".join("x" for _ in range(11))
            )
        ),
        repo_facts=RepoFacts(languages=["Python"], frameworks=["flask"]),
        budget=TokenBudget(max_tokens_per_task=8000),
    )


async def test_successful_review_produces_verdict():
    provider = ScriptedProvider([verdict_payload()])
    reviewer = Reviewer("r1", provider)

    outcome = await reviewer.review(make_task())

    assert outcome.verdict.status is VerdictStatus.OK
    assert outcome.verdict.vulnerable is True
    assert outcome.verdict.severity is Severity.HIGH
    assert outcome.verdict.candidate_id == "c1"
    assert outcome.verdict.reviewer == "r1"
    assert outcome.verdict.usage.input_tokens == 100


async def test_prompt_contains_untrusted_delimiters_and_schema():
    provider = ScriptedProvider([verdict_payload()])
    await Reviewer("r1", provider).review(make_task())

    request = provider.requests[0]
    assert "<<<UNTRUSTED_CODE>>>" in request.user
    assert "UNTRUSTED DATA" in request.system
    assert "src/app.py" in request.user
    assert request.json_schema is not None
    assert request.temperature == 0.0


async def test_repair_retry_recovers_from_broken_json():
    """壊れた応答は 1 回だけ修復を試みる (§10.2)."""
    provider = ScriptedProvider(["これは JSON ではありません", json.dumps(verdict_payload())])
    outcome = await Reviewer("r1", provider).review(make_task())

    assert outcome.verdict.status is VerdictStatus.OK
    assert outcome.verdict.attempt == 2
    assert len(provider.requests) == 2
    assert "不正でした" in provider.requests[1].user


async def test_repair_is_attempted_only_once():
    provider = ScriptedProvider(["壊れています", "まだ壊れています"])
    outcome = await Reviewer("r1", provider).review(make_task())

    assert outcome.verdict.status is VerdictStatus.SCHEMA_ERROR
    assert len(provider.requests) == 2  # 3 回目は呼ばない
    assert outcome.warnings


async def test_usage_is_summed_across_repair():
    provider = ScriptedProvider(["壊れています", json.dumps(verdict_payload())])
    outcome = await Reviewer("r1", provider).review(make_task())
    assert outcome.verdict.usage.input_tokens == 200


async def test_cost_is_unknown_without_price_table():
    provider = ScriptedProvider([verdict_payload()])
    outcome = await Reviewer("r1", provider).review(make_task())
    assert outcome.verdict.usage.cost_known is False
    assert outcome.verdict.usage.estimated_usd is None


async def test_cost_is_computed_with_price():
    provider = ScriptedProvider([verdict_payload()])
    reviewer = Reviewer("r1", provider, price=ModelPrice(input_per_1m=10.0, output_per_1m=30.0))
    outcome = await reviewer.review(make_task())

    assert outcome.verdict.usage.cost_known is True
    assert outcome.verdict.usage.estimated_usd == (100 * 10.0 + 50 * 30.0) / 1_000_000


async def test_trace_records_hashes_not_prompts_by_default():
    """既定ではプロンプト全文を保存しない (§24.2)."""
    provider = ScriptedProvider([verdict_payload()])
    outcome = await Reviewer("r1", provider).review(make_task())

    prompt = outcome.trace["prompt"]
    assert "system_sha256" in prompt
    assert "system" not in prompt
    assert outcome.trace["status"] == "ok"


async def test_trace_can_include_prompts():
    provider = ScriptedProvider([verdict_payload()])
    reviewer = Reviewer("r1", provider, save_prompts=True)
    outcome = await reviewer.review(make_task())
    assert (
        "<<<UNTRUSTED_CODE>>>"
        in outcome.trace["prompt"]["system"] + outcome.trace["prompt"]["user"]
    )


async def test_out_of_range_evidence_is_dropped():
    payload = verdict_payload(
        evidence=[{"path": "src/app.py", "start_line": 999, "end_line": 999, "note": "範囲外"}]
    )
    outcome = await Reviewer("r1", ScriptedProvider([payload])).review(make_task())

    assert outcome.verdict.evidence == []
    assert any("範囲外" in warning for warning in outcome.warnings)


async def test_error_outcome_is_recorded_not_swallowed():
    reviewer = Reviewer("r1", ScriptedProvider([]))
    outcome = reviewer.error_outcome(make_task(), VerdictStatus.PROVIDER_ERROR, "401 unauthorized")

    assert outcome.verdict.status is VerdictStatus.PROVIDER_ERROR
    assert outcome.verdict.vulnerable is False
    assert "401" in outcome.verdict.reasoning
