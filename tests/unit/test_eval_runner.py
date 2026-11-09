"""Unit tests for eval/runner.py covering edge cases such as schedule.stopped_reason."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_checker.config.schema import Config
from security_checker.eval.dataset import CaseCandidate, Dataset, EvalCase, GroundTruth
from security_checker.eval.runner import run_eval
from security_checker.models.enums import Category, Severity
from security_checker.review.scheduler import ScheduleResult
from security_checker.run import ReviewPass, ReviewerSetup


@pytest.mark.asyncio
async def test_run_eval_appends_stopped_reason_to_warnings(tmp_path):
    """When the review schedule stops early, the reason is added to warnings (covers the branch)."""
    dataset = Dataset(
        name="tiny",
        cases=[
            EvalCase(
                id="c1",
                code="print(1)",
                candidate=CaseCandidate(
                    scanner="fake",
                    rule_id="r",
                    category=Category.SAST,
                    message="m",
                    path="a.py",
                    start_line=1,
                    severity_reported=Severity.LOW,
                ),
                ground_truth=GroundTruth(vulnerable=False),
            )
        ],
    )
    config = Config()

    fake_setup = ReviewerSetup(configs={}, runtimes=[], providers=[], warnings=[])
    stopped = ScheduleResult(stopped_reason="budget exceeded")
    fake_pass = ReviewPass(findings=[], schedule=stopped, warnings=["prior warning"])

    with (
        patch("security_checker.eval.runner.build_reviewers", return_value=fake_setup),
        patch(
            "security_checker.eval.runner.review_and_aggregate",
            new_callable=AsyncMock,
            return_value=fake_pass,
        ),
        patch("security_checker.eval.runner.close_providers", new_callable=AsyncMock),
        patch(
            "security_checker.eval.runner._prepare",
            return_value=MagicMock(tasks=[], candidates=[], by_id={}),
        ),
    ):
        result = await run_eval(dataset, config, reviewer_setup=fake_setup)

    assert "budget exceeded" in result.warnings
    assert "prior warning" in result.warnings
    assert result.cases == 1
    assert result.outcomes == []
