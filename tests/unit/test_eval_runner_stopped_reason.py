"""Unit tests for run_eval covering the stopped_reason warning path.

Addresses #500: ensure schedule.stopped_reason is appended to warnings.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from security_checker.config.schema import Config
from security_checker.eval.dataset import CaseCandidate, Dataset, EvalCase, GroundTruth
from security_checker.eval.runner import run_eval
from security_checker.models.enums import Category, Severity
from security_checker.review.scheduler import ScheduleResult
from security_checker.run import ReviewerSetup, ReviewPass


def _minimal_config() -> Config:
    return Config.model_validate(
        {
            "scanners": {"semgrep": {"enabled": False}},
            "reviewers": [
                {
                    "name": "r1",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://stub",
                    "model": "stub",
                }
            ],
        }
    )


def _minimal_dataset() -> Dataset:
    case = EvalCase(
        id="c1",
        candidate=CaseCandidate(
            scanner="semgrep",
            rule_id="rules.test",
            category=Category.SAST,
            path="a.py",
            start_line=1,
            severity_reported=Severity.HIGH,
            cwe=["CWE-1"],
        ),
        code="print(1)",
        ground_truth=GroundTruth(vulnerable=True, severity=Severity.HIGH, cwe=["CWE-1"]),
    )
    return Dataset(name="t", cases=[case])


@pytest.mark.asyncio
async def test_run_eval_appends_stopped_reason_to_warnings(tmp_path: Path) -> None:
    """When the scheduler stops early, stopped_reason must appear in warnings (#500)."""
    dataset = _minimal_dataset()
    config = _minimal_config()
    setup = ReviewerSetup(runtimes=[], providers=[], configs={})

    schedule = ScheduleResult(
        stopped_reason="予算上限に達したため中断しました",
        warnings=["existing schedule warning"],
    )
    review_pass = ReviewPass(findings=[], schedule=schedule, warnings=["review pass warning"])

    with patch(
        "security_checker.eval.runner.review_and_aggregate",
        new=AsyncMock(return_value=review_pass),
    ) as mock_agg:
        result = await run_eval(dataset, config, reviewer_setup=setup, workspace=tmp_path)

    mock_agg.assert_awaited_once()
    assert "予算上限に達したため中断しました" in result.warnings
    assert "existing schedule warning" in result.warnings
    assert "review pass warning" in result.warnings
    assert result.cases == 1
    assert result.outcomes == []
