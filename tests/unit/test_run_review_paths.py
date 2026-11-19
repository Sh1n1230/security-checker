"""run_review の分岐: diff モードの絞り込み・信用しない検査対象・save_prompts (#571〜#573).

実 LLM は呼ばない。スキャナと Provider はフェイクに差し替える。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from security_checker.config.schema import Config
from security_checker.github.pr import DiffScope
from security_checker.policy.suppress import SuppressionRules
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup, RunOutcome, run_review
from security_checker.testing import FakeScanner, ScriptedProvider, verdict_payload
from tests.factories import make_candidate

if TYPE_CHECKING:
    from pathlib import Path

    from security_checker.models.candidate import Candidate


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("\n" * 41 + "run(cmd, shell=True)\n", encoding="utf-8")
    (root / "src" / "old.py").write_text("\n" * 41 + "run(cmd, shell=True)\n", encoding="utf-8")
    return root


async def review(
    tmp_path: Path,
    candidates: list[Candidate],
    *,
    diff: DiffScope | None = None,
    suppression: SuppressionRules | None = None,
    save_prompts: bool = False,
) -> tuple[RunOutcome, ScriptedProvider]:
    config = Config.model_validate(
        {
            "output": {"dir": str(tmp_path / "out"), "save_prompts": save_prompts},
            "reviewers": [
                {
                    "name": "alpha",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://x/v1",
                    "model": "m",
                }
            ],
            "policy": {"strict": False},
        }
    )
    provider = ScriptedProvider([verdict_payload()] * len(candidates))
    setup = ReviewerSetup(
        runtimes=[
            build_runtime(Reviewer("alpha", provider), config.reviewers[0], default_concurrency=1)
        ],
        providers=[provider],
        configs={"alpha": config.reviewers[0]},
    )
    outcome = await run_review(
        config,
        workspace(tmp_path),
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=candidates)],
        reviewer_setup=setup,
        diff=diff,
        suppression=suppression,
    )
    return outcome, provider


async def test_diff_mode_reviews_only_candidates_on_changed_lines(tmp_path):
    """変更行に重ならない候補は送らず outside_diff に分ける (#571)."""
    changed = make_candidate("changed", path="src/app.py", line=42)
    untouched = make_candidate("untouched", path="src/old.py", line=42)
    diff = DiffScope(
        base="origin/main",
        added={"src/app.py": ((40, 45),)},
        changed_files=frozenset({"src/app.py"}),
    )
    outcome, provider = await review(tmp_path, [changed, untouched], diff=diff)

    assert len(provider.requests) == 1
    assert [f.candidate.id for f in outcome.report.findings] == ["changed"]
    assert [c.id for c in outcome.report.outside_diff] == ["untouched"]
    target = outcome.report.target
    assert target.mode == "diff"
    assert target.base == "origin/main"
    assert target.changed_files == 1


async def test_untrusted_target_warns_about_ignore_files_scanners_still_read(tmp_path):
    """信用しない検査対象でも gitleaks は .gitleaksignore を読む. その事実を警告に残す (#572)."""
    root = tmp_path / "app"
    root.mkdir()
    (root / ".gitleaksignore").write_text("x\n", encoding="utf-8")
    outcome, _ = await review(
        tmp_path, [make_candidate()], suppression=SuppressionRules(untrusted_target=True)
    )
    untrusted = [w for w in outcome.report.warnings if w.source == "untrusted-target"]
    assert untrusted
    assert ".gitleaksignore" in untrusted[0].message


async def test_save_prompts_warns_where_the_prompts_are_written(tmp_path):
    """プロンプト全文の保存は、置き場所と .gitignore の確認を促す警告を出す (#573)."""
    outcome, _ = await review(tmp_path, [make_candidate()], save_prompts=True)
    saved = [w for w in outcome.report.warnings if "save_prompts" in w.message]
    assert len(saved) == 1
    assert saved[0].source == "output"
    assert str(outcome.output_dir) in saved[0].message
