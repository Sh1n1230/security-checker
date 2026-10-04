"""Judge 戦略 (設計書 §16).

- 割れた候補だけが Judge に回る (コスト)
- Judge には名前を伏せた意見と元のコードが渡る (匿名化・原文脈)
- Judge が失敗したら fallback の結果が残り、そのことが detail に残る
- 確信の無い「脆弱ではない」で候補を消さない (見逃しを増やさない)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_checker.aggregate.judge import anonymize, apply_judgement, needs_judge
from security_checker.config.schema import AggregationConfig, Config, PolicyConfig, ReviewerConfig
from security_checker.errors import ConfigError
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, FindingStatus, Severity
from security_checker.models.finding import Finding
from security_checker.providers.errors import ProviderBadRequestError
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup, RunOutcome, run_review
from security_checker.testing import FakeScanner, ScriptedProvider, verdict_payload
from tests.factories import make_candidate, make_finding, make_verdict


def candidate(cid: str = "c1", line: int = 3) -> Candidate:
    return Candidate(
        id=cid,
        scanner="semgrep",
        category=Category.SAST,
        rule_id="rules.sql-injection",
        title="sql-injection",
        message="文字列連結でクエリを組み立てています",
        location=Location(path="db.py", start_line=line, end_line=line),
        severity_reported=Severity.HIGH,
    )


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "db.py").write_text(
        "def find(cur, name):\n    q = 'x'\n    return cur.execute('select ' + name)\n"
        "def other(cur, n):\n    return cur.execute('select ' + str(int(n)))\n",
        encoding="utf-8",
    )
    return root


def config(tmp_path: Path, **judge: Any) -> Config:
    reviewers = [
        {
            "name": name,
            "transport": "http",
            "dialect": "openai_chat",
            "base_url": "http://x/v1",
            "model": f"model-{name}",
        }
        for name in ("alpha", "beta", "judge")
    ]
    return Config.model_validate(
        {
            "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
            "output": {"dir": str(tmp_path / "out")},
            "reviewers": reviewers,
            "aggregation": {"strategy": "judge", "judge": {"reviewer": "judge", **judge}},
            "policy": {"strict": False},
        }
    )


def setup(scripts: dict[str, list[Any]]) -> tuple[ReviewerSetup, dict[str, ScriptedProvider]]:
    providers = {
        name: ScriptedProvider(script, model=f"model-{name}") for name, script in scripts.items()
    }
    runtimes = [
        build_runtime(
            Reviewer(name, provider),
            ReviewerConfig(
                name=name,
                transport="http",
                dialect="openai_chat",
                base_url="http://x/v1",
                model=f"model-{name}",
            ),
            default_concurrency=1,
        )
        for name, provider in providers.items()
    ]
    return (
        ReviewerSetup(
            runtimes=runtimes,
            providers=list(providers.values()),
            configs={
                name: ReviewerConfig(
                    name=name,
                    transport="http",
                    dialect="openai_chat",
                    base_url="http://x/v1",
                    model="m",
                )
                for name in providers
            },
        ),
        providers,
    )


async def run(
    tmp_path: Path, scripts: dict[str, list[Any]], candidates: list[Candidate], **judge: Any
) -> tuple[RunOutcome, dict[str, ScriptedProvider]]:
    reviewer_setup, providers = setup(scripts)
    outcome = await run_review(
        config(tmp_path, **judge),
        workspace(tmp_path),
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=candidates)],
        reviewer_setup=reviewer_setup,
    )
    return outcome, providers


async def test_only_split_candidates_go_to_the_judge(tmp_path):
    outcome, providers = await run(
        tmp_path,
        {
            # c1: 割れる / c2: 一致して confirmed
            "alpha": [
                verdict_payload(vulnerable=True, confidence=0.9),
                verdict_payload(vulnerable=True, confidence=0.95),
            ],
            "beta": [
                verdict_payload(
                    vulnerable=False,
                    severity="none",
                    confidence=0.7,
                    reasoning="int にキャスト済み",
                ),
                verdict_payload(vulnerable=True, confidence=0.9),
            ],
            "judge": [
                verdict_payload(
                    vulnerable=True,
                    severity="critical",
                    confidence=0.9,
                    reasoning="Accepted Reviewer A: name は未検証",
                )
            ],
        },
        [candidate("c1", 3), candidate("c2", 5)],
    )
    findings = {f.candidate.id: f for f in outcome.report.findings}
    assert len(providers["judge"].requests) == 1
    judged = findings["c1"]
    assert judged.status is FindingStatus.CONFIRMED
    assert judged.severity is Severity.CRITICAL
    assert judged.aggregation is not None and judged.aggregation.strategy == "judge"
    assert judged.aggregation.detail["fallback_status"] == "review_required"
    assert judged.aggregation.detail["judge"]["rationale"].startswith("Accepted")
    # Judge 自身の判定は Finding の verdicts (独立した Reviewer の意見) に混ぜない
    assert {v.reviewer for v in judged.verdicts} == {"alpha", "beta"}
    assert findings["c2"].status is FindingStatus.CONFIRMED
    assert findings["c2"].aggregation is not None
    assert findings["c2"].aggregation.strategy == "consensus"
    # Judge の呼び出しも Reviewer ごとの集計に残る
    by_name = {r.name: r for r in outcome.report.reviewers}
    assert by_name["judge"].calls == 1


async def test_judge_receives_anonymized_shuffled_opinions_and_the_code(tmp_path):
    _, providers = await run(
        tmp_path,
        {
            "alpha": [verdict_payload(vulnerable=True, reasoning="alpha の論点")],
            "beta": [verdict_payload(vulnerable=False, severity="none", reasoning="beta の論点")],
            "judge": [verdict_payload(vulnerable=True)],
        },
        [candidate()],
    )
    request = providers["judge"].requests[0]
    assert "alpha の論点" in request.user and "beta の論点" in request.user
    # 名前もモデル名も渡さない
    for leaked in ("alpha", "beta", "model-alpha", "model-beta"):
        assert f"### {leaked}" not in request.user
        assert leaked not in request.user.replace("alpha の論点", "").replace("beta の論点", "")
    assert "### Reviewer A" in request.user and "### Reviewer B" in request.user
    assert "<<<UNTRUSTED_CODE>>>" in request.user  # 元の文脈も渡す
    assert "final judge" in request.system
    # 一次レビューの Reviewer は Judge のプロンプトを受け取らない
    assert "final judge" not in providers["alpha"].requests[0].system


async def test_judge_failure_falls_back_and_says_so(tmp_path):
    outcome, _ = await run(
        tmp_path,
        {
            "alpha": [verdict_payload(vulnerable=True)],
            "beta": [verdict_payload(vulnerable=False, severity="none")],
            "judge": [ProviderBadRequestError("down")],
        },
        [candidate()],
    )
    finding = outcome.report.findings[0]
    assert finding.status is FindingStatus.REVIEW_REQUIRED
    assert finding.aggregation is not None
    assert finding.aggregation.detail["judge"] is None
    assert finding.aggregation.detail["fallback_used"]


async def test_judge_can_review_every_candidate(tmp_path):
    _, providers = await run(
        tmp_path,
        {
            "alpha": [verdict_payload(vulnerable=True)],
            "beta": [verdict_payload(vulnerable=True)],
            "judge": [verdict_payload(vulnerable=True)],
        },
        [candidate()],
        only_on_disagreement=False,
    )
    assert len(providers["judge"].requests) == 1


async def test_judge_alone_is_a_config_error(tmp_path):
    reviewer_setup, _ = setup({"judge": []})
    with pytest.raises(ConfigError, match="Judge 以外"):
        await run_review(
            Config.model_validate(
                {
                    "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
                    "output": {"dir": str(tmp_path / "out")},
                    "reviewers": [
                        {
                            "name": "judge",
                            "transport": "http",
                            "dialect": "openai_chat",
                            "base_url": "http://x/v1",
                            "model": "m",
                        }
                    ],
                    "aggregation": {"strategy": "judge", "judge": {"reviewer": "judge"}},
                }
            ),
            workspace(tmp_path),
            base_dir=tmp_path,
            scanners=[FakeScanner("semgrep", candidates=[candidate()])],
            reviewer_setup=reviewer_setup,
        )


# --- 単体: 判定の写像 ------------------------------------------------------------------


def split_finding() -> Finding:
    c = make_candidate()
    return make_finding(
        c,
        FindingStatus.REVIEW_REQUIRED,
        verdicts=[make_verdict("alpha"), make_verdict("beta", vulnerable=False)],
    )


@pytest.mark.parametrize(
    ("judge", "status"),
    [
        ({"vulnerable": True, "confidence": 0.9}, FindingStatus.CONFIRMED),
        ({"vulnerable": True, "confidence": 0.6}, FindingStatus.LIKELY),
        ({"vulnerable": True, "confidence": 0.3}, FindingStatus.REVIEW_REQUIRED),
        ({"vulnerable": False, "confidence": 0.9}, FindingStatus.FALSE_POSITIVE),
        # 確信の無い「脆弱ではない」では消さない
        ({"vulnerable": False, "confidence": 0.6}, FindingStatus.REVIEW_REQUIRED),
        (
            {"vulnerable": False, "confidence": 0.95, "needs_more_context": ["caller"]},
            FindingStatus.REVIEW_REQUIRED,
        ),
    ],
)
def test_apply_judgement(judge, status):
    verdict = make_verdict("judge", **judge)
    result = apply_judgement(split_finding(), verdict, policy=PolicyConfig())
    assert result.status is status


def test_needs_judge_ignores_findings_without_opinions():
    c = make_candidate()
    cfg = AggregationConfig(strategy="judge")
    assert needs_judge(split_finding(), cfg)
    assert not needs_judge(make_finding(c, FindingStatus.ERROR, verdicts=[]), cfg)
    assert not needs_judge(make_finding(c, FindingStatus.CONFIRMED), cfg)


def test_anonymize_is_deterministic_per_candidate():
    verdicts = [make_verdict(name, reasoning=name) for name in ("a", "b", "c", "d")]
    first = anonymize("cand-1", verdicts)
    assert [o.reasoning for o in first] == [o.reasoning for o in anonymize("cand-1", verdicts)]
    assert [o.label for o in first] == ["Reviewer A", "Reviewer B", "Reviewer C", "Reviewer D"]
