"""Run オーケストレータ (設計書 §3).

パイプライン全体を 1 つの Run として扱い、run_id で全出力を紐づける。
`run_scan` は Scanner → Normalizer → Policy → Report、
`run_review` はそこに Context Builder → Reviewer → Aggregator を挟む。
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from security_checker import __version__
from security_checker.aggregate.findings import build_findings
from security_checker.aggregate.registry import build_aggregator
from security_checker.config.schema import Config, ReviewerConfig
from security_checker.context.builder import ContextBuilder
from security_checker.context.facts import collect_repo_facts
from security_checker.errors import ConfigError
from security_checker.ids import new_run_id
from security_checker.models.candidate import Candidate
from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.report import (
    Coverage,
    Report,
    ReportWarning,
    ReviewerRun,
    ScannerRun,
    TargetInfo,
    count_by_severity,
    count_by_status,
    utcnow,
)
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import Usage, VerdictStatus
from security_checker.observability.cost import PriceTable
from security_checker.observability.trace import TraceWriter
from security_checker.policy.engine import PolicyDecision, evaluate
from security_checker.policy.score import compute_score
from security_checker.providers.base import LLMProvider
from security_checker.providers.registry import build_provider
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import (
    ReviewerRuntime,
    ReviewScheduler,
    ScheduleResult,
    build_runtime,
)
from security_checker.scanners.base import ScanContext, Scanner, ScanResult, Target
from security_checker.scanners.registry import build_scanners


@dataclass
class RunOutcome:
    """1 回の実行の成果物一式."""

    report: Report
    decision: PolicyDecision
    output_dir: Path
    results: list[ScanResult] = field(default_factory=list)


def resolve_output_dir(config: Config, base: Path) -> Path:
    """出力先を決める. 相対指定は呼び出し元のカレントディレクトリ基準."""
    configured = Path(config.output.dir).expanduser()
    return configured if configured.is_absolute() else (base / configured)


def _coverage(runs: list[ScannerRun], candidates: list[Candidate], *, reviewed: int) -> Coverage:
    return Coverage(
        scanners_total=len(runs),
        scanners_ok=sum(1 for run in runs if run.status is ScanStatus.OK),
        scanners_skipped=sum(1 for run in runs if run.status is ScanStatus.SKIPPED),
        scanners_failed=sum(1 for run in runs if run.status is ScanStatus.FAILED),
        candidates_total=len(candidates),
        candidates_reviewed=reviewed,
    )


def _sort_key(candidate: Candidate) -> tuple[int, str, str, int]:
    severity = candidate.severity_reported or Severity.INFO
    location = candidate.location
    return (
        -severity.order,
        candidate.scanner,
        location.path if location else "",
        location.start_line if location else 0,
    )


def dedupe_and_sort(results: list[ScanResult]) -> list[Candidate]:
    """スキャナ横断で重複 ID を落とし、重大度順に並べる."""
    seen: set[str] = set()
    merged: list[Candidate] = []
    for result in results:
        for candidate in result.candidates:
            if candidate.id in seen:
                continue
            seen.add(candidate.id)
            merged.append(candidate)
    return sorted(merged, key=_sort_key)


async def _run_one(
    scanner: Scanner,
    target: Target,
    ctx: ScanContext,
    semaphore: asyncio.Semaphore,
) -> ScanResult:
    async with semaphore:
        try:
            return await scanner.scan(target, ctx)
        except Exception as exc:  # 1 つの失敗で全体を落とさない (§20.2)
            return ScanResult(
                scanner=scanner.name,
                category=scanner.category,
                status=ScanStatus.FAILED,
                reason=f"内部エラー: {exc}",
            )


async def _execute_scanners(
    config: Config,
    root: Path,
    raw_dir: Path,
    scanners: Sequence[Scanner] | None,
) -> tuple[list[ScanResult], list[ScannerRun], list[ReportWarning]]:
    """スキャナを並列実行し、結果・サマリ・警告に整形する."""
    warnings: list[ReportWarning] = []
    if scanners is None:
        resolved, warnings_text = build_scanners(config)
    else:
        resolved, warnings_text = list(scanners), []
    warnings.extend(
        ReportWarning(level="warn", source="config", message=message) for message in warnings_text
    )

    target = Target(root=root)
    ctx = ScanContext(raw_dir=raw_dir, exclude=list(config.target.exclude))
    semaphore = asyncio.Semaphore(config.concurrency.scanners)
    results = list(
        await asyncio.gather(*(_run_one(scanner, target, ctx, semaphore) for scanner in resolved))
    )

    runs: list[ScannerRun] = []
    for result in results:
        runs.append(
            ScannerRun(
                scanner=result.scanner,
                category=result.category,
                status=result.status,
                candidate_count=len(result.candidates),
                duration_ms=result.duration_ms,
                exit_code=result.exit_code,
                version=result.version,
                reason=result.reason,
                stderr_excerpt=result.stderr_excerpt,
                raw_path=str(result.raw_path) if result.raw_path else None,
                parse_warnings=result.parse_warnings,
            )
        )
        if result.status is ScanStatus.FAILED:
            warnings.append(
                ReportWarning(
                    level="error",
                    source=result.scanner,
                    message=result.reason or f"{result.scanner} が失敗しました",
                )
            )
        elif result.status is ScanStatus.SKIPPED:
            warnings.append(
                ReportWarning(
                    level="warn",
                    source=result.scanner,
                    message=result.reason or f"{result.scanner} をスキップしました",
                )
            )
        warnings.extend(
            ReportWarning(level="warn", source=result.scanner, message=parse_warning)
            for parse_warning in result.parse_warnings
        )
    return results, runs, warnings


async def run_scan(
    config: Config,
    root: Path,
    *,
    base_dir: Path | None = None,
    run_id: str | None = None,
    scanners: Sequence[Scanner] | None = None,
) -> RunOutcome:
    """スキャンを実行してレポートとポリシー判定を返す (LLM は使わない).

    `scanners` を渡すと registry の解決を飛ばす (テストと将来の埋め込み用途)。
    """
    started_at = utcnow()
    identifier = run_id or new_run_id()
    output_dir = resolve_output_dir(config, base_dir or Path.cwd())
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    results, runs, warnings = await _execute_scanners(config, root, raw_dir, scanners)
    candidates = dedupe_and_sort(results)
    score = compute_score(candidates, runs)
    coverage = _coverage(runs, candidates, reviewed=0)

    report = Report(
        tool_version=__version__,
        run_id=identifier,
        started_at=started_at,
        finished_at=utcnow(),
        target=TargetInfo(root=str(root), mode="full"),
        scanners=runs,
        candidates=candidates,
        findings=[],
        coverage=coverage,
        score=score,
        warnings=warnings,
        severity_counts=count_by_severity(candidates),
    )
    decision = evaluate(report, config.policy)
    return RunOutcome(report=report, decision=decision, output_dir=output_dir, results=results)


@dataclass
class ReviewerSetup:
    """設定から組み立てた Reviewer 一式."""

    runtimes: list[ReviewerRuntime] = field(default_factory=list)
    providers: list[LLMProvider] = field(default_factory=list)
    configs: dict[str, ReviewerConfig] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def build_reviewers(
    config: Config,
    *,
    price_table: PriceTable | None = None,
    environ: dict[str, str] | None = None,
) -> ReviewerSetup:
    """設定の reviewers から Provider と Reviewer を作る (§9, §22)."""
    setup = ReviewerSetup()
    table = price_table or PriceTable()
    for reviewer_config in config.reviewers:
        provider = build_provider(reviewer_config, environ=environ, warnings=setup.warnings)
        reviewer = Reviewer(
            reviewer_config.name,
            provider,
            weight=reviewer_config.weight,
            max_output_tokens=reviewer_config.max_output_tokens,
            timeout_s=float(reviewer_config.timeout_s),
            seed=reviewer_config.seed,
            # process transport はトークンを実測できないため、価格表があっても
            # 金額を出さない。推測した数字を出すより cost: unknown が正しい (§9.7)。
            price=None
            if reviewer_config.transport == "process"
            else table.lookup(reviewer_config.model or ""),
            save_prompts=config.output.save_prompts,
        )
        setup.runtimes.append(
            build_runtime(
                reviewer,
                reviewer_config,
                default_concurrency=config.concurrency.reviews_per_provider,
            )
        )
        setup.providers.append(provider)
        setup.configs[reviewer_config.name] = reviewer_config
    return setup


def build_tasks(
    candidates: list[Candidate],
    root: Path,
    config: Config,
) -> tuple[list[ReviewTask], list[Candidate]]:
    """候補を ReviewTask にする. budget.max_candidates を超えた分は未レビューとして返す."""
    limit = config.budget.max_candidates
    selected = candidates[:limit]
    overflow = candidates[limit:]
    builder = ContextBuilder(root, config.context, collect_repo_facts(root))
    return [builder.build(candidate) for candidate in selected], overflow


async def run_review(
    config: Config,
    root: Path,
    *,
    base_dir: Path | None = None,
    run_id: str | None = None,
    scanners: Sequence[Scanner] | None = None,
    reviewer_setup: ReviewerSetup | None = None,
    price_table: PriceTable | None = None,
    environ: dict[str, str] | None = None,
) -> RunOutcome:
    """スキャン → 文脈構築 → LLM レビュー → 集約 → ポリシー判定."""
    started_at = utcnow()
    identifier = run_id or new_run_id()
    output_dir = resolve_output_dir(config, base_dir or Path.cwd())
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if not config.reviewers and reviewer_setup is None:
        raise ConfigError(
            "reviewers が設定されていません。security-checker.yml に reviewer を定義するか、"
            "LLM を使わない `security-checker scan` を実行してください"
        )

    results, runs, warnings = await _execute_scanners(config, root, raw_dir, scanners)
    candidates = dedupe_and_sort(results)

    aggregator, aggregator_warnings = build_aggregator(config.aggregation.strategy)
    warnings.extend(
        ReportWarning(level="warn", source="aggregate", message=message)
        for message in aggregator_warnings
    )

    setup = reviewer_setup or build_reviewers(config, price_table=price_table, environ=environ)
    warnings.extend(
        ReportWarning(level="warn", source="reviewer", message=message)
        for message in setup.warnings
    )
    tasks, overflow = build_tasks(candidates, root, config)
    if overflow:
        warnings.append(
            ReportWarning(
                level="warn",
                source="budget",
                message=(
                    f"候補 {len(candidates)} 件のうち {len(overflow)} 件は "
                    f"budget.max_candidates ({config.budget.max_candidates}) を超えたため"
                    "未レビューです"
                ),
            )
        )

    trace = TraceWriter(output_dir, identifier, enabled=True)
    if config.output.save_prompts:
        warnings.append(
            ReportWarning(
                level="warn",
                source="output",
                message=(
                    "save_prompts が有効です。プロンプト全文が "
                    f"{output_dir} に保存されます。.gitignore への追加を確認してください"
                ),
            )
        )

    scheduler = ReviewScheduler(setup.runtimes, budget=config.budget)
    schedule = await scheduler.run(tasks)

    warnings.extend(
        ReportWarning(level="warn", source="review", message=message)
        for message in schedule.warnings
    )
    if schedule.stopped_reason:
        warnings.append(
            ReportWarning(level="warn", source="budget", message=schedule.stopped_reason)
        )

    findings = build_findings(
        candidates,
        schedule.verdicts,
        aggregator=aggregator,
        aggregation=config.aggregation,
        policy=config.policy,
    )

    trace.write_run(
        {
            "run_id": identifier,
            "started_at": started_at,
            "target": str(root),
            "config": config.masked_dump(),
            "scanners": [run.model_dump(mode="json") for run in runs],
            "reviewers": sorted(setup.configs),
            "candidates": len(candidates),
            "reviewed": len(schedule.reviewed_candidate_ids),
        }
    )
    for call_trace in schedule.traces:
        trace.write_call(call_trace)

    for provider in setup.providers:
        await provider.aclose()

    score = compute_score(candidates, runs, findings)
    coverage = _coverage(runs, candidates, reviewed=len(schedule.reviewed_candidate_ids))
    report = Report(
        tool_version=__version__,
        run_id=identifier,
        started_at=started_at,
        finished_at=utcnow(),
        target=TargetInfo(root=str(root), mode="full"),
        scanners=runs,
        reviewers=_reviewer_runs(setup, schedule),
        candidates=candidates,
        findings=findings,
        coverage=coverage,
        score=score,
        warnings=warnings,
        severity_counts=count_by_severity(candidates),
        finding_counts=count_by_status(findings),
        usage=schedule.usage,
        stopped_reason=schedule.stopped_reason,
        trace_dir=str(trace.root),
    )
    decision = evaluate(report, config.policy)
    return RunOutcome(report=report, decision=decision, output_dir=output_dir, results=results)


def _reviewer_runs(setup: ReviewerSetup, schedule: ScheduleResult) -> list[ReviewerRun]:
    """Reviewer 単位のサマリ. 無効化された事実もレポートに残す."""
    summaries: list[ReviewerRun] = []
    for runtime in setup.runtimes:
        name = runtime.name
        verdicts = [
            verdict
            for verdict_list in schedule.verdicts.values()
            for verdict in verdict_list
            if verdict.reviewer == name
        ]
        usage = Usage()
        for verdict in verdicts:
            usage = usage.merge(verdict.usage)
        provider = runtime.reviewer.provider
        summaries.append(
            ReviewerRun(
                name=name,
                model=getattr(provider, "model", None),
                transport=provider.transport,
                dialect=provider.dialect,
                calls=len(verdicts),
                verdicts_ok=sum(1 for v in verdicts if v.status is VerdictStatus.OK),
                verdicts_error=sum(1 for v in verdicts if v.status is not VerdictStatus.OK),
                usage=usage,
                disabled_reason=schedule.disabled_reviewers.get(name),
            )
        )
    return summaries
