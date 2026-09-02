"""Run オーケストレータ (設計書 §3).

パイプライン全体を 1 つの Run として扱い、run_id で全出力を紐づける。
P1 では Scanner → Normalizer → Policy → Report までを実装する
(Context Builder / Reviewer / Aggregator は P2 以降)。
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from security_checker import __version__
from security_checker.config.schema import Config
from security_checker.ids import new_run_id
from security_checker.models.candidate import Candidate
from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.report import (
    Coverage,
    Report,
    ReportWarning,
    ScannerRun,
    TargetInfo,
    count_by_severity,
    utcnow,
)
from security_checker.policy.engine import PolicyDecision, evaluate
from security_checker.policy.score import compute_score
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

    target = Target(root=root)
    ctx = ScanContext(raw_dir=raw_dir, exclude=list(config.target.exclude))

    if scanners is None:
        scanners, warnings_text = build_scanners(config)
    else:
        warnings_text = []
    warnings: list[ReportWarning] = [
        ReportWarning(level="warn", source="config", message=message) for message in warnings_text
    ]

    semaphore = asyncio.Semaphore(config.concurrency.scanners)
    results = list(
        await asyncio.gather(*(_run_one(scanner, target, ctx, semaphore) for scanner in scanners))
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
        for parse_warning in result.parse_warnings:
            warnings.append(
                ReportWarning(level="warn", source=result.scanner, message=parse_warning)
            )

    candidates = dedupe_and_sort(results)
    score = compute_score(candidates, runs)
    coverage = Coverage(
        scanners_total=len(runs),
        scanners_ok=sum(1 for run in runs if run.status is ScanStatus.OK),
        scanners_skipped=sum(1 for run in runs if run.status is ScanStatus.SKIPPED),
        scanners_failed=sum(1 for run in runs if run.status is ScanStatus.FAILED),
        candidates_total=len(candidates),
        candidates_reviewed=0,
    )

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
