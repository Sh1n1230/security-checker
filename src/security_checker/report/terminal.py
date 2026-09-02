"""ターミナル出力 (設計書 §18.2).

「ツールが失敗した」ことを最初に、はっきり出す。0 件と検査不能を見分けられない出力にしない。
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.report import Report
from security_checker.policy.engine import PolicyDecision

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.NONE: "dim",
}
STATUS_MARK = {
    ScanStatus.OK: ("✓", "green"),
    ScanStatus.SKIPPED: ("-", "yellow"),
    ScanStatus.FAILED: ("✗", "bold red"),
}
MAX_ROWS = 50
WARNING_CHARS = 160


def _one_line(message: str, limit: int = WARNING_CHARS) -> str:
    """警告は 1 行に畳む. スキャナは数十行のエラーを吐くことがあり、画面を潰すため."""
    collapsed = " ".join(message.split())
    return collapsed if len(collapsed) <= limit else collapsed[:limit] + " …(全文は report.json)"


def _header(report: Report) -> Text:
    text = Text()
    text.append(f"security-checker v{report.tool_version}", style="bold")
    text.append(f"   run {report.run_id}", style="dim")
    text.append(f"   target: {report.target.root} ({report.target.mode} mode)")
    return text


def _scanner_line(report: Report) -> Text:
    text = Text()
    for index, run in enumerate(report.scanners):
        if index:
            text.append("  ")
        mark, style = STATUS_MARK[run.status]
        text.append(f"{run.scanner} ", style="bold")
        text.append(mark, style=style)
        if run.status is ScanStatus.OK:
            text.append(f" {run.candidate_count}")
        elif run.status is ScanStatus.SKIPPED:
            text.append(" skipped", style="yellow")
        else:
            suffix = f" (exit {run.exit_code})" if run.exit_code is not None else ""
            text.append(f" failed{suffix}", style="bold red")
    if not report.scanners:
        text.append("(有効なスキャナがありません)", style="yellow")
    return text


def _candidate_table(report: Report) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("severity", width=9)
    table.add_column("scanner", width=9)
    table.add_column("rule")
    table.add_column("location", overflow="fold")
    for candidate in report.candidates[:MAX_ROWS]:
        severity = candidate.severity_reported or Severity.INFO
        table.add_row(
            Text(severity.value.upper(), style=SEVERITY_STYLE[severity]),
            candidate.scanner,
            candidate.title,
            candidate.where,
        )
    return table


def render(
    report: Report,
    decision: PolicyDecision,
    output_dir: Path,
    console: Console | None = None,
) -> None:
    """レポートを描画する (既定は標準出力)."""
    console = console or Console()
    console.print()
    console.print(_header(report))
    console.print()

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", width=11)
    grid.add_column()
    grid.add_row("Scanners", _scanner_line(report))
    grid.add_row("Candidates", f"{report.coverage.candidates_total} 件 (未レビュー: LLM 未実行)")
    console.print(grid)

    errors = [w for w in report.warnings if w.level == "error"]
    notices = [w for w in report.warnings if w.level == "warn"]
    for warning in errors:
        console.print(Text(f"  ⚠ {warning.source}: {_one_line(warning.message)}", style="bold red"))
    for warning in notices[:5]:
        console.print(Text(f"  · {warning.source}: {_one_line(warning.message)}", style="yellow"))
    if len(notices) > 5:
        console.print(Text(f"  · ほか {len(notices) - 5} 件の警告 (report.json 参照)", style="dim"))

    if report.candidates:
        console.print()
        console.print(
            Panel(
                _candidate_table(report),
                title="CANDIDATES (スキャナの報告 / LLM 判定前)",
                title_align="left",
                border_style="blue",
            )
        )
        if len(report.candidates) > MAX_ROWS:
            console.print(
                Text(
                    f"  … ほか {len(report.candidates) - MAX_ROWS} 件は report.json 参照",
                    style="dim",
                )
            )
    else:
        console.print()
        console.print(Text("  検出なし", style="green"))

    counts = report.severity_counts
    summary = Text("  ")
    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        summary.append(
            f"{severity.value} {counts.get(severity.value, 0)}   ", style=SEVERITY_STYLE[severity]
        )
    console.print()
    console.print(summary)

    score_text = Text(f"  score {report.score.value}/100  rank {report.score.rank}")
    if report.score.partial:
        score_text.append(f"  (partial: {report.score.partial_reason})", style="yellow")
    console.print(score_text)
    console.print(Text(f"  詳細: {output_dir / 'report.json'}", style="dim"))

    for reason in decision.reasons:
        console.print(Text(f"  ✗ {reason}", style="bold red"))
    console.print()
