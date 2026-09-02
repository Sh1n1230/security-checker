"""CLI (設計書 §12, §17.1).

P1 で提供するのは `scan` (LLM を使わないスキャン) と `config` のみ。
`review` は P2 で追加する。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console

from security_checker import __version__
from security_checker.config.loader import LoadedConfig, available_presets, load_config
from security_checker.context.redact import redact_known_patterns
from security_checker.errors import ConfigError, ExitCode, SecurityCheckerError
from security_checker.models.enums import Severity
from security_checker.report.json_writer import write_json
from security_checker.report.terminal import render
from security_checker.run import run_scan

app = typer.Typer(
    name="security-checker",
    help="拡張可能な AI Security Review プラットフォーム",
    no_args_is_help=True,
    add_completion=False,
)
config_app = typer.Typer(help="設定の確認", no_args_is_help=True)
app.add_typer(config_app, name="config")

err_console = Console(stderr=True)


def _fail(message: str, code: ExitCode) -> NoReturn:
    err_console.print(f"[bold red]エラー:[/bold red] {redact_known_patterns(message)}")
    raise typer.Exit(code=int(code))


def _load(
    root: Path,
    config_path: Path | None,
    preset: str | None,
    overrides: dict[str, Any],
) -> LoadedConfig:
    try:
        return load_config(root, config_path=config_path, preset=preset, cli_overrides=overrides)
    except ConfigError as exc:
        _fail(str(exc), ExitCode.CONFIG_ERROR)


def _cli_overrides(
    *,
    fail_on: Severity | None,
    min_score: int | None,
    strict: bool | None,
    exclude: list[str] | None,
    output_dir: Path | None,
    formats: list[str] | None,
    semgrep_config: str | None,
) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    if fail_on is not None:
        policy["fail_on"] = fail_on.value
    if min_score is not None:
        policy["min_score"] = min_score
    if strict is not None:
        policy["strict"] = strict

    overrides: dict[str, Any] = {}
    if policy:
        overrides["policy"] = policy
    if exclude:
        overrides["target"] = {"exclude": exclude}
    output: dict[str, Any] = {}
    if output_dir is not None:
        output["dir"] = str(output_dir)
    if formats:
        output["formats"] = formats
    if output:
        overrides["output"] = output
    if semgrep_config is not None:
        overrides["scanners"] = {"semgrep": {"config": semgrep_config}}
    return overrides


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="検査対象ディレクトリ")] = Path("."),
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (既定は自動探索)")
    ] = None,
    preset: Annotated[
        str | None,
        typer.Option("--preset", "-p", help=f"プリセット: {', '.join(available_presets())}"),
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="この重大度以上の検出で exit 1")
    ] = None,
    min_score: Annotated[
        int | None, typer.Option("--min-score", min=0, max=100, help="スコア下限 (下回れば exit 1)")
    ] = None,
    strict: Annotated[
        bool | None,
        typer.Option("--strict/--no-strict", help="スキャナの失敗を exit 3 にする (既定: 有効)"),
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="除外パターン (複数指定可)")
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="レポート出力先 (既定: .security-checker/)"),
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="ターミナル出力を抑制する")] = False,
) -> None:
    """スキャナのみで検査する (LLM を使わない)."""
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"検査対象が見つかりません: {path}", ExitCode.CONFIG_ERROR)

    overrides = _cli_overrides(
        fail_on=fail_on,
        min_score=min_score,
        strict=strict,
        exclude=exclude,
        output_dir=output_dir,
        formats=None,
        semgrep_config=None,
    )
    loaded = _load(root, config_path, preset, overrides)

    try:
        outcome = asyncio.run(run_scan(loaded.config, root))
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    if "json" in loaded.config.output.formats:
        write_json(outcome.report, outcome.output_dir)
    if not quiet and "terminal" in loaded.config.output.formats:
        render(outcome.report, outcome.decision, outcome.output_dir)

    raise typer.Exit(code=int(outcome.decision.exit_code))


@config_app.command("show")
def config_show(
    path: Annotated[Path, typer.Argument(help="対象ディレクトリ")] = Path("."),
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    preset: Annotated[str | None, typer.Option("--preset", "-p")] = None,
    explain: Annotated[
        bool, typer.Option("--explain", help="どの層で値が決まったかを表示する")
    ] = False,
) -> None:
    """解決された最終設定を出力する (秘匿値は保持しない設計のため常に安全)."""
    root = path.expanduser().resolve()
    loaded = _load(root, config_path, preset, {})
    console = Console()

    if explain:
        console.print(f"[bold]preset[/bold]: {loaded.preset or '(なし)'}")
        console.print(f"[bold]config file[/bold]: {loaded.config_path or '(なし)'}")
        for key in sorted(loaded.origins):
            console.print(f"  {key} [dim]← {loaded.origins[key]}[/dim]")
        return

    print(json.dumps(loaded.config.masked_dump(), ensure_ascii=False, indent=2))


@app.command()
def version() -> None:
    """バージョンを表示する."""
    print(f"security-checker {__version__}")


def main() -> None:
    """コンソールスクリプトのエントリポイント."""
    try:
        app()
    except SecurityCheckerError as exc:  # pragma: no cover - 最後の砦
        err_console.print(f"[bold red]エラー:[/bold red] {redact_known_patterns(str(exc))}")
        sys.exit(int(exc.exit_code))


if __name__ == "__main__":  # pragma: no cover
    main()
