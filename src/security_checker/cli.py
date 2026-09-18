"""CLI (設計書 §12, §17.1, §9.8).

`scan` は LLM を使わないスキャン、`review` は LLM Reviewer を使ったレビュー、
`init` は環境を検出しての設定生成、`config` は解決済み設定の確認。
"""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
import yaml
from rich.console import Console
from rich.panel import Panel

from security_checker import __version__
from security_checker.config.loader import (
    CONFIG_FILENAMES,
    LOCAL_CONFIG_FILENAMES,
    LoadedConfig,
    available_presets,
    load_config,
)
from security_checker.context.budget import estimate_tokens
from security_checker.context.redact import redact_known_patterns
from security_checker.errors import ConfigError, ExitCode, SecurityCheckerError
from security_checker.eval.dataset import load_dataset
from security_checker.eval.runner import run_eval, to_markdown
from security_checker.models.enums import Severity
from security_checker.observability.cost import load_price_table
from security_checker.providers.detect import Detection, detect_all
from security_checker.report.json_writer import write_json
from security_checker.report.markdown import write_markdown
from security_checker.report.terminal import render
from security_checker.review import prompts
from security_checker.review.structured import verdict_schema
from security_checker.run import RunOutcome, build_tasks, run_review, run_scan

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


def _write_reports(loaded: LoadedConfig, outcome: RunOutcome, *, quiet: bool) -> None:
    """設定された形式で書き出す. terminal 以外はファイルとして残す (§18.1)."""
    formats = loaded.config.output.formats
    if "json" in formats:
        write_json(outcome.report, outcome.output_dir)
    if "markdown" in formats:
        write_markdown(outcome.report, outcome.decision, outcome.output_dir)
    if not quiet and "terminal" in formats:
        render(outcome.report, outcome.decision, outcome.output_dir)


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
        outcome = asyncio.run(run_scan(loaded.config, root, extra_warnings=loaded.warnings))
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    _write_reports(loaded, outcome, quiet=quiet)
    raise typer.Exit(code=int(outcome.decision.exit_code))


@app.command()
def review(
    path: Annotated[Path, typer.Argument(help="検査対象ディレクトリ")] = Path("."),
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (既定は自動探索)")
    ] = None,
    preset: Annotated[
        str | None,
        typer.Option("--preset", "-p", help=f"プリセット: {', '.join(available_presets())}"),
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="この重大度以上の判定で exit 1")
    ] = None,
    strict: Annotated[
        bool | None,
        typer.Option("--strict/--no-strict", help="スキャナ/Reviewer の失敗を exit 3 にする"),
    ] = None,
    max_candidates: Annotated[
        int | None, typer.Option("--max-candidates", min=1, help="レビューする候補の上限")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="除外パターン (複数指定可)")
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="レポート出力先 (既定: .security-checker/)"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="LLM に送信せず、送信予定の内容を表示する"),
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="ターミナル出力を抑制する")] = False,
) -> None:
    """スキャン結果を LLM Reviewer でレビューする."""
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"検査対象が見つかりません: {path}", ExitCode.CONFIG_ERROR)

    overrides = _cli_overrides(
        fail_on=fail_on,
        min_score=None,
        strict=strict,
        exclude=exclude,
        output_dir=output_dir,
        formats=None,
        semgrep_config=None,
    )
    if max_candidates is not None:
        overrides["budget"] = {"max_candidates": max_candidates}
    loaded = _load(root, config_path, preset, overrides)

    if dry_run:
        _dry_run(loaded, root)
        raise typer.Exit(code=int(ExitCode.OK))

    price_table = load_price_table(
        loaded.config_path.parent if loaded.config_path is not None else None
    )
    try:
        outcome = asyncio.run(
            run_review(loaded.config, root, price_table=price_table, extra_warnings=loaded.warnings)
        )
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    _write_reports(loaded, outcome, quiet=quiet)
    raise typer.Exit(code=int(outcome.decision.exit_code))


def _dry_run(loaded: LoadedConfig, root: Path) -> None:
    """何が送信されるかを、送信前に全部見せる (設計書 §19.3)."""
    console = Console()
    outcome = asyncio.run(run_scan(loaded.config, root, extra_warnings=loaded.warnings))
    tasks, overflow = build_tasks(outcome.report.candidates, root, loaded.config)

    console.print(
        f"[bold]dry-run[/bold]: 候補 {len(outcome.report.candidates)} 件中 "
        f"{len(tasks)} 件を送信予定 (超過 {len(overflow)} 件は未レビュー)"
    )
    console.print(
        f"[bold]reviewers[/bold]: "
        f"{', '.join(r.name for r in loaded.config.reviewers) or '(未設定)'}"
    )
    schema = verdict_schema()
    total = 0
    for task in tasks:
        user = prompts.render_user(task, schema)
        total += estimate_tokens(user)
        console.print(
            Panel(
                user,
                title=f"{task.candidate.id}  {task.candidate.where}",
                title_align="left",
                border_style="blue",
            )
        )
    console.print(
        f"[bold]推定入力トークン[/bold]: 約 {total:,} "
        f"(× Reviewer {len(loaded.config.reviewers)} 個)"
    )
    console.print("[dim]system プロンプトは全タスク共通です[/dim]")


INIT_HEADER = """\
# security-checker の設定 (設計書 §12)
# すべての項目に既定値があるため、必要なものだけを書けば動きます。
#
# reviewers に既定値はありません。特定のベンダーを標準として押し付けないためです (§9.8)。
# 以下は `security-checker init` が **この環境で実際に使えるもの** を検出して生成しました。
#
# transport: process は、そのコマンド側の既存ログインをそのまま使います (API キー不要)。
# 起動は毎回作り直す空の一時ディレクトリで行い、書き込みがあれば検知して警告しますが、
# コマンド自体の書き込み能力を無効化できているかは本体からは検証できません。
# 非対話・ツール無効 (または読み取り専用) のフラグを command に含めてください (§9.7)。
"""


def _reviewer_block(name: str, command: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "transport": "process",
        "command": command,
        "prompt_via": "stdin",
        "timeout_s": 300,
        "concurrency": 1,
    }


def _print_detections(console: Console, detections: list[Detection]) -> list[Detection]:
    """検出結果を表示する. 推奨マークは付けず、検出順のまま並べる (§9.8)."""
    console.print("環境を検出しています…\n")
    usable: list[Detection] = []
    for transport, title in (
        ("process", "process transport で使えるコマンド"),
        ("http", "http transport で使える資格情報"),
    ):
        rows = [item for item in detections if item.transport == transport]
        console.print(f"  [bold]{title}[/bold]")
        if not rows:
            console.print("    [dim](プリセットがありません)[/dim]")
        for item in rows:
            mark = "[green]✓[/green]" if item.available else "[dim]✗[/dim]"
            console.print(f"    {mark} {item.name:<28} [dim]({item.detail})[/dim]")
            if item.available:
                usable.append(item)
        console.print()
    return usable


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="設定ファイルを置くディレクトリ")] = Path("."),
    command: Annotated[
        str | None,
        typer.Option(
            "--command",
            help="process transport の Reviewer にするコマンド (例: 'mycmd --non-interactive')",
        ),
    ] = None,
    name: Annotated[
        str | None, typer.Option("--name", help="--command で作る Reviewer の名前")
    ] = None,
    local: Annotated[
        bool,
        typer.Option(
            "--local",
            help="security-checker.local.yml に書く (git 管理しない個人用の上書き層)",
        ),
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="既存の設定ファイルを上書きする")] = False,
    stdout: Annotated[
        bool, typer.Option("--stdout", help="ファイルに書かず標準出力に表示する")
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="検出されたものをすべて採用する")
    ] = False,
) -> None:
    """環境を検出して設定ファイルを生成する (設計書 §9.8)."""
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"ディレクトリが見つかりません: {path}", ExitCode.CONFIG_ERROR)
    console = Console()

    usable = _print_detections(console, detect_all())
    blocks: list[dict[str, Any]] = []

    if usable and command is not None and not yes:
        # --command は「これを使う」という明示なので、検出分を対話で尋ねない。
        # 尋ねると、CI やスクリプトから呼んだときに標準入力が無くて失敗する。
        console.print(
            "[dim]--command が指定されているため、検出されたものは採用しません。"
            "検出分も使うなら --yes を付けるか、--command なしで実行してください[/dim]\n"
        )
        usable = []
    elif usable and not yes:
        for index, item in enumerate(usable, start=1):
            console.print(f"    [bold]{index}[/bold]. {item.name} ({item.transport})")
        answer = typer.prompt(
            "Reviewer にするものを番号で (カンマ区切り・空欄で全部・'-' で選ばない)",
            default="",
            show_default=False,
        ).strip()
        usable = _select(usable, answer, console)
    blocks.extend(dict(item.config) for item in usable)

    if command is not None:
        argv = shlex.split(command)
        if not argv:
            _fail("--command が空です", ExitCode.CONFIG_ERROR)
        blocks.append(_reviewer_block(name or Path(argv[0]).name, argv))

    if not blocks:
        console.print(
            "[yellow]Reviewer は生成しませんでした。[/yellow]\n"
            "プリセットが 1 つも無くても、コマンドを直接指定すれば使えます:\n"
            "  [bold]security-checker init --command "
            "'<your-command> --non-interactive --no-tools'[/bold]\n"
            "LLM を使わない検査は [bold]security-checker scan[/bold] で今すぐ実行できます。"
        )
        raise typer.Exit(code=int(ExitCode.OK))

    document = INIT_HEADER + yaml.safe_dump(
        {"version": 1, "reviewers": blocks},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    if stdout:
        print(document)
        raise typer.Exit(code=int(ExitCode.OK))

    destination = root / (LOCAL_CONFIG_FILENAMES[0] if local else CONFIG_FILENAMES[0])
    if destination.exists() and not force:
        _fail(
            f"{destination} は既に存在します。--force で上書きするか、--stdout で内容だけ"
            "表示できます"
            + (
                ""
                if local
                else "。共有設定を残したまま手元用の Reviewer を足すなら --local を使ってください"
            ),
            ExitCode.CONFIG_ERROR,
        )
    destination.write_text(document, encoding="utf-8")
    console.print(f"[green]書き出しました[/green]: {destination}")
    if local:
        console.print(
            "[dim]このファイルは共有設定に後勝ちで重なります。"
            ".gitignore 済みなのでコミットされません[/dim]"
        )
    console.print("次: [bold]security-checker review --dry-run[/bold] で送信内容を確認できます")


def _select(usable: list[Detection], answer: str, console: Console) -> list[Detection]:
    """番号の入力を選択に変換する. 解釈できない入力は黙って無視せず知らせる."""
    if answer == "-":
        return []
    if not answer:
        return usable
    chosen: list[Detection] = []
    for token in answer.split(","):
        cleaned = token.strip()
        if not cleaned.isdigit() or not 1 <= int(cleaned) <= len(usable):
            console.print(f"[yellow]無視しました[/yellow]: '{cleaned}' は番号ではありません")
            continue
        chosen.append(usable[int(cleaned) - 1])
    return chosen


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

    # 受け付けたが効かない設定は、config show でも必ず見えるようにする (P9)。
    # 既定の出力は JSON なので、警告は標準エラーに出して混ぜない。
    warn_console = Console(stderr=True)
    for message in loaded.warnings:
        warn_console.print(f"[yellow]警告[/yellow]: {message}", highlight=False)

    if explain:
        console.print(f"[bold]preset[/bold]: {loaded.preset or '(なし)'}")
        console.print(f"[bold]config file[/bold]: {loaded.config_path or '(なし)'}")
        console.print(f"[bold]local config[/bold]: {loaded.local_config_path or '(なし)'}")
        for key in sorted(loaded.origins):
            console.print(f"  {key} [dim]← {loaded.origins[key]}[/dim]")
        return

    print(json.dumps(loaded.config.masked_dump(), ensure_ascii=False, indent=2))


@app.command("eval")
def eval_command(
    dataset_dir: Annotated[
        Path, typer.Option("--dataset", "-d", help="評価データセットのディレクトリ")
    ],
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (Reviewer を含むもの)")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="結果 JSON の保存先")
    ] = None,
    markdown: Annotated[
        Path | None, typer.Option("--markdown", "-m", help="比較表 (Markdown) の保存先")
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="標準出力を抑制する")] = False,
) -> None:
    """ラベル付きデータセットでレビュー精度を測る (設計書 §27).

    **主指標は Recall。** 見逃しを増やさずに誤検知を減らせているかを見る。
    """
    console = Console()
    root = (config_path.parent if config_path is not None else Path.cwd()).resolve()
    loaded = _load(root, config_path, None, {})
    for message in loaded.warnings:
        console.print(f"[yellow]警告[/yellow]: {message}", highlight=False)

    try:
        dataset = load_dataset(dataset_dir)
        result = asyncio.run(run_eval(dataset, loaded.config))
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    document = to_markdown(result)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if markdown is not None:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(document, encoding="utf-8")
    if not quiet:
        print(document)

    # 見逃しがあれば、それ自体を失敗として扱う (§27.2 の必須条件)
    if result.metrics.missed_true_positives:
        _fail(
            f"真陽性を {result.metrics.missed_true_positives} 件見逃しました: "
            f"{', '.join(result.metrics.missed_case_ids)}",
            ExitCode.POLICY_VIOLATION,
        )


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
