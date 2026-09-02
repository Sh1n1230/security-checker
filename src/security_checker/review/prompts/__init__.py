"""プロンプトテンプレート (設計書 §11).

テンプレートはバージョン番号付きで置く (`system.v1.jinja`)。
プロンプト変更は評価指標に直結するため、差し替えは版を分けて行う。
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from security_checker.models.task import ReviewTask

PROMPT_DIR = Path(__file__).parent
PROMPT_VERSION = "v1"


@lru_cache(maxsize=1)
def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(PROMPT_DIR),
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - HTML ではなくプロンプトを生成するため
        keep_trailing_newline=True,
    )


def render_system() -> str:
    return _environment().get_template(f"system.{PROMPT_VERSION}.jinja").render()


def render_user(task: ReviewTask, schema: dict[str, object]) -> str:
    primary = task.code_context.primary
    return (
        _environment()
        .get_template(f"user.{PROMPT_VERSION}.jinja")
        .render(
            candidate=task.candidate,
            primary=primary,
            primary_text=_sanitize(primary.numbered()) if primary is not None else "",
            callers=task.code_context.callers,
            facts=task.repo_facts,
            notes=task.notes,
            schema=json.dumps(schema, ensure_ascii=False, indent=2),
        )
    )


def _sanitize(text: str) -> str:
    """コード中にデリミタが現れたらエスケープする (§19.4-2)."""
    return text.replace("<<<UNTRUSTED_CODE>>>", "<<<UNTRUSTED_CODE_ESCAPED>>>").replace(
        "<<<END_UNTRUSTED_CODE>>>", "<<<END_UNTRUSTED_CODE_ESCAPED>>>"
    )


def render_repair(previous_output: str, error: str, schema: dict[str, object]) -> str:
    """修復リトライ用の指示 (§10.2). 1 回だけ使う."""
    return (
        "あなたの前回の出力は次の理由で不正でした:\n"
        f"{error}\n\n"
        "前回の出力:\n"
        f"{previous_output[:4000]}\n\n"
        "同じ判定内容のまま、スキーマに適合する JSON オブジェクトのみを再出力してください。"
        "JSON 以外の文字は一切出力しないでください。\n"
        f"{json.dumps(schema, ensure_ascii=False)}"
    )
