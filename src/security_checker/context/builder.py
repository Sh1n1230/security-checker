"""Context Builder — Candidate → ReviewTask (設計書 §8).

ここが Secret 値のマスキングの **必須通過点** である (§19.2)。
"""

from __future__ import annotations

from pathlib import Path

from security_checker.config.schema import ContextConfig
from security_checker.context.budget import estimate_tokens
from security_checker.context.redact import mask_secret, redact_text
from security_checker.context.slicer import line_window, shrink
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category
from security_checker.models.task import (
    CodeContext,
    CodeSlice,
    RepoFacts,
    ReviewTask,
    TokenBudget,
)

MIN_WINDOW_LINES = 6
SECRET_MIN_LENGTH = 8


class ContextBuilder:
    """候補ごとにレビュー用の文脈を組み立てる."""

    def __init__(self, root: Path, config: ContextConfig, repo_facts: RepoFacts) -> None:
        self.root = root
        self.config = config
        self.repo_facts = repo_facts if config.include_repo_facts else RepoFacts()

    def build(self, candidate: Candidate) -> ReviewTask:
        notes: list[str] = []
        primary: CodeSlice | None = None
        truncated = False

        if candidate.location is not None:
            primary = line_window(
                self.root, candidate.location, window_lines=self.config.window_lines
            )
            if primary is None:
                notes.append("対象ファイルを読み込めなかったため、コード本文は提示されていません。")
        elif candidate.package is not None:
            notes.append("依存パッケージに対する指摘のため、コード本文はありません。")

        if primary is not None and candidate.category is Category.SECRET:
            primary = self._redact_slice(primary, candidate)
            notes.append(
                "この候補はシークレット検出です。値はマスクしてあり、原文は送信していません。"
            )

        if primary is not None:
            primary, truncated = self._fit_budget(primary, candidate)
            if truncated:
                notes.append(
                    "トークン予算のため文脈を切り詰めています。"
                    "判断に足りなければ needs_more_context に記載してください。"
                )

        context = CodeContext(primary=primary, truncated=truncated)
        estimated = estimate_tokens(primary.text) if primary is not None else 0
        return ReviewTask(
            candidate=candidate,
            code_context=context,
            repo_facts=self.repo_facts,
            budget=TokenBudget(
                max_tokens_per_task=self.config.max_tokens_per_task,
                estimated_input_tokens=estimated,
            ),
            notes=notes,
        )

    # --- 内部 -------------------------------------------------------------

    def _redact_slice(self, slice_: CodeSlice, candidate: Candidate) -> CodeSlice:
        """コード片に残っている検出値をマスクする (§19.2-2).

        形式が判断材料になるので完全消去はせず、prefix だけ残す。
        """
        secrets = _secret_hints(candidate)
        text = redact_text(slice_.text, secrets) if secrets else slice_.text
        text = _mask_long_tokens_on_line(text, candidate)
        return slice_.model_copy(update={"text": text})

    def _fit_budget(self, slice_: CodeSlice, candidate: Candidate) -> tuple[CodeSlice, bool]:
        """予算超過時はウィンドウを縮める (primary は最後まで守る・§8.3)."""
        limit = self.config.max_tokens_per_task
        if estimate_tokens(slice_.text) <= limit:
            return slice_, False

        focus = candidate.location.start_line if candidate.location else slice_.start_line
        keep = max(MIN_WINDOW_LINES, self.config.window_lines)
        current = slice_
        while keep >= MIN_WINDOW_LINES:
            current = shrink(slice_, keep_lines=keep, focus_line=focus)
            if estimate_tokens(current.text) <= limit:
                return current, True
            keep //= 2
        return current, True


def _secret_hints(candidate: Candidate) -> list[str]:
    """Candidate に残っている「値らしきもの」を集める.

    Candidate 側は既にマスク済みだが、コード片には原文が残っているため、
    ここでスニペットに含まれる長いトークンを潰す手掛かりに使う。
    """
    hints: list[str] = []
    snippet = candidate.location.snippet if candidate.location else None
    if snippet:
        hints.extend(part for part in snippet.split() if len(part) >= SECRET_MIN_LENGTH)
    return hints


def _mask_long_tokens_on_line(text: str, candidate: Candidate) -> str:
    """検出行に含まれる引用符付きの長い文字列をマスクする.

    gitleaks は値を返すが我々はそれを保持しないため、行単位で保守的に伏せる。
    """
    if candidate.location is None:
        return text
    masked_lines: list[str] = []
    for line in text.splitlines():
        masked_lines.append(_mask_quoted(line))
    return "\n".join(masked_lines)


def _mask_quoted(line: str) -> str:
    result = line
    for quote in ('"', "'"):
        parts = result.split(quote)
        if len(parts) < 3:
            continue
        for index in range(1, len(parts), 2):
            value = parts[index]
            if len(value) >= SECRET_MIN_LENGTH and " " not in value:
                parts[index] = mask_secret(value)
        result = quote.join(parts)
    return result
