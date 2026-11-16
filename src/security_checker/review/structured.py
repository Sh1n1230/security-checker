"""Structured Output — スキーマ生成・抽出・修復 (設計書 §10).

出力の形を LLM に委ねない。壊れた応答は握り潰さず、1 回だけ修復を試み、
それでも駄目なら `schema_error` として **レポートに残す**(黙って消さない・P9)。
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from security_checker.models.verdict import ReviewJudgement

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from security_checker.models.task import ReviewTask

FENCE_MARKERS = ("```json", "```JSON", "```")


@lru_cache(maxsize=1)
def verdict_schema() -> dict[str, Any]:
    """ReviewVerdict の LLM 生成部分を JSON Schema にする.

    `$ref` を展開し `additionalProperties: false` を全体に付ける
    (json_schema モードの strict 指定を通すため)。
    """
    raw = ReviewJudgement.model_json_schema()
    defs = raw.pop("$defs", {})
    hardened = _harden(_inline_refs(raw, defs))
    return hardened if isinstance(hardened, dict) else {}


def _inline_refs(node: object, defs: dict[str, Any]) -> object:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            target = _inline_refs(defs.get(ref.split("/")[-1], {}), defs)
            merged = dict(target) if isinstance(target, dict) else {}
            merged.update({k: v for k, v in node.items() if k != "$ref"})
            return merged
        return {key: _inline_refs(value, defs) for key, value in node.items()}
    if isinstance(node, list):
        return [_inline_refs(item, defs) for item in node]
    return node


def _harden(node: object) -> object:
    if isinstance(node, dict):
        hardened = {
            # properties の中身はプロパティ名 → スキーマ. 名前そのもの (title など) は消さない
            key: {name: _harden(sub) for name, sub in value.items()}
            if key == "properties" and isinstance(value, dict)
            else _harden(value)
            for key, value in node.items()
        }
        properties = hardened.get("properties")
        if hardened.get("type") == "object" and isinstance(properties, dict):
            hardened["additionalProperties"] = False
            # strict な json_schema モードでは「全プロパティが required」であることを
            # 求める実装があるため、省略可能な項目も null 許容にしたうえで必須にする。
            hardened["required"] = sorted(properties)
        hardened.pop("title", None)
        # pydantic は docstring を description にする. 内部向けの日本語のメモを
        # プロンプトの一部として LLM に送らない (送る説明はテンプレートで版管理する) (#290)
        hardened.pop("description", None)
        return hardened
    if isinstance(node, list):
        return [_harden(item) for item in node]
    return node


def extract_json(
    text: str, *, accept: Callable[[dict[str, Any]], bool] | None = None
) -> dict[str, Any] | None:
    """応答から JSON オブジェクトを取り出す.

    ```json フェンス・前後の散文・末尾の余計な文章を許容する (§10.2)。
    `accept` を渡すと、それを満たす最初のオブジェクトを返す。モデルが「例えば {"a": 1} の
    ように…」と前置きしてから答えを書いたとき、例示ではなく答えを拾うため。
    どれも満たさなければ最後のオブジェクトを返す (答えは例示の後に来る)。
    `accept` が無ければ最初のオブジェクトを返す。
    """
    if not text:
        return None
    candidate = _strip_fence(text.strip())
    direct = _try_load(candidate)
    if direct is not None:
        return direct
    last: dict[str, Any] | None = None
    for found in _objects(candidate):
        if accept is None or accept(found):
            return found
        last = found
    return last


def _strip_fence(text: str) -> str:
    for marker in FENCE_MARKERS:
        if text.startswith(marker):
            without_open = text[len(marker) :]
            closing = without_open.rfind("```")
            return (without_open[:closing] if closing != -1 else without_open).strip()
    return text


def _try_load(text: str) -> dict[str, Any] | None:
    try:
        loaded = json.loads(text)
    except ValueError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _objects(text: str) -> Iterator[dict[str, Any]]:
    """最上位の「釣り合った」波括弧ブロックのうち、JSON として読めるものを順に返す.

    文字列内の括弧は数えない。
    """
    depth = 0
    start = -1
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            index = _after_string(text, index)
            continue
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start != -1:
                found = _try_load(text[start : index + 1])
                if found is not None:
                    yield found
                start = -1
        index += 1


def _after_string(text: str, opening: int) -> int:
    """`opening` の引用符で始まる文字列の、閉じ引用符の次の位置. 閉じていなければ末尾."""
    index = opening + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index + 1
        index += 1
    return len(text)


class SchemaViolationError(Exception):
    """検証に失敗した. message は修復プロンプトにそのまま載せる."""

    def __init__(self, message: str, *, raw_text: str) -> None:
        super().__init__(message)
        self.raw_text = raw_text


def _is_judgement(data: dict[str, Any]) -> bool:
    try:
        ReviewJudgement.model_validate(data)
    except ValidationError:
        return False
    return True


def parse_judgement(payload: dict[str, Any] | None, raw_text: str) -> ReviewJudgement:
    """応答を ReviewJudgement に変換する. 失敗は SchemaViolationError として上げる."""
    data = payload
    if data is None or not _is_judgement(data):
        # Provider が取り出したもの (最初のオブジェクト) が判定でなければ、本文から探し直す
        data = extract_json(raw_text, accept=_is_judgement) or data
    if data is None:
        raise SchemaViolationError(
            "応答から JSON オブジェクトを取り出せませんでした", raw_text=raw_text
        )
    try:
        return ReviewJudgement.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '(root)'}: {error['msg']}"
            for error in exc.errors()[:5]
        )
        raise SchemaViolationError(details, raw_text=raw_text) from exc


def drop_hallucinated_evidence(
    judgement: ReviewJudgement, task: ReviewTask
) -> tuple[ReviewJudgement, list[str]]:
    """提示した範囲外を指す evidence を落とす (§11.3).

    ハルシネーションした位置をレポートに載せない。落としたことは warning に残す。
    コードを 1 行も提示していない候補 (依存パッケージなど) の evidence はすべて範囲外である。
    """
    if not judgement.evidence:
        return judgement, []
    context = task.code_context
    shown = [*([context.primary] if context.primary is not None else []), *context.callers]

    kept = []
    warnings = []
    for item in judgement.evidence:
        path = item.path.replace("\\", "/").removeprefix("./")
        inside = item.start_line <= item.end_line and any(
            path == slice_.path
            and slice_.start_line <= item.start_line
            and item.end_line <= slice_.end_line
            for slice_ in shown
        )
        if inside:
            kept.append(item)
        else:
            warnings.append(
                f"提示範囲外の evidence を除外しました: "
                f"{item.path}:{item.start_line}-{item.end_line}"
            )
    if len(kept) == len(judgement.evidence):
        return judgement, []
    return judgement.model_copy(update={"evidence": kept}), warnings
