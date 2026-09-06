"""レポート本文の言語 (設計書 §18).

LLM が返す自然言語フィールド (`reasoning` / `impact` / `remediation.approach` など) の
言語を決める。ここで決めた言語が、terminal / markdown / json のすべての出力に効く
(レポート本文は LLM の出力そのものなので、出力形式ごとに訳し直す場所がない)。

既定は `auto`: 利用者のロケールから推定し、判定できなければ英語にする。
**推定結果は必ずトレースに残す** (§24.2)。同じリポジトリでも実行環境によって
本文の言語が変わりうるため、「どの言語で書かせたか」が後から分からないと監査できない。
"""

from __future__ import annotations

import os
from collections.abc import Mapping

AUTO = "auto"
DEFAULT_LANGUAGE = "en"
LOCALE_VARS = ("LC_ALL", "LC_MESSAGES", "LANG")
#: ロケール未設定を表す値. これらは「英語」ではなく「不明」として扱う.
NEUTRAL_LOCALES = frozenset({"c", "posix", ""})

#: 言語タグ → プロンプトに書く名前. 未知のタグはそのまま渡す (ここは網羅を目指さない).
LANGUAGE_NAMES = {
    "ar": "Arabic",
    "de": "German",
    "en": "English",
    "es": "Spanish",
    "fr": "French",
    "hi": "Hindi",
    "id": "Indonesian",
    "it": "Italian",
    "ja": "Japanese (日本語)",
    "ko": "Korean (한국어)",
    "pt": "Portuguese",
    "ru": "Russian",
    "th": "Thai",
    "tr": "Turkish",
    "vi": "Vietnamese",
    "zh": "Chinese (中文)",
}


def resolve_language(configured: str, environ: Mapping[str, str] | None = None) -> str:
    """設定値を実際の言語タグに解決する. `auto` のときだけ環境を見る."""
    if configured != AUTO:
        return configured
    source = environ if environ is not None else os.environ
    for variable in LOCALE_VARS:
        tag = _tag_from_locale(source.get(variable))
        if tag is not None:
            return tag
    return DEFAULT_LANGUAGE


def _tag_from_locale(value: str | None) -> str | None:
    """`ja_JP.UTF-8` → `ja`. ロケール未設定 (C / POSIX) は不明として扱う."""
    if not value:
        return None
    head = value.split(".")[0].split("@")[0].strip()
    if head.lower() in NEUTRAL_LOCALES:
        return None
    return head.replace("_", "-").split("-")[0].lower() or None


def language_name(tag: str) -> str:
    """プロンプトに書く言語名. 未知のタグはタグ自体を使う."""
    return LANGUAGE_NAMES.get(tag.lower(), tag)


def output_language_instruction(tag: str) -> str:
    """出力言語の指示. 英語なら**何も足さない** (v1 プロンプトと完全一致させるため).

    構造化フィールドの値 (enum・CWE・パス・コード) まで訳されるとスキーマ検証や
    突き合わせが壊れるため、訳す対象を明示的に列挙する。
    """
    if tag.lower().split("-")[0] == DEFAULT_LANGUAGE:
        return ""
    return (
        "OUTPUT LANGUAGE:\n"
        f"Write every natural-language field in {language_name(tag)}: "
        "`reasoning`, `impact`, `attack_vector`, `attack_path`, "
        "`vulnerability_type`, `remediation.approach`, and `evidence[].note`.\n"
        "Do NOT translate anything else. These must stay exactly as specified by the "
        "schema or the source: JSON keys, enum values (`severity`, `exploitability`), "
        "CWE identifiers, file paths, symbol names, and the code inside "
        "`remediation.example`."
    )
