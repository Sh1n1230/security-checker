"""Markdown への埋め込みの無害化 (設計書 §19.4, #44).

LLM の出力はレビュー対象のコードに誘導されうる。PR コメントと `report.md`
(= GitHub の Step Summary) の両方で、注入文字列が構造を壊さないことを押さえる。
"""

from __future__ import annotations

from typing import Any

from security_checker.errors import ExitCode
from security_checker.models.enums import FindingStatus
from security_checker.models.report import Report
from security_checker.models.verdict import Remediation
from security_checker.policy.engine import PolicyDecision
from security_checker.report import sanitize as md
from security_checker.report.markdown import render_markdown
from tests.factories import make_candidate, make_finding, make_report, make_verdict

INJECTION = (
    "<!-- hide --> <details><summary>✅ No issues</summary> "
    "![x](https://attacker.example/pixel.png) ping @octocat "
    f"key sk-{'A' * 40}"
)


# --- 単体 -----------------------------------------------------------------------


def test_text_neutralizes_html_images_mentions_and_secrets():
    cleaned = md.text(INJECTION)
    assert "<" not in cleaned
    assert ">" not in cleaned
    assert "![" not in cleaned
    assert "@octocat" not in cleaned
    assert "A" * 40 not in cleaned


def test_text_keeps_email_addresses():
    assert "a@b.com" in md.text("contact a@b.com")


def test_code_span_cannot_be_escaped_with_backticks():
    span = md.code_span("src/a.py`<img src=x>`:1")
    assert span.startswith("`")
    assert span.endswith("`")
    assert span.count("`") == 2


def test_code_block_fence_is_longer_than_any_backtick_run_inside():
    lines = md.code_block("x = 1\n````\n# ## Injected heading\n````")
    fence = lines[0]
    assert fence == "`````"
    assert lines[-1] == fence


def test_code_block_uses_three_backticks_by_default():
    assert md.code_block("print(1)") == ["```", "print(1)", "```"]


# --- report.md ------------------------------------------------------------------


def _report_with(**verdict_overrides: Any) -> Report:
    candidate = make_candidate(path="src/a`b.py", line=1)
    finding = make_finding(
        candidate,
        FindingStatus.CONFIRMED,
        summary=INJECTION,
        verdicts=[make_verdict("r1", **verdict_overrides)],
    )
    return make_report([candidate], [finding])


def test_report_md_neutralizes_llm_text():
    body = render_markdown(
        _report_with(
            reasoning=INJECTION,
            attack_path=["<script>", "@octocat"],
            remediation=Remediation(approach=INJECTION),
        ),
        PolicyDecision(ExitCode.OK),
    )
    assert "<!-- hide" not in body
    assert "<details><summary>✅" not in body
    assert "![x]" not in body
    assert "@octocat" not in body
    assert "<script>" not in body
    assert "A" * 40 not in body
    # 自分で出す要素は残る
    assert "<details><summary>各 Reviewer の判断理由</summary>" in body


def test_report_md_example_cannot_break_out_of_its_fence():
    example = "fixed()\n```\n## ✅ No issues found\n```"
    body = render_markdown(
        _report_with(remediation=Remediation(approach="直す", example=example)),
        PolicyDecision(ExitCode.OK),
    )
    lines = body.splitlines()
    start = lines.index("````")
    end = lines.index("````", start + 1)
    assert "## ✅ No issues found" in lines[start:end]


def test_report_md_path_cannot_break_out_of_code_span():
    body = render_markdown(_report_with(), PolicyDecision(ExitCode.OK))
    assert "`src/a'b.py:1`" in body
