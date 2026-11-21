"""Scanner/LLM metadata must remain inert in human-readable security reports."""

from __future__ import annotations

from security_checker.github.comment import render_inline, render_summary
from security_checker.models.enums import FindingStatus
from security_checker.report.markdown import _finding_block
from tests.factories import make_candidate, make_finding, make_report


def test_untrusted_cwe_cannot_create_a_forged_report_heading():
    candidate = make_candidate()
    injected = "CWE-79\x60\n## FORGED SECURITY VERDICT"
    finding = make_finding(candidate, FindingStatus.CONFIRMED, cwe=[injected])

    pr_summary = render_summary(make_report([candidate], [finding]))
    report_block = "\n".join(_finding_block(finding))

    for output in (pr_summary, report_block):
        assert "\n## FORGED SECURITY VERDICT" not in output
        assert "CWE-79' ## FORGED SECURITY VERDICT" in output
    assert pr_summary.startswith("<!-- security-checker:summary:v2 -->")


def test_untrusted_scanner_rule_names_cannot_break_inline_metadata_code_span():
    candidate = make_candidate(
        scanner="scanner\x60\n### FORGED INLINE HEADING",
        rule_id="rule\x60@reviewer",
    )
    finding = make_finding(candidate, FindingStatus.CONFIRMED)
    inline = render_inline(finding)

    assert "\n### FORGED INLINE HEADING" not in inline
    assert "scanner' ### FORGED INLINE HEADING/rule'@reviewer" in inline
    assert "<sub>\x60scanner'" in inline
