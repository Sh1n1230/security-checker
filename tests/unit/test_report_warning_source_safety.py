"""Warning source fields must not inject Markdown into security reports."""
from __future__ import annotations

from types import SimpleNamespace

from security_checker.report.markdown import _warnings


def test_untrusted_warning_sources_cannot_forge_report_sections():
    malicious = "scanner\n## No security problems detected"
    report = SimpleNamespace(
        warnings=[
            SimpleNamespace(level="error", source=malicious, message="scan failed"),
            SimpleNamespace(level="warn", source=malicious, message="scan skipped"),
        ]
    )
    result = "\n".join(_warnings(report))

    assert "\n## No security problems detected" not in result
    assert result.count("scanner ## No security problems detected") == 2
    assert result.count("scan failed") == 1
    assert result.count("scan skipped") == 1


def test_warning_sources_cannot_insert_new_list_items():
    forged = "scanner\n- green: all checks passed"
    report = SimpleNamespace(
        warnings=[SimpleNamespace(level="warn", source=forged, message="not inspected")]
    )
    result = "\n".join(_warnings(report))
    assert "\n- green: all checks passed" not in result
    assert "scanner - green: all checks passed" in result
