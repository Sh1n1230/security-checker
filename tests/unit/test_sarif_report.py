"""SARIF 出力 (設計書 §18.3, §18.4).

ここで押さえるのは Ruleset のゲートが依存する不変条件:
tool 名の固定・level の決め方・review_required を落とさないこと・壊れた run を成功に見せないこと。
"""

from __future__ import annotations

import json
from typing import Any

from security_checker.models.candidate import Location, PackageRef
from security_checker.models.enums import Category, FindingStatus, ScanStatus, Severity
from security_checker.models.finding import SuppressionReason
from security_checker.models.report import ScannerRun
from security_checker.report.sarif import TOOL_NAME, is_uploadable, render_sarif, write_sarif
from tests.factories import make_candidate, make_finding, make_report, make_verdict


def results_of(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = sarif["runs"][0]["results"]
    return results


def test_tool_name_is_fixed_regardless_of_scanner():
    """Ruleset は tool.driver.name をキーにする. スキャナ名にしてはならない (§18.4.4)."""
    candidates = [
        make_candidate("a", scanner="semgrep"),
        make_candidate("b", scanner="gitleaks", category=Category.SECRET),
    ]
    sarif = render_sarif(make_report(candidates))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == TOOL_NAME == "security-checker"
    assert {r["ruleId"] for r in results_of(sarif)} == {
        "semgrep/rules.command-injection",
        "gitleaks/rules.command-injection",
    }
    rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)


def test_scan_mode_maps_scanner_severity_to_level():
    candidates = [
        make_candidate("crit", severity=Severity.CRITICAL),
        make_candidate("med", severity=Severity.MEDIUM, path="b.py"),
        make_candidate("low", severity=Severity.LOW, path="c.py"),
        make_candidate("none", severity=None, path="d.py"),
    ]
    results = {
        r["partialFingerprints"]["primary"]: r
        for r in results_of(render_sarif(make_report(candidates)))
    }
    assert results["crit"]["level"] == "error"
    assert results["crit"]["properties"]["security-severity"] == "9.5"
    assert results["med"]["level"] == "warning"
    assert results["low"]["level"] == "note"
    assert results["none"]["level"] == "note"


def test_location_and_fingerprint():
    sarif = render_sarif(make_report([make_candidate("abc123", path="src/x.py", line=7)]))
    result = results_of(sarif)[0]
    region = result["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "src/x.py"
    assert region["region"] == {"startLine": 7, "endLine": 7}
    # 行番号を含まない安定 ID を指紋にする. 無関係な編集で alert が付け替わらない
    assert result["partialFingerprints"] == {"primary": "abc123"}


def test_line_zero_is_clamped_to_one():
    """SARIF の行番号は 1 始まり. 0 をそのまま出すと GitHub が結果を捨てる."""
    sarif = render_sarif(make_report([make_candidate(line=0)]))
    assert results_of(sarif)[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_dependency_candidate_is_placed_on_its_manifest():
    candidate = make_candidate(
        "dep",
        category=Category.DEPENDENCY,
        location=None,
        package=PackageRef(ecosystem="PyPI", name="x", version="1.0", manifest="requirements.txt"),
    )
    result = results_of(render_sarif(make_report([candidate])))[0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "requirements.txt"
    )


def test_candidate_without_any_location_is_skipped():
    candidate = make_candidate("nowhere", location=None)
    assert results_of(render_sarif(make_report([candidate]))) == []


def test_confirmed_uses_scanner_severity_not_llm_severity():
    """D3: LLM の判定で level を決めると、非決定性で alert が開閉を繰り返す."""
    candidate = make_candidate(severity=Severity.MEDIUM)
    finding = make_finding(candidate, FindingStatus.CONFIRMED, severity=Severity.CRITICAL)
    result = results_of(render_sarif(make_report([candidate], [finding])))[0]
    assert result["level"] == "warning"
    assert result["properties"]["security-severity"] == "5.5"
    # LLM の判定は properties に残す
    assert result["properties"]["llm_severity"] == "critical"
    assert result["properties"]["status"] == "confirmed"


def test_likely_is_one_step_lower():
    candidate = make_candidate(severity=Severity.HIGH)
    finding = make_finding(candidate, FindingStatus.LIKELY)
    result = results_of(render_sarif(make_report([candidate], [finding])))[0]
    assert result["level"] == "warning"
    assert result["properties"]["security-severity"] == "7.0"


def test_review_required_is_note_and_zero():
    """§18.4.1: review_required は CI を落とさない. Ruleset 側でもその約束を守る."""
    candidate = make_candidate(severity=Severity.CRITICAL)
    finding = make_finding(candidate, FindingStatus.REVIEW_REQUIRED)
    result = results_of(render_sarif(make_report([candidate], [finding])))[0]
    assert result["level"] == "note"
    assert result["properties"]["security-severity"] == "0.0"


def test_unjudged_findings_stay_visible_but_do_not_block():
    """判定が得られなかった候補を出さないと、既存 alert が「解決済み」に化ける."""
    statuses = [FindingStatus.NOT_REVIEWED, FindingStatus.ERROR, FindingStatus.INCONCLUSIVE]
    candidates = [make_candidate(f"c{i}", path=f"f{i}.py") for i in range(len(statuses))]
    findings = [
        make_finding(candidate, status, verdicts=[])
        for candidate, status in zip(candidates, statuses, strict=True)
    ]
    results = results_of(render_sarif(make_report(candidates, findings)))
    assert len(results) == 3
    assert {r["level"] for r in results} == {"note"}


def test_false_positive_and_suppressed_are_not_emitted():
    fp = make_candidate("fp", path="a.py")
    suppressed = make_candidate("sup", path="b.py")
    kept = make_candidate("kept", path="c.py")
    findings = [
        make_finding(fp, FindingStatus.FALSE_POSITIVE),
        make_finding(suppressed, FindingStatus.CONFIRMED, suppressed=SuppressionReason.BASELINE),
        make_finding(kept, FindingStatus.CONFIRMED),
    ]
    results = results_of(render_sarif(make_report([fp, suppressed, kept], findings)))
    assert [r["partialFingerprints"]["primary"] for r in results] == ["kept"]


def test_message_carries_llm_summary_and_reasoning():
    candidate = make_candidate()
    finding = make_finding(
        candidate,
        FindingStatus.CONFIRMED,
        summary="OS コマンドインジェクション",
        verdicts=[
            make_verdict("alpha", reasoning="filename がシェルに渡る"),
            make_verdict("beta", vulnerable=False, confidence=0.3),
        ],
    )
    result = results_of(render_sarif(make_report([candidate], [finding])))[0]
    text = result["message"]["text"]
    assert text.startswith("[confirmed] OS コマンドインジェクション")
    assert "filename がシェルに渡る" in text
    reviewers = result["properties"]["reviewers"]
    assert [r["name"] for r in reviewers] == ["alpha", "beta"]
    assert reviewers[1]["vulnerable"] is False


def test_message_is_truncated_and_redacted():
    candidate = make_candidate(message="key=sk-" + "A" * 40 + " " + "x" * 3000)
    text = results_of(render_sarif(make_report([candidate])))[0]["message"]["text"]
    assert len(text) <= 1000
    assert "A" * 40 not in text


def test_successful_run_is_uploadable():
    sarif = render_sarif(make_report([make_candidate()]))
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in invocation
    assert is_uploadable(sarif)


def test_failed_scanner_marks_run_unsuccessful():
    """§18.4.2: 壊れた run の SARIF を上げると、既存 alert が一括で閉じる."""
    runs = [
        ScannerRun(scanner="semgrep", category=Category.SAST, status=ScanStatus.OK),
        ScannerRun(
            scanner="gitleaks",
            category=Category.SECRET,
            status=ScanStatus.FAILED,
            reason="exit 2",
        ),
    ]
    sarif = render_sarif(make_report([], scanners=runs))
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    notifications = invocation["toolExecutionNotifications"]
    assert notifications[0]["level"] == "error"
    assert "gitleaks" in notifications[0]["message"]["text"]
    assert not is_uploadable(sarif)


def test_skipped_scanner_does_not_block_upload():
    runs = [ScannerRun(scanner="osv", category=Category.DEPENDENCY, status=ScanStatus.SKIPPED)]
    assert is_uploadable(render_sarif(make_report([], scanners=runs)))


def test_empty_sarif_is_not_uploadable():
    assert not is_uploadable({"runs": []})
    assert not is_uploadable({"runs": [{"invocations": [{}]}]})


def test_write_sarif_produces_valid_json(tmp_path):
    path = write_sarif(
        make_report([make_candidate(location=Location(path="a.py", start_line=1, end_line=2))]),
        tmp_path,
    )
    assert path.name == "report.sarif"
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 1,
        "endLine": 2,
    }
