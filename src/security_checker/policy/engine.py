"""Policy Engine — 閾値判定と exit code の決定 (設計書 §17.1).

「脆弱性が見つかった」(1) と「ツールが壊れた」(3) を必ず分ける。
これを混ぜたのが v1 の「壊れているのに緑」の原因だった。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from security_checker.config.schema import PolicyConfig
from security_checker.errors import ExitCode
from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.report import Report


@dataclass
class PolicyDecision:
    """判定結果と、その理由."""

    exit_code: ExitCode
    reasons: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.exit_code is not ExitCode.OK


def evaluate(report: Report, policy: PolicyConfig) -> PolicyDecision:
    """レポートをポリシーに照らして exit code を決める."""
    reasons: list[str] = []

    failed_runs = [run for run in report.scanners if run.status is ScanStatus.FAILED]
    if failed_runs and policy.strict:
        names = ", ".join(run.scanner for run in failed_runs)
        return PolicyDecision(
            exit_code=ExitCode.EXECUTION_ERROR,
            reasons=[f"スキャナが失敗しました (strict): {names}"],
        )

    threshold = policy.fail_on
    if threshold is not Severity.NONE:
        blocking = [
            candidate
            for candidate in report.candidates
            if (candidate.severity_reported or Severity.INFO) >= threshold
        ]
        if blocking:
            reasons.append(
                f"{threshold.value} 以上の検出が {len(blocking)} 件あります "
                f"(policy.fail_on: {threshold.value})"
            )

    if policy.min_score is not None and report.score.value < policy.min_score:
        reasons.append(f"スコア {report.score.value} が下限 {policy.min_score} を下回りました")

    if reasons:
        return PolicyDecision(exit_code=ExitCode.POLICY_VIOLATION, reasons=reasons)
    return PolicyDecision(exit_code=ExitCode.OK, reasons=[])
