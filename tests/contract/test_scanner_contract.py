"""内蔵 Scanner と FakeScanner が公開の Scanner 契約テストを通ること (設計書 §25, §29).

実ツールが無い環境 (CI の quality ジョブ) では「skipped を返す」側の契約を検証する。
"""

from __future__ import annotations

from pathlib import Path

from security_checker.config.schema import GitleaksConfig, OsvConfig, SemgrepConfig, TrivyConfig
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, ScanStatus
from security_checker.scanners.base import Scanner
from security_checker.scanners.gitleaks import GitleaksScanner
from security_checker.scanners.osv import OsvScanner
from security_checker.scanners.semgrep import SemgrepScanner
from security_checker.scanners.trivy import TrivyScanner
from security_checker.testing import FakeScanner, ScannerContractTests

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestFakeScannerContract(ScannerContractTests):
    def make_scanner(self) -> Scanner:
        return FakeScanner(
            "fake",
            candidates=[
                Candidate(
                    id="a",
                    scanner="fake",
                    category=Category.SAST,
                    rule_id="r",
                    title="t",
                    message="m",
                    location=Location(path="a.py", start_line=1, end_line=1),
                )
            ],
        )


class TestFailingFakeScannerContract(ScannerContractTests):
    def make_scanner(self) -> Scanner:
        return FakeScanner("broken", status=ScanStatus.FAILED, reason="exit 2")


class TestSemgrepContract(ScannerContractTests):
    def make_scanner(self) -> Scanner:
        return SemgrepScanner(SemgrepConfig(config=str(FIXTURES / "semgrep-rules.yml")))

    def populate(self, root: Path) -> None:
        (root / "app.py").write_text(
            (FIXTURES / "vulnerable-app" / "app.py").read_text(encoding="utf-8"), encoding="utf-8"
        )


class TestGitleaksContract(ScannerContractTests):
    def make_scanner(self) -> Scanner:
        return GitleaksScanner(GitleaksConfig())


class TestOsvContract(ScannerContractTests):
    def make_scanner(self) -> Scanner:
        return OsvScanner(OsvConfig(enabled=True))


class TestTrivyContract(ScannerContractTests):
    def make_scanner(self) -> Scanner:
        return TrivyScanner(
            TrivyConfig(enabled=True, extra_args=["--offline-scan", "--skip-check-update"])
        )
