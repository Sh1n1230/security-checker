"""外部プラグイン作者に公開するテスト支援 API (設計書 §25.2)."""

from __future__ import annotations

from security_checker.testing.cassette import CassetteMissError, CassetteProvider
from security_checker.testing.fakes import FakeScanner, ScriptedProvider, verdict_payload
from security_checker.testing.provider_contract import (
    ProcessProviderContractTests,
    ProviderContractTests,
    python_command,
)
from security_checker.testing.scanner_contract import ScannerContractTests

__all__ = [
    "CassetteMissError",
    "CassetteProvider",
    "FakeScanner",
    "ProcessProviderContractTests",
    "ProviderContractTests",
    "ScannerContractTests",
    "ScriptedProvider",
    "python_command",
    "verdict_payload",
]
