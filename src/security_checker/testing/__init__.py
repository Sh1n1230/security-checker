"""外部プラグイン作者に公開するテスト支援 API (設計書 §25.2)."""

from __future__ import annotations

from security_checker.testing.fakes import FakeScanner, ScriptedProvider, verdict_payload
from security_checker.testing.provider_contract import ProviderContractTests

__all__ = ["FakeScanner", "ProviderContractTests", "ScriptedProvider", "verdict_payload"]
