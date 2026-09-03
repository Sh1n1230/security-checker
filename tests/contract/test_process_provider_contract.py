"""内蔵 process Provider が公開契約テストを通ること (設計書 §25.2 の 7〜10)."""

from __future__ import annotations

from security_checker.testing import ProcessProviderContractTests


class TestProcessProviderContract(ProcessProviderContractTests):
    """既定の make_process_provider (内蔵 ProcessProvider) をそのまま検証する."""
