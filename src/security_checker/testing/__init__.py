"""外部プラグイン作者に公開するテスト支援 API (設計書 §25.2)."""

from __future__ import annotations

from security_checker.testing.fakes import FakeScanner

__all__ = ["FakeScanner"]
