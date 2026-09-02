"""テスト用のフェイク実装 (設計書 §25).

外部プラグイン作者にも公開する。実ツール / 実 LLM を叩かずにパイプラインを回すために使う。
"""

from __future__ import annotations

from typing import ClassVar

from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, ScanStatus
from security_checker.scanners.base import ScanContext, ScanResult, Target, ToolStatus


class FakeScanner:
    """あらかじめ決めた結果を返す Scanner."""

    requires: ClassVar[list[str]] = []

    def __init__(
        self,
        name: str = "fake",
        *,
        category: Category = Category.SAST,
        status: ScanStatus = ScanStatus.OK,
        candidates: list[Candidate] | None = None,
        reason: str | None = None,
        exit_code: int | None = 0,
        raises: Exception | None = None,
    ) -> None:
        self.name = name
        self.category = category
        self._status = status
        self._candidates = candidates or []
        self._reason = reason
        self._exit_code = exit_code
        self._raises = raises
        self.calls = 0

    def probe(self) -> ToolStatus:
        return ToolStatus(available=self._status is not ScanStatus.SKIPPED, reason=self._reason)

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=self._status,
            candidates=self._candidates if self._status is ScanStatus.OK else [],
            reason=self._reason,
            exit_code=self._exit_code,
        )
