"""ドメイン列挙型 (設計書 §6.4)."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """重大度. 値の順序は `order` で比較する."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"

    @property
    def order(self) -> int:
        """深刻なほど大きい整数. 閾値比較に使う."""
        return _SEVERITY_ORDER[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.order >= other.order

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.order > other.order

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.order <= other.order

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.order < other.order


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class Category(StrEnum):
    """候補の由来カテゴリ."""

    SECRET = "secret"  # noqa: S105 - カテゴリ名であり秘密値ではない
    SAST = "sast"
    DEPENDENCY = "dependency"
    CONFIG = "config"
    WEB = "web"


class FindingStatus(StrEnum):
    """集約後の Finding の状態 (P3 以降で使用)."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    REVIEW_REQUIRED = "review_required"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    NOT_REVIEWED = "not_reviewed"
    ERROR = "error"


class Agreement(StrEnum):
    """Reviewer 間の一致度."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_APPLICABLE = "not_applicable"


class Exploitability(StrEnum):
    """悪用可能性."""

    PROVEN = "proven"
    LIKELY = "likely"
    THEORETICAL = "theoretical"
    NOT_EXPLOITABLE = "not_exploitable"
    UNKNOWN = "unknown"


class ScanStatus(StrEnum):
    """Scanner の実行結果 (設計書 §7.2: skipped と failed を混ぜない)."""

    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"
