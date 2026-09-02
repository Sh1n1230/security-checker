"""Severity の順序比較."""

from __future__ import annotations

from security_checker.models.enums import Severity


def test_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.NONE < Severity.INFO
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.MEDIUM


def test_comparison_with_other_types_is_not_implemented():
    assert Severity.HIGH.__gt__("high") is NotImplemented
