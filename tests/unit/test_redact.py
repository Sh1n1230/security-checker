"""マスキング関数のテスト (設計書 §19)."""

from __future__ import annotations

import pytest

from security_checker.context.redact import mask_secret, redact_known_patterns, redact_text


@pytest.mark.parametrize(
    ("value", "expected_prefix"),
    [("AKIATESTONLY000000", "AKIA"), ("xoxb-abcdef", "xoxb"), ("ab", "")],
)
def test_mask_keeps_only_prefix(value, expected_prefix):
    masked = mask_secret(value)
    assert value not in masked or len(value) <= 4
    if expected_prefix:
        assert masked.startswith(expected_prefix)
        assert set(masked[4:]) == {"*"}


def test_mask_empty():
    assert mask_secret("") == ""


def test_redact_text_replaces_all_occurrences():
    text = 'key = "TESTONLY-1234567890"; backup = "TESTONLY-1234567890"'
    redacted = redact_text(text, ["TESTONLY-1234567890"])
    assert "TESTONLY-1234567890" not in redacted
    assert redacted.count("TEST*") == 2


def test_redact_known_patterns_masks_api_keys():
    text = "使用中のキー: sk-abcdefghijklmnop と ghp_0123456789abcdefgh"
    redacted = redact_known_patterns(text)
    assert "sk-abcdefghijklmnop" not in redacted
    assert "ghp_0123456789abcdefgh" not in redacted
