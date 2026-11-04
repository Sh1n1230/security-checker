"""Tests for resolve_http_preset edge cases.

Covers the path where no preset matches the provided base_url and model.
"""

from __future__ import annotations

from security_checker.providers.presets.loader import (
    HttpPreset,
    PresetMatch,
    resolve_http_preset,
)


def test_resolve_http_preset_returns_none_when_no_match():
    """When name is omitted and no preset matches host/model, return None.

    This covers the final return None in resolve_http_preset.
    """
    presets = {
        "example": HttpPreset(
            name="example",
            dialect="openai",
            match=PresetMatch(host="example.com", model="gpt-.*"),
        )
    }
    result = resolve_http_preset(
        presets,
        name=None,
        base_url="https://other.example.com/v1",
        model="claude-3",
    )
    assert result is None


def test_resolve_http_preset_returns_none_when_base_or_model_missing():
    """Early return None when base_url or model is missing."""
    presets = {}
    assert resolve_http_preset(presets, name=None, base_url=None, model="x") is None
    assert resolve_http_preset(presets, name=None, base_url="https://x", model=None) is None
