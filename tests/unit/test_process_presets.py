"""process プリセットの読み込みと組み立て (設計書 §9.7).

プリセットは**データ**であり、コードにコマンド名は現れない。
利用者は PR なしで追加・上書きできる。
"""

from __future__ import annotations

import pytest

from security_checker.config.schema import ReviewerConfig
from security_checker.errors import ConfigError
from security_checker.providers.presets.loader import (
    ProcessPreset,
    load_process_presets,
    resolve_process_preset,
)
from security_checker.providers.registry import build_process_provider, build_provider


def test_bundled_process_presets_are_loadable_without_user_presets(tmp_path):
    """ユーザー側に 1 つも無くても同梱分は読める.

    同梱プリセットがあっても既定 Reviewer は増えない (§9.8)。
    中身の検証は test_bundled_presets.py。
    """
    presets = load_process_presets(tmp_path)
    assert all(preset.source == "bundled" for preset in presets.values())


def test_user_preset_is_loaded(tmp_path):
    (tmp_path / "mine.yml").write_text(
        "command: ['my-cmd', '--non-interactive']\n"
        "prompt_via: file\n"
        "requires_readonly_flags: true\n"
        "capabilities:\n  max_context_tokens: 200000\n",
        encoding="utf-8",
    )
    presets = load_process_presets(tmp_path)
    assert presets["mine"].command == ["my-cmd", "--non-interactive"]
    assert presets["mine"].prompt_via == "file"
    assert presets["mine"].source == "user"


def test_broken_preset_is_a_config_error(tmp_path):
    (tmp_path / "bad.yml").write_text("command: 42\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_process_presets(tmp_path)


def test_unknown_preset_name_lists_what_exists():
    with pytest.raises(ConfigError, match="利用可能"):
        resolve_process_preset({}, name="nope")


def test_command_alone_is_enough():
    """プリセットを 1 つも同梱しなくても command 直書きで動く — P2.5 の受け入れ条件."""
    config = ReviewerConfig(name="r1", transport="process", command=["cmd", "--flag"])
    built = build_process_provider(config, presets={})
    assert built.command == ["cmd", "--flag"]
    assert built.prompt_via == "stdin"


def test_preset_supplies_the_command():
    preset = ProcessPreset(name="mine", command=["my-cmd", "--x"], prompt_via="file")
    config = ReviewerConfig(name="r1", transport="process", preset="mine")
    built = build_process_provider(config, presets={"mine": preset})
    assert built.command == ["my-cmd", "--x"]
    assert built.prompt_via == "file"
    assert built.model == "mine"


def test_direct_command_warns_about_write_capability():
    """本体はコマンドの中身を検証できない. 責任の所在を黙って飲み込まない (§9.7 の 2)."""
    warnings: list[str] = []
    config = ReviewerConfig(name="r1", transport="process", command=["cmd"])
    build_process_provider(config, presets={}, warnings=warnings)
    assert len(warnings) == 1
    assert "書き込み能力" in warnings[0]


def test_preset_declaring_readonly_flags_is_not_warned():
    preset = ProcessPreset(name="safe", command=["cmd", "--no-tools"], requires_readonly_flags=True)
    warnings: list[str] = []
    config = ReviewerConfig(name="r1", transport="process", preset="safe")
    build_process_provider(config, presets={"safe": preset}, warnings=warnings)
    assert warnings == []


def test_structured_output_override_is_rejected_with_a_warning():
    warnings: list[str] = []
    config = ReviewerConfig(
        name="r1",
        transport="process",
        command=["cmd"],
        capabilities={"structured_output": "json_schema"},
    )
    built = build_process_provider(config, presets={}, warnings=warnings)
    assert built.capabilities.structured_output.value == "prompt_only"
    assert any("prompt_only" in warning for warning in warnings)


def test_build_provider_routes_process_transport():
    config = ReviewerConfig(name="r1", transport="process", command=["cmd"])
    assert build_provider(config).transport == "process"


def test_text_io_dialect_is_rejected_for_http():
    with pytest.raises(ValueError, match="text_io"):
        ReviewerConfig(
            name="r1",
            transport="http",
            dialect="text_io",
            base_url="https://x/v1",
            model="m",
        )


def test_http_dialect_is_rejected_for_process():
    with pytest.raises(ValueError, match="text_io のみ"):
        ReviewerConfig(name="r1", transport="process", command=["cmd"], dialect="openai_chat")
