"""受け付けたが効かない設定を、黙って無視しない (設計書 P9).

v1 の最大の欠陥は「ツールが失敗しても成功に見える」ことだった。
「設定したのに効かない」も同じ種類の事故なので、同じ強さで扱う。
"""

from __future__ import annotations

from security_checker.config.loader import load_config
from security_checker.config.schema import Config
from security_checker.config.unimplemented import unimplemented_warnings


def test_nothing_is_reported_for_the_defaults():
    """既定値のままなら警告は出ない (ノイズにしない)."""
    assert unimplemented_warnings(Config(), {}) == []


def test_sarif_format_is_no_longer_reported():
    """P4 で実装した. 実装済みの項目を警告し続けると、警告そのものが信用されなくなる."""
    config = Config.model_validate({"output": {"formats": ["terminal", "json", "sarif"]}})
    assert unimplemented_warnings(config, {}) == []


def test_baseline_is_no_longer_reported():
    config = Config.model_validate({"policy": {"baseline": ".security-checker-baseline.json"}})
    assert unimplemented_warnings(config, {}) == []


def test_diff_mode_is_no_longer_reported():
    diff = Config.model_validate({"target": {"mode": "diff"}})
    assert unimplemented_warnings(diff, {}) == []


def test_github_section_is_no_longer_reported():
    config = Config()
    assert unimplemented_warnings(config, {"github.comment": "file:security-checker.yml"}) == []


def test_logging_section_is_no_longer_reported():
    assert unimplemented_warnings(Config(), {"logging.format": "cli"}) == []


def test_num_ctx_names_the_reviewer():
    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "local",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://localhost:11434",
                    "model": "m",
                    "num_ctx": 16384,
                }
            ]
        }
    )
    messages = unimplemented_warnings(config, {})
    assert any("'local'" in message and "num_ctx" in message for message in messages)


def test_ci_preset_does_not_warn_about_sarif(tmp_path):
    loaded = load_config(tmp_path, preset="ci")
    assert "sarif" in loaded.config.output.formats
    assert not any("sarif" in message for message in loaded.warnings)


def test_plain_config_has_no_warnings(tmp_path):
    loaded = load_config(tmp_path)
    assert loaded.warnings == []
