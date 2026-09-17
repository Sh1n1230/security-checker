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


def test_sarif_format_is_reported():
    config = Config.model_validate({"output": {"formats": ["terminal", "json", "sarif"]}})
    messages = unimplemented_warnings(config, {})
    assert len(messages) == 1
    assert "sarif" in messages[0]
    # 何が起きないかを書く。「未実装」だけでは次の行動が決まらない
    assert "Code Scanning" in messages[0]


def test_baseline_is_reported():
    config = Config.model_validate({"policy": {"baseline": ".security-checker-baseline.json"}})
    assert any("baseline" in message for message in unimplemented_warnings(config, {}))


def test_diff_mode_is_reported_but_auto_is_not():
    diff = Config.model_validate({"target": {"mode": "diff"}})
    assert any("diff" in message for message in unimplemented_warnings(diff, {}))
    # auto は「自動で決める」であり、現状の最善が全件スキャンなので警告しない
    auto = Config.model_validate({"target": {"mode": "auto"}})
    assert unimplemented_warnings(auto, {}) == []


def test_github_section_is_reported_only_when_the_user_set_it():
    config = Config()
    assert unimplemented_warnings(config, {"github.comment": "default"}) == []
    messages = unimplemented_warnings(config, {"github.comment": "file:security-checker.yml"})
    assert any("github" in message for message in messages)


def test_logging_section_is_reported_only_when_the_user_set_it():
    config = Config()
    assert unimplemented_warnings(config, {"logging.format": "default"}) == []
    assert unimplemented_warnings(config, {"logging.format": "cli"})


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


def test_ci_preset_warns_about_sarif(tmp_path):
    """--preset ci は sarif を要求する. 黙って出力されないままにしない."""
    loaded = load_config(tmp_path, preset="ci")
    assert "sarif" in loaded.config.output.formats
    assert any("sarif" in message for message in loaded.warnings)


def test_plain_config_has_no_warnings(tmp_path):
    loaded = load_config(tmp_path)
    assert loaded.warnings == []
