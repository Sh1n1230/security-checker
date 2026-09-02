"""設定の合成順序と検証のテスト (設計書 §12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_checker.config.loader import available_presets, env_overrides, load_config
from security_checker.errors import ConfigError
from security_checker.models.enums import Severity


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "security-checker.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_without_config_file(tmp_path):
    loaded = load_config(tmp_path, environ={})
    assert loaded.config.policy.fail_on is Severity.HIGH
    assert loaded.config.scanners.semgrep.enabled is True
    assert loaded.config_path is None


def test_config_file_is_discovered(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_on: critical\n")
    loaded = load_config(tmp_path, environ={})
    assert loaded.config.policy.fail_on is Severity.CRITICAL
    assert loaded.origins["policy.fail_on"].startswith("file:")


def test_merge_order_cli_wins_over_env_and_file(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_on: critical\n  min_confidence: 0.9\n")
    loaded = load_config(
        tmp_path,
        environ={"SECURITY_CHECKER__POLICY__FAIL_ON": "medium"},
        cli_overrides={"policy": {"fail_on": "low"}},
    )
    assert loaded.config.policy.fail_on is Severity.LOW
    assert loaded.config.policy.min_confidence == 0.9  # 上書きされていない値は保持
    assert loaded.origins["policy.fail_on"] == "cli"


def test_env_overrides_parse_scalars():
    overrides = env_overrides(
        {
            "SECURITY_CHECKER__POLICY__STRICT": "false",
            "SECURITY_CHECKER__CONCURRENCY__SCANNERS": "8",
            "UNRELATED": "x",
        }
    )
    assert overrides == {"policy": {"strict": False}, "concurrency": {"scanners": 8}}


def test_preset_is_applied_then_overridden_by_file(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  strict: true\n")
    loaded = load_config(tmp_path, preset="minimal", environ={})
    assert loaded.config.policy.fail_on is Severity.CRITICAL  # preset 由来
    assert loaded.config.policy.strict is True  # ファイルが後勝ち
    assert loaded.config.scanners.osv.enabled is False


def test_all_presets_are_valid(tmp_path):
    assert set(available_presets()) == {"ci", "frugal", "minimal", "thorough"}
    for preset in available_presets():
        load_config(tmp_path, preset=preset, environ={})


def test_unknown_preset(tmp_path):
    with pytest.raises(ConfigError, match="preset"):
        load_config(tmp_path, preset="存在しない", environ={})


def test_plaintext_api_key_is_rejected(tmp_path):
    write_config(
        tmp_path,
        "version: 1\nreviewers:\n  - name: r1\n    transport: http\n"
        "    dialect: openai_chat\n    base_url: http://x/v1\n    model: m\n"
        "    api_key: TESTONLY-secret\n",
    )
    with pytest.raises(ConfigError, match="api_key_env"):
        load_config(tmp_path, environ={})


def test_unknown_key_is_rejected(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_onn: high\n")
    with pytest.raises(ConfigError, match="fail_onn"):
        load_config(tmp_path, environ={})


def test_broken_yaml_is_config_error(tmp_path):
    write_config(tmp_path, "version: 1\npolicy: [\n")
    with pytest.raises(ConfigError, match="YAML"):
        load_config(tmp_path, environ={})


def test_transport_is_required(tmp_path):
    write_config(tmp_path, "version: 1\nreviewers:\n  - name: r1\n    model: m\n")
    with pytest.raises(ConfigError, match="transport"):
        load_config(tmp_path, environ={})


def test_http_reviewer_requires_endpoint_fields(tmp_path):
    write_config(tmp_path, "version: 1\nreviewers:\n  - name: r1\n    transport: http\n")
    with pytest.raises(ConfigError, match="dialect"):
        load_config(tmp_path, environ={})


def test_process_reviewer_requires_preset_or_command(tmp_path):
    write_config(tmp_path, "version: 1\nreviewers:\n  - name: r1\n    transport: process\n")
    with pytest.raises(ConfigError, match="preset"):
        load_config(tmp_path, environ={})


def test_duplicate_reviewer_names(tmp_path):
    write_config(
        tmp_path,
        "version: 1\nreviewers:\n"
        "  - { name: r1, transport: process, command: [echo] }\n"
        "  - { name: r1, transport: process, command: [echo] }\n",
    )
    with pytest.raises(ConfigError, match="重複"):
        load_config(tmp_path, environ={})


def test_judge_reviewer_must_exist(tmp_path):
    write_config(
        tmp_path,
        "version: 1\nreviewers:\n  - { name: r1, transport: process, command: [echo] }\n"
        "aggregation:\n  strategy: judge\n  judge:\n    reviewer: missing\n",
    )
    with pytest.raises(ConfigError, match="judge"):
        load_config(tmp_path, environ={})


def test_explicit_config_path_must_exist(tmp_path):
    with pytest.raises(ConfigError, match="見つかりません"):
        load_config(tmp_path, config_path=tmp_path / "nope.yml", environ={})
