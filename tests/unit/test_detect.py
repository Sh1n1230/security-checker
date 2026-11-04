"""`init` の環境検出 (設計書 §9.8).

検出の材料はプリセットデータと環境変数だけ。コードにコマンド名もベンダー名も現れない。
結果は名前のアルファベット順で、推奨マークなしで並ぶ。
"""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import patch

from security_checker.providers.detect import (
    command_version,
    detect_http,
    detect_process,
)
from security_checker.providers.presets.loader import HttpPreset, ProcessPreset


def test_command_version_reports_a_missing_binary():
    status = command_version("security-checker-no-such-command")
    assert status.available is False
    assert status.reason is not None


def test_command_version_reads_the_version_of_an_existing_binary():
    status = command_version(sys.executable)
    assert status.available is True
    assert status.version is not None


def test_command_version_handles_subprocess_failure():
    """Version check that raises SubprocessError returns available=True with a failure reason.

    Covers the exception handler in command_version (previously untested lines).
    """
    with (
        patch("security_checker.providers.detect.shutil.which", return_value="/fake/bin/cmd"),
        patch(
            "security_checker.providers.detect.subprocess.run",
            side_effect=subprocess.SubprocessError("simulated failure"),
        ),
    ):
        status = command_version("cmd")

    assert status.available is True
    assert status.version is None
    assert status.reason is not None
    assert "バージョン取得に失敗しました" in status.reason


def test_process_detection_is_driven_by_preset_data():
    presets = {
        "b-missing": ProcessPreset(name="b-missing", command=["no-such-command-xyz"]),
        "a-present": ProcessPreset(name="a-present", command=[sys.executable]),
    }
    found = detect_process(presets)
    assert [item.name for item in found] == ["a-present", "b-missing"]
    assert [item.available for item in found] == [True, False]
    assert found[0].config == {"name": "a-present", "transport": "process", "preset": "a-present"}


def test_http_detection_looks_at_the_declared_environment_variable():
    presets = {
        "set": HttpPreset(name="set", dialect="openai_chat", api_key_env="SC_SET"),
        "unset": HttpPreset(name="unset", dialect="openai_chat", api_key_env="SC_UNSET"),
    }
    found = detect_http(presets, environ={"SC_SET": "value"})
    by_name = {item.name: item for item in found}
    assert by_name["set"].available is True
    assert by_name["unset"].available is False


def test_local_endpoints_need_no_credentials():
    presets = {
        "local": HttpPreset(name="local", dialect="ollama_chat", base_url="http://localhost:11434"),
        "remote": HttpPreset(name="remote", dialect="openai_chat", base_url="https://example/v1"),
    }
    found = {item.name: item for item in detect_http(presets, environ={})}
    assert found["local"].available is True
    assert found["remote"].available is False


def test_nothing_is_detected_without_presets():
    """既定設定に Reviewer は 1 つも入っていない (§9.8). 検出も同様に空で始まる."""
    assert detect_process({}) == []
    assert detect_http({}, environ={}) == []
