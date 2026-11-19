"""Provider まわりの境界: 方言の応答の揺れ・プリセットの不備・疎通確認の案内 (設計書 §9・§20.2)."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any

import httpx
import pytest
import respx

from security_checker.config.schema import ReviewerConfig
from security_checker.errors import ConfigError
from security_checker.providers import check, detect, registry
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderBadRequestError,
    ProviderError,
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderTimeoutError,
)
from security_checker.providers.http.dialects import gemini_generate
from security_checker.providers.http.dialects.anthropic_messages import AnthropicMessagesDialect
from security_checker.providers.http.dialects.gemini_generate import GeminiGenerateDialect
from security_checker.providers.http.dialects.ollama_chat import OllamaChatDialect
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect
from security_checker.providers.http.transport import HttpProvider, _retry_after
from security_checker.providers.presets.loader import (
    HttpPreset,
    PresetMatch,
    ProcessPreset,
    load_http_presets,
    resolve_http_preset,
)
from security_checker.providers.process import runner, sandbox
from security_checker.testing import ScriptedProvider

BASE_URL = "http://endpoint.test/v1"


def http_reviewer(**overrides: Any) -> ReviewerConfig:
    payload: dict[str, Any] = {
        "name": "r1",
        "transport": "http",
        "dialect": "openai_chat",
        "base_url": BASE_URL,
        "model": "m",
        "timeout_s": 12,
    }
    payload.update(overrides)
    return ReviewerConfig(**payload)


def request(**overrides: Any) -> CompletionRequest:
    payload: dict[str, Any] = {"system": "s", "user": "u", "json_schema": {"type": "object"}}
    payload.update(overrides)
    return CompletionRequest(**payload)


# --- 方言: 応答の揺れ -------------------------------------------------------------


def test_openai_null_content_is_an_empty_text():
    parsed = OpenAIChatDialect().parse_response({"choices": [{"message": {"content": None}}]})
    assert parsed.text == ""


def test_ollama_null_content_is_empty_and_other_types_are_rejected():
    dialect = OllamaChatDialect()
    assert dialect.parse_response({"message": {"content": None}}).text == ""
    with pytest.raises(ProviderResponseError, match="文字列ではありません"):
        dialect.parse_response({"message": {"content": ["a"]}})


def test_anthropic_skips_content_blocks_that_are_not_objects():
    parsed = AnthropicMessagesDialect().parse_response(
        {"content": ["stray", {"type": "text", "text": "ok"}]}
    )
    assert parsed.text == "ok"


def test_gemini_candidate_that_is_not_an_object_is_rejected():
    with pytest.raises(
        ProviderResponseError, match=r"candidates\[0\] がオブジェクトではありません"
    ):
        GeminiGenerateDialect().parse_response({"candidates": ["text"]})


def test_gemini_without_candidates_or_feedback_says_so():
    with pytest.raises(ProviderResponseError, match="応答に candidates がありません"):
        GeminiGenerateDialect().parse_response({})


def test_gemini_sends_the_seed_and_folds_system_into_user_when_unsupported():
    payload = GeminiGenerateDialect().build_payload(
        request(seed=7),
        model="m",
        capabilities=Capabilities(supports_seed=True, supports_system_role=False),
        mode=StructuredMode.PROMPT_ONLY,
    )
    assert payload["generationConfig"]["seed"] == 7
    assert "systemInstruction" not in payload
    assert payload["contents"] == [{"role": "user", "parts": [{"text": "s\n\nu"}]}]


def test_gemini_schema_rejection_suggests_json_mode():
    hint = GeminiGenerateDialect().explain_error(400, "Invalid responseSchema: too deep")
    assert hint is not None
    assert "json_mode" in hint


def test_gemini_schema_conversion_of_degenerate_nodes():
    convert = gemini_generate._convert
    assert convert("not a schema", defs={}) == {}
    assert convert({"anyOf": [{"type": "null"}]}, defs={}) == {"type": "STRING", "nullable": True}
    assert convert({"type": ["null"]}, defs={}) == {"type": "STRING", "nullable": True}
    described = convert(
        {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "補足"}, defs={}
    )
    assert described == {"type": "STRING", "nullable": True, "description": "補足"}


@pytest.mark.parametrize(
    "dialect", [AnthropicMessagesDialect(), GeminiGenerateDialect(), OllamaChatDialect()]
)
def test_health_payload_asks_for_a_single_token(dialect):
    payload = dialect.health_payload("m", Capabilities())
    limits = [
        payload.get("max_tokens"),
        payload.get("generationConfig", {}).get("maxOutputTokens"),
        payload.get("options", {}).get("num_predict"),
    ]
    assert "ping" in str(payload)
    assert [limit for limit in limits if limit is not None] == [1]


@pytest.mark.parametrize("dialect", [AnthropicMessagesDialect(), OllamaChatDialect()])
def test_dialects_without_a_body_level_auth_error(dialect):
    assert dialect.is_auth_error(400, "API key not valid") is False


# --- http transport ---------------------------------------------------------------


@respx.mock
async def test_json_array_response_is_a_response_error():
    respx.post(f"{BASE_URL}/chat/completions").mock(return_value=httpx.Response(200, json=[1]))
    provider = HttpProvider(
        name="r1",
        dialect=OpenAIChatDialect(),
        base_url=BASE_URL,
        model="m",
        capabilities=Capabilities(),
        client=httpx.AsyncClient(),
    )
    with pytest.raises(ProviderResponseError, match="トップレベルがオブジェクトではありません"):
        await provider.complete(request(timeout_s=5.0))
    await provider.aclose()


def test_retry_after_http_date_without_a_timezone_is_read_as_utc():
    when = datetime.now(UTC) + timedelta(seconds=90)
    naive = format_datetime(when.replace(tzinfo=None))  # "... -0000": 時差の情報なし
    seconds = _retry_after(httpx.Response(429, headers={"retry-after": naive}))
    assert seconds is not None
    assert 80 <= seconds <= 90


# --- プリセット -------------------------------------------------------------------


def test_preset_model_pattern_must_match():
    match = PresetMatch(host="endpoint.test", model="^gpt-")
    assert match.matches(BASE_URL, "gpt-x") is True
    assert match.matches(BASE_URL, "other") is False


@pytest.mark.parametrize(
    ("body", "message"),
    [("dialect: [unclosed\n", "読み込めません"), ("- a\n", "トップレベルはマッピング")],
)
def test_broken_user_preset_is_a_config_error(tmp_path, body, message):
    directory = tmp_path / "http"
    directory.mkdir()
    (directory / "mine.yml").write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_http_presets(user_dir=directory)


def test_no_preset_is_resolved_without_a_name_or_a_url_and_model():
    presets = {"p": HttpPreset(name="p", dialect="openai_chat", match=PresetMatch(model="^m$"))}
    assert resolve_http_preset(presets, name=None, base_url=None, model="m") is None
    assert resolve_http_preset(presets, name=None, base_url=BASE_URL, model=None) is None


def test_preset_with_invalid_capabilities_is_a_config_error():
    preset = HttpPreset(
        name="bad", dialect="openai_chat", capabilities={"structured_output": "telepathy"}
    )
    with pytest.raises(ConfigError, match="プリセット 'bad' の capabilities が不正です"):
        registry.resolve_capabilities(http_reviewer(), preset)


def test_preset_without_a_base_url_cannot_be_resolved_on_its_own():
    presets = {"p": HttpPreset(name="p", dialect="openai_chat")}
    reviewer = http_reviewer(preset="p", dialect=None, base_url=None)
    with pytest.raises(ConfigError, match="dialect / base_url / model を解決できません"):
        registry.build_http_provider(reviewer, presets=presets)


class _Entry:
    def __init__(self, name: str, loaded: Any) -> None:
        self.name = name
        self._loaded = loaded

    def load(self) -> Any:
        if isinstance(self._loaded, Exception):
            raise self._loaded
        return self._loaded


# --- 自作 Provider (transport: plugin) ----------------------------------------------


def plugin_reviewer(plugin: str = "mine") -> ReviewerConfig:
    return ReviewerConfig(name="p1", transport="plugin", plugin=plugin, model="m")


def test_a_configured_plugin_builds_the_provider_from_the_reviewer_config():
    built: list[ReviewerConfig] = []

    def factory(reviewer: ReviewerConfig) -> ScriptedProvider:
        built.append(reviewer)
        return ScriptedProvider([])

    entries: dict[str, Any] = {"mine": _Entry("mine", factory)}
    provider = registry.build_provider(plugin_reviewer(), plugins=entries)
    assert isinstance(provider, ScriptedProvider)
    assert built[0].model == "m"


def test_installed_plugins_are_listed_without_being_loaded(monkeypatch):
    # 依存に入っただけのパッケージを import しない. 読み込むのは設定に書いたものだけ
    entries = [_Entry("unused", AssertionError("読み込まれた"))]
    monkeypatch.setattr(registry, "entry_points", lambda group: entries)
    assert sorted(registry.discover_plugin_providers()) == ["unused"]


def test_an_unregistered_plugin_name_is_a_config_error_listing_what_exists():
    entries: dict[str, Any] = {"other": _Entry("other", ScriptedProvider)}
    with pytest.raises(ConfigError, match=r"plugin 'mine' は .*登録済み: other"):
        registry.build_provider(plugin_reviewer(), plugins=entries)


def test_a_plugin_that_fails_to_load_is_a_config_error_with_the_cause():
    entries: dict[str, Any] = {"mine": _Entry("mine", ImportError("missing dep"))}
    with pytest.raises(
        ConfigError, match=r"plugin 'mine' を読み込めません \(ImportError\): missing"
    ):
        registry.build_provider(plugin_reviewer(), plugins=entries)


def test_a_plugin_that_raises_a_config_error_keeps_its_own_message():
    """プラグインが自分で出した設定エラーは包み直さない (原因の文がそのまま利用者に届く) (#557)."""

    def factory(reviewer: ReviewerConfig) -> ScriptedProvider:
        raise ConfigError("mine: api_key が必要です")

    entries: dict[str, Any] = {"mine": _Entry("mine", factory)}
    with pytest.raises(ConfigError, match=r"^mine: api_key が必要です$"):
        registry.build_provider(plugin_reviewer(), plugins=entries)


def test_a_process_preset_without_a_command_is_a_config_error():
    """command を解決できないプリセット (空の command) は黙って起動しない (#557)."""
    reviewer = ReviewerConfig(name="p1", transport="process", preset="empty")
    presets = {"empty": ProcessPreset(name="empty", command=[])}
    with pytest.raises(ConfigError, match="command を解決できません"):
        registry.build_process_provider(reviewer, presets=presets)


def test_plugin_name_and_transport_must_come_together():
    with pytest.raises(ValueError, match="transport: plugin のときに"):
        ReviewerConfig(name="p1", transport="plugin")
    with pytest.raises(ValueError, match="transport: plugin のときに"):
        http_reviewer(plugin="mine")


# --- 検出 -------------------------------------------------------------------------


def test_command_version_failure_keeps_the_command_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/fake/bin/cmd")

    def boom(*args: Any, **kwargs: Any) -> None:
        raise subprocess.SubprocessError("simulated failure")

    monkeypatch.setattr("subprocess.run", boom)
    status = detect.command_version("cmd")
    assert status.available is True
    assert status.version is None
    assert "バージョン取得に失敗しました" in (status.reason or "")


def test_detect_all_lists_process_before_http(monkeypatch):
    process: list[Any] = ["p1", "p2"]
    http: list[Any] = ["h1"]
    monkeypatch.setattr(detect, "detect_process", lambda: process)
    monkeypatch.setattr(detect, "detect_http", lambda environ=None: http)
    assert detect.detect_all(environ={}) == [*process, *http]


def test_a_missing_base_url_is_not_local():
    assert detect._is_local(None) is False
    assert detect._is_local("http://localhost:11434") is True


# --- providers check の案内 -------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderAuthError("401"), "認証に失敗しました。KEY_ENV の値"),
        (ProviderRateLimitError("429"), "rate_limit.rpm を下げる"),
        (ProviderTimeoutError("timeout"), "timeout_s (現在 12) を延ばしてください"),
        (ProviderBadRequestError("400"), "structured_output: prompt_only"),
        (ProviderError("down"), f"base_url ({BASE_URL}) に到達できるか"),
    ],
)
def test_suggestion_names_the_next_action(error, expected):
    assert expected in check._suggest(error, http_reviewer(api_key_env="KEY_ENV"))


def test_suggestion_for_a_process_reviewer_points_at_the_command():
    reviewer = ReviewerConfig(name="p", transport="process", command=["tool"])
    assert "command が非対話で JSON を標準出力に返すか" in check._suggest(
        ProviderError("exit 1"), reviewer
    )


@respx.mock
async def test_check_reports_a_failed_call_with_a_suggestion():
    # 疎通 (max_tokens 1) は通るが、本番の呼び出しで 401 になる
    respx.post(f"{BASE_URL}/chat/completions").mock(
        side_effect=[
            httpx.Response(200, json={"choices": [{"message": {"content": "pong"}}]}),
            httpx.Response(401, text="invalid key"),
        ]
    )
    result = await check.check_reviewer(http_reviewer(), environ={})
    assert result.ok is False
    assert (result.steps[-1].label, result.steps[-1].ok) == ("呼び出し", False)
    assert any("認証に失敗しました" in suggestion for suggestion in result.suggestions)


# --- process transport ------------------------------------------------------------


def test_long_stderr_is_collapsed_and_truncated():
    text = "error line\n" * 1000
    shown = runner._excerpt(text)
    assert "\n" not in shown
    assert shown.endswith(" …(truncated)")
    assert len(shown) == runner.STDERR_EXCERPT_LIMIT + len(" …(truncated)")


def test_created_paths_are_capped(tmp_path):
    for index in range(sandbox.CREATED_PATHS_LIMIT + 5):
        (tmp_path / f"f{index:02}").write_text("", encoding="utf-8")
    found = sandbox.created_paths(tmp_path)
    assert len(found) == sandbox.CREATED_PATHS_LIMIT
    assert found[0] == "f00"


async def test_capped_communicate_requires_pipes():
    class NoPipes:
        stdin = stdout = stderr = None

    with pytest.raises(RuntimeError, match="PIPE"):
        await sandbox._communicate_capped(NoPipes(), b"")  # type: ignore[arg-type]
