"""ProcessProvider の応答変換とエラー正規化 (設計書 §9.2, §9.7).

サンドボックスは差し替えて、Provider の責務だけを見る。
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import (
    ProviderError,
    ProviderResponseError,
    ProviderServerError,
    ProviderTimeoutError,
)
from security_checker.providers.process.runner import ProcessProvider
from security_checker.providers.process.sandbox import SandboxResult


def sandbox(**overrides: Any) -> SandboxResult:
    payload: dict[str, Any] = {
        "exit_code": 0,
        "stdout": '{"vulnerable": false}',
        "stderr": "",
        "argv": ("cmd",),
    }
    payload.update(overrides)
    return SandboxResult(**payload)


def provider(result: SandboxResult | Exception, **overrides: Any) -> ProcessProvider:
    calls: list[dict[str, Any]] = []

    async def runner(command: Any, **kwargs: Any) -> SandboxResult:
        calls.append({"command": command, **kwargs})
        if isinstance(result, Exception):
            raise result
        return result

    built = ProcessProvider(
        name="p1",
        command=["cmd", "--non-interactive"],
        capabilities=Capabilities(),
        runner=runner,
        **overrides,
    )
    built.calls = calls  # type: ignore[attr-defined]
    return built


def request(**overrides: Any) -> CompletionRequest:
    payload: dict[str, Any] = {"system": "S", "user": "U", "timeout_s": 30.0}
    payload.update(overrides)
    return CompletionRequest(**payload)


def test_identity_is_transport_process_with_text_io_dialect():
    assert provider(sandbox()).transport == "process"
    assert provider(sandbox()).dialect == "text_io"


def test_capabilities_are_clamped_to_prompt_only():
    """スキーマ強制も system ロールも seed も、契約上「あることにできない」(§9.7)."""
    built = ProcessProvider(
        name="p1",
        command=["cmd"],
        capabilities=Capabilities(
            structured_output=StructuredMode.JSON_SCHEMA,
            supports_system_role=True,
            supports_seed=True,
        ),
    )
    assert built.capabilities.structured_output is StructuredMode.PROMPT_ONLY
    assert built.capabilities.supports_system_role is False
    assert built.capabilities.supports_seed is False


async def test_system_and_user_are_folded_into_one_prompt():
    built = provider(sandbox())
    await built.complete(request())
    sent = built.calls[0]["prompt"]  # type: ignore[attr-defined]
    assert sent.startswith("S")
    assert sent.endswith("U")


async def test_json_is_extracted_from_prose_wrapped_stdout():
    """散文が混ざっても抽出する. json_schema が使えない代償を抽出で払う (§10.2)."""
    noisy = 'ここに結果です:\n```json\n{"vulnerable": true}\n```\nご確認ください。'
    response = await provider(sandbox(stdout=noisy)).complete(request())
    assert response.parsed == {"vulnerable": True}


async def test_usage_is_estimated_and_marked_unknown_cost():
    response = await provider(sandbox()).complete(request())
    assert response.usage.input_tokens > 0
    assert response.usage.cost_known is False
    assert response.usage.estimated_usd is None


async def test_trace_carries_argv_version_stderr_and_exit_code():
    """§9.7 の監査証跡. params に argv とバージョン、response に stderr と exit code."""
    result = sandbox(argv=("cmd", "--non-interactive"), stderr="warm-up\n")
    response = await provider(result, version="cmd 1.2.3").complete(request())
    assert response.trace_params["argv"] == ["cmd", "--non-interactive"]
    assert response.trace_params["version"] == "cmd 1.2.3"
    assert response.trace_response["stderr"] == "warm-up"
    assert response.trace_response["exit_code"] == 0


async def test_write_detection_becomes_a_warning():
    result = sandbox(created_paths=("notes.md",))
    response = await provider(result).complete(request())
    assert any("notes.md" in warning for warning in response.warnings)


async def test_timeout_is_normalized():
    with pytest.raises(ProviderTimeoutError):
        await provider(sandbox(timed_out=True, exit_code=None)).complete(request())


async def test_nonzero_exit_is_retryable_server_error():
    with pytest.raises(ProviderServerError) as raised:
        await provider(sandbox(exit_code=2, stderr="unknown flag")).complete(request())
    assert raised.value.retryable is True
    assert "unknown flag" in str(raised.value)


async def test_empty_stdout_is_a_response_error():
    with pytest.raises(ProviderResponseError, match="stdout が空"):
        await provider(sandbox(stdout="   \n")).complete(request())


async def test_missing_command_is_a_provider_error_with_a_hint():
    with pytest.raises(ProviderError, match="コマンドが見つかりません"):
        await provider(FileNotFoundError("no such file")).complete(request())


async def test_aclose_is_a_noop():
    built = provider(sandbox())
    await built.aclose()
    await built.aclose()


async def test_health_check_reports_a_missing_command():
    built = ProcessProvider(
        name="p1", command=["security-checker-no-such-command"], capabilities=Capabilities()
    )
    status = await built.health_check()
    assert status.ok is False
    assert status.detail is not None


async def test_health_check_reports_the_version_of_an_existing_command():
    built = ProcessProvider(name="p1", command=[sys.executable], capabilities=Capabilities())
    status = await built.health_check()
    assert status.ok is True


async def test_health_check_rejects_an_empty_command():
    built = ProcessProvider(name="p1", command=[], capabilities=Capabilities())
    assert (await built.health_check()).ok is False


async def test_launch_failure_is_a_provider_error():
    with pytest.raises(ProviderError, match="起動できません"):
        await provider(PermissionError("denied")).complete(request())
