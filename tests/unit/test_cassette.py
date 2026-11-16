"""record / replay (設計書 §25.3)."""

from __future__ import annotations

import json

import pytest

from security_checker.providers.base import CompletionRequest
from security_checker.providers.check import probe_task
from security_checker.review.reviewer import Reviewer
from security_checker.testing import (
    CassetteMissError,
    CassetteProvider,
    ScriptedProvider,
    verdict_payload,
)


async def test_record_then_replay_without_the_real_provider(tmp_path):
    path = tmp_path / "cassette.json"
    inner = ScriptedProvider([verdict_payload(reasoning="記録した応答")])
    recorded = await Reviewer("r", CassetteProvider(path, inner=inner, record=True)).review(
        probe_task()
    )

    # 再生: 元の Provider 無しで同じ判定が得られる
    replay = CassetteProvider(path, model=inner.model)
    replayed = await Reviewer("r", replay).review(probe_task())
    assert replayed.verdict.reasoning == recorded.verdict.reasoning == "記録した応答"


async def test_replay_miss_is_loud(tmp_path):
    path = tmp_path / "cassette.json"
    path.write_text(json.dumps({"version": 1, "entries": {}}), encoding="utf-8")
    with pytest.raises(CassetteMissError, match="--record"):
        await CassetteProvider(path).complete(CompletionRequest(system="s", user="u"))


async def test_recorded_cassette_is_masked(tmp_path):
    path = tmp_path / "cassette.json"
    secret = "sk-" + "B" * 40
    inner = ScriptedProvider([f"key {secret}"])
    await CassetteProvider(path, inner=inner, record=True).complete(
        CompletionRequest(system="s", user="u")
    )
    assert secret not in path.read_text(encoding="utf-8")


def test_recording_requires_a_real_provider(tmp_path):
    with pytest.raises(ValueError):
        CassetteProvider(tmp_path / "c.json", record=True)


def test_cassette_of_another_version_is_refused(tmp_path):
    path = tmp_path / "old.json"
    path.write_text('{"version": -1, "entries": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="カセットの版が違います"):
        CassetteProvider(path)


async def test_replay_is_healthy_without_a_provider_and_close_is_a_no_op(tmp_path):
    provider = CassetteProvider(tmp_path / "c.json")
    health = await provider.health_check()
    assert (health.ok, health.detail) == (True, "cassette")
    await provider.aclose()


async def test_recording_delegates_health_and_close_to_the_real_provider(tmp_path):
    inner = ScriptedProvider([])
    provider = CassetteProvider(tmp_path / "c.json", inner=inner, record=True)
    assert (await provider.health_check()).ok is True
    await provider.aclose()
    assert inner.closed is True


async def test_scripted_provider_fails_loudly_when_the_script_runs_out():
    provider = ScriptedProvider([])
    with pytest.raises(AssertionError, match="応答が尽きました"):
        await provider.complete(CompletionRequest(system="s", user="u", json_schema={}))
