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
    path.write_text(json.dumps({"version": 1, "entries": {}}))
    with pytest.raises(CassetteMissError, match="--record"):
        await CassetteProvider(path).complete(CompletionRequest(system="s", user="u"))


async def test_recorded_cassette_is_masked(tmp_path):
    path = tmp_path / "cassette.json"
    secret = "sk-" + "B" * 40
    inner = ScriptedProvider([f"key {secret}"])
    await CassetteProvider(path, inner=inner, record=True).complete(
        CompletionRequest(system="s", user="u")
    )
    assert secret not in path.read_text()


def test_recording_requires_a_real_provider(tmp_path):
    with pytest.raises(ValueError):
        CassetteProvider(tmp_path / "c.json", record=True)
