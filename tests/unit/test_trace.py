"""監査証跡 (設計書 §24.2)."""

from __future__ import annotations

import json
import os
import stat

import pytest

from security_checker.observability.trace import TraceWriter, sha256_text


def test_writes_run_and_calls(tmp_path):
    writer = TraceWriter(tmp_path, "RUN1")
    writer.write_run({"run_id": "RUN1"})
    first = writer.write_call({"candidate_id": "c1"})
    second = writer.write_call({"candidate_id": "c2"})

    assert (tmp_path / "trace" / "RUN1" / "run.json").is_file()
    assert first is not None
    assert second is not None
    assert first.name == "0000.json"
    assert second.name == "0001.json"
    assert json.loads(first.read_text(encoding="utf-8"))["candidate_id"] == "c1"


def test_api_keys_are_masked_in_traces(tmp_path):
    writer = TraceWriter(tmp_path, "RUN1")
    path = writer.write_call({"note": "key is sk-abcdefghijklmnop here"})
    assert path is not None
    assert "sk-abcdefghijklmnop" not in path.read_text(encoding="utf-8")


def test_disabled_writer_writes_nothing(tmp_path):
    writer = TraceWriter(tmp_path, "RUN1", enabled=False)
    assert writer.write_run({}) is None
    assert writer.write_call({}) is None
    assert not (tmp_path / "trace").exists()


def test_sha256_is_stable():
    assert sha256_text("a") == sha256_text("a")
    assert sha256_text("a") != sha256_text("b")


def test_trace_is_readable_only_by_its_owner(tmp_path):
    # トレースは LLM の応答 (コードを引用する) を含む. 同じマシンの他のユーザーに読ませない
    if os.name != "posix":
        pytest.skip("権限ビットは POSIX のみ")
    writer = TraceWriter(tmp_path, "RUN1")
    run = writer.write_run({"run_id": "RUN1"})
    call = writer.write_call({"candidate_id": "c1"})
    assert run is not None
    assert call is not None
    for directory in (tmp_path / "trace", tmp_path / "trace" / "RUN1", call.parent):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700, directory
    for path in (run, call):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    # 出力先そのもの (report.json を置く場所) の権限は変えない
    assert stat.S_IMODE(tmp_path.stat().st_mode) != 0o000


def test_an_existing_loose_trace_directory_is_tightened(tmp_path):
    if os.name != "posix":
        pytest.skip("権限ビットは POSIX のみ")
    loose = tmp_path / "trace" / "RUN1"
    loose.mkdir(parents=True)
    loose.chmod(0o755)
    TraceWriter(tmp_path, "RUN1").write_run({})
    assert stat.S_IMODE(loose.stat().st_mode) == 0o700
