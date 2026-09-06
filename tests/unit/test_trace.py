"""監査証跡 (設計書 §24.2)."""

from __future__ import annotations

import json

from security_checker.observability.trace import TraceWriter, sha256_text


def test_writes_run_and_calls(tmp_path):
    writer = TraceWriter(tmp_path, "RUN1")
    writer.write_run({"run_id": "RUN1"})
    first = writer.write_call({"candidate_id": "c1"})
    second = writer.write_call({"candidate_id": "c2"})

    assert (tmp_path / "trace" / "RUN1" / "run.json").is_file()
    assert first is not None and second is not None
    assert first.name == "0000.json"
    assert second.name == "0001.json"
    assert json.loads(first.read_text())["candidate_id"] == "c1"


def test_api_keys_are_masked_in_traces(tmp_path):
    writer = TraceWriter(tmp_path, "RUN1")
    path = writer.write_call({"note": "key is sk-abcdefghijklmnop here"})
    assert path is not None
    assert "sk-abcdefghijklmnop" not in path.read_text()


def test_disabled_writer_writes_nothing(tmp_path):
    writer = TraceWriter(tmp_path, "RUN1", enabled=False)
    assert writer.write_run({}) is None
    assert writer.write_call({}) is None
    assert not (tmp_path / "trace").exists()


def test_sha256_is_stable():
    assert sha256_text("a") == sha256_text("a")
    assert sha256_text("a") != sha256_text("b")
