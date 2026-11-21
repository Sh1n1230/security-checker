"""Untrusted scanner metadata must not override structured audit provenance."""
from __future__ import annotations

import io
import json

from security_checker.observability import logging as log


def test_json_audit_core_fields_cannot_be_overridden():
    stream = io.StringIO()
    log.configure(fmt="json", stream=stream)
    log.set_run_id("trusted-run")
    try:
        log.logger.info(
            "scan.complete",
            extra={
                "fields": {
                    "ts": "1999-01-01T00:00:00Z",
                    "event": "forged.event",
                    "run_id": "forged-run",
                    "level": "critical",
                    "detail": "real detail",
                }
            },
        )
        record = json.loads(stream.getvalue())
        assert record["event"] == "scan.complete"
        assert record["run_id"] == "trusted-run"
        assert record["level"] == "info"
        assert record["ts"] != "1999-01-01T00:00:00Z"
        assert record["detail"] == "real detail"
    finally:
        log.disable()
        log.set_run_id(None)


def test_text_audit_core_fields_cannot_be_shadowed():
    stream = io.StringIO()
    log.configure(fmt="text", stream=stream)
    try:
        log.logger.info(
            "scan.complete",
            extra={
                "fields": {"event": "forged", "run_id": "other", "level": "error", "note": "ok"}
            },
        )
        line = stream.getvalue()
        assert "scan.complete" in line
        assert "info " in line
        assert "note=ok" in line
        assert "event=forged" not in line
        assert "run_id=other" not in line
        assert "level=error" not in line
    finally:
        log.disable()
