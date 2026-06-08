"""The audit trail must be complete, ordered, flushed, and replayable."""

from __future__ import annotations

import json
from pathlib import Path

import _bootstrap  # noqa: F401  (side effect: puts src/ on sys.path)
from alertward.audit import AuditLog


def test_records_are_written_and_mirrored(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    with AuditLog(path=log_path) as log:
        log.record("run_start", {"alert_count": 3})
        log.record("incident", {"incident_id": "INC-001"})
        log.record("run_end", {"auto_used": 1})

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["step"] for p in parsed] == ["run_start", "incident", "run_end"]
    assert all("ts" in p for p in parsed)


def test_flush_makes_partial_trail_readable_mid_run(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path)
    log.record("run_start", {"alert_count": 1})
    # No close yet: a crash here should still leave the first line on disk.
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    log.close()


def test_counts_groups_by_step():
    log = AuditLog()
    log.record("incident", {})
    log.record("incident", {})
    log.record("decision", {})
    assert log.counts() == {"incident": 2, "decision": 1}


def test_memory_only_log_needs_no_file():
    log = AuditLog()
    entry = log.record("run_start", {"x": 1})
    assert entry["step"] == "run_start"
    assert log.records == [entry]
