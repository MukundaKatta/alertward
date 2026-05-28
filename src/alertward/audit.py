"""Append-only JSONL audit trail.

Every step of a triage run is written as one JSON object on its own line and
flushed immediately, so the trail survives a crash mid-run and the whole run
can be replayed and graded after the fact. Records are written in the order
they happen; nothing rewrites earlier lines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Literal

StepType = Literal[
    "run_start",
    "incident",
    "proposal",
    "decision",
    "execution",
    "report",
    "run_end",
]


@dataclass
class AuditLog:
    """Writes audit records to a file and keeps an in-memory mirror."""

    path: Path | None = None
    records: list[dict[str, object]] = field(default_factory=list)
    _fh: IO[str] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = Path(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("w", encoding="utf-8")

    def record(self, step: StepType, payload: dict[str, object]) -> dict[str, object]:
        entry: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "step": step,
            **payload,
        }
        self.records.append(entry)
        if self._fh is not None:
            self._fh.write(json.dumps(entry, sort_keys=True) + "\n")
            self._fh.flush()
        return entry

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for entry in self.records:
            step = str(entry["step"])
            out[step] = out.get(step, 0) + 1
        return out

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
