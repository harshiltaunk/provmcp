"""Append-only audit log of inspection decisions.

One JSON object per line (JSONL). Every inspected `tools/call` that produced
findings, and every call that was held or blocked, is recorded with a UTC
timestamp. The format is meant to be both human-greppable and trivially
loadable for the evaluation chapter of the report.

Several bridge processes may append to the same file. Each event is written
with a single `write` call on a file opened in append mode, which POSIX keeps
atomic for lines this short, so concurrent writers do not interleave.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    """Write decision events to a JSONL file, or keep them in memory."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._memory: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        """Stamp the event with the current time and persist it."""
        stamped = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}
        if self.path is None:
            self._memory.append(stamped)
            return stamped
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(stamped, ensure_ascii=False, default=str) + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return stamped

    def read(self, last: int | None = None) -> list[dict[str, Any]]:
        """Return recorded events, oldest first, optionally only the last N."""
        if self.path is None:
            events = list(self._memory)
        elif not self.path.exists():
            events = []
        else:
            events = [
                json.loads(line)
                for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        return events[-last:] if last else events
