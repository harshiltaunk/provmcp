"""Out-of-band approvals for calls held under the warn-and-confirm policy.

When a `tools/call` is held, ProvMCP records a pending approval keyed by a
fingerprint of the exact call (target server, tool name, arguments). The user
approves or denies it from a terminal with `provmcp approvals ...`. When the
host retries the identical call, the proxy consumes the approval and lets the
call through once. A second identical call needs a fresh approval.

Why out-of-band: if approval happened inside the conversation, injected text
could simply tell the LLM to approve its own call. The approval channel is
therefore a file the LLM cannot write through MCP, plus a CLI that refuses to
run without an interactive terminal.

The store is a JSON file so that the daemon, every bridge process, and the CLI
share one view. Writes go to a temporary file followed by an atomic rename,
so a reader never sees a half-written file.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

Status = Literal["pending", "approved", "denied", "used", "expired"]


class Approval(BaseModel):
    id: str
    fingerprint: str
    target: str
    tool: str
    summary: str
    created_at: float
    status: Status = "pending"
    decided_at: float | None = None


def fingerprint_call(target: str, params: dict[str, Any]) -> str:
    """Stable fingerprint of one exact tool call."""
    canonical = json.dumps(
        {"target": target, "tool": params.get("name"), "arguments": params.get("arguments")},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


class ApprovalStore:
    """Pending and decided approvals, in a JSON file or in memory."""

    def __init__(self, path: str | Path | None = None, *, ttl_seconds: float = 600.0) -> None:
        self.path = Path(path) if path is not None else None
        self.ttl_seconds = ttl_seconds
        self._memory: dict[str, Approval] = {}

    # --- persistence --------------------------------------------------------

    def _load(self) -> dict[str, Approval]:
        if self.path is None:
            return self._memory
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        return {key: Approval.model_validate(value) for key, value in raw.items()}

    def _save(self, items: dict[str, Approval]) -> None:
        if self.path is None:
            self._memory = items
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({k: v.model_dump() for k, v in items.items()}, indent=2)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".approvals-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(tmp, self.path)

    def _expire(self, items: dict[str, Approval]) -> bool:
        now = time.time()
        changed = False
        for item in items.values():
            if item.status in ("pending", "approved") and now - item.created_at > self.ttl_seconds:
                item.status = "expired"
                item.decided_at = now
                changed = True
        return changed

    def _snapshot(self) -> dict[str, Approval]:
        items = self._load()
        if self._expire(items):
            self._save(items)
        return items

    # --- proxy side ---------------------------------------------------------

    def request(self, *, fingerprint: str, target: str, tool: str, summary: str) -> Approval:
        """Return the live pending approval for this call, creating one if needed."""
        items = self._snapshot()
        for item in items.values():
            if item.fingerprint == fingerprint and item.status == "pending":
                return item
        approval = Approval(
            id=uuid.uuid4().hex[:8],
            fingerprint=fingerprint,
            target=target,
            tool=tool,
            summary=summary,
            created_at=time.time(),
        )
        items[approval.id] = approval
        self._save(items)
        return approval

    def consume(self, fingerprint: str) -> bool:
        """If this exact call was approved, mark the approval used and return True."""
        items = self._snapshot()
        for item in items.values():
            if item.fingerprint == fingerprint and item.status == "approved":
                item.status = "used"
                item.decided_at = time.time()
                self._save(items)
                return True
        return False

    def is_denied(self, fingerprint: str) -> bool:
        return any(
            item.fingerprint == fingerprint and item.status == "denied"
            for item in self._snapshot().values()
        )

    # --- user side ----------------------------------------------------------

    def get(self, approval_id: str) -> Approval | None:
        return self._snapshot().get(approval_id)

    def decide(self, approval_id: str, *, approve: bool) -> Approval:
        items = self._snapshot()
        item = items.get(approval_id)
        if item is None:
            raise KeyError(f"no approval with id {approval_id!r}")
        if item.status != "pending":
            raise ValueError(f"approval {approval_id} is {item.status}, not pending")
        item.status = "approved" if approve else "denied"
        item.decided_at = time.time()
        self._save(items)
        return item

    def entries(self, *, include_decided: bool = False) -> list[Approval]:
        items = sorted(self._snapshot().values(), key=lambda a: a.created_at)
        if include_decided:
            return items
        return [item for item in items if item.status == "pending"]
