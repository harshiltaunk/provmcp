"""Provenance primitives.

A provenance tag marks a piece of data with the server that produced it, plus
when and under which host invocation. Tags are the atom of ProvMCP's defense:
when data from server A later shows up as a parameter on a call to server B,
the tag on the data makes the cross-origin flow visible to the policy engine.

The implementation is deliberately minimal — the goal here is correctness of
the schema, not a high-performance taint engine. Propagation strategies
(substring, embedding, structured-field) live in `provmcp.detectors`.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Self

from pydantic import BaseModel, Field, field_validator


class OriginTag(BaseModel):
    """Who produced this data, and when.

    A tag is immutable once created. To record derived data (e.g. a slice of
    a tagged payload reused somewhere else), create a new tag that references
    the parent via `parent_tag_id` rather than mutating the original.
    """

    tag_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    server_id: str
    tool_name: str | None = None
    created_at: float = Field(default_factory=time.time)
    parent_tag_id: str | None = None

    @field_validator("server_id")
    @classmethod
    def _non_empty_server(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("server_id must be non-empty")
        return value

    def derive(self, *, tool_name: str | None = None) -> OriginTag:
        """Return a child tag whose origin is this tag."""
        return OriginTag(
            server_id=self.server_id,
            tool_name=tool_name or self.tool_name,
            parent_tag_id=self.tag_id,
        )


class TaggedPayload(BaseModel):
    """A chunk of server output plus its origin tag.

    `content` is the raw response body as the server sent it (typically a dict
    produced by JSON-RPC). `tag` records where it came from. ProvMCP writes
    these into its provenance store on each server reply, and reads them back
    when inspecting outbound tool calls.
    """

    content: Any
    tag: OriginTag

    def is_from(self, server_id: str) -> bool:
        return self.tag.server_id == server_id


class ProvenanceStore:
    """An in-memory record of every payload the host has seen, by tag.

    The store is a simple append-only map for Week 1 — persistence and bounded
    retention arrive in Week 3. The store is single-process; multi-proxy
    coordination is out of scope for this project.
    """

    def __init__(self) -> None:
        self._payloads: dict[str, TaggedPayload] = {}

    def record(self, payload: TaggedPayload) -> None:
        self._payloads[payload.tag.tag_id] = payload

    def get(self, tag_id: str) -> TaggedPayload | None:
        return self._payloads.get(tag_id)

    def from_server(self, server_id: str) -> list[TaggedPayload]:
        return [p for p in self._payloads.values() if p.is_from(server_id)]

    def __len__(self) -> int:
        return len(self._payloads)

    def clear(self) -> None:
        self._payloads.clear()

    @classmethod
    def empty(cls) -> Self:
        return cls()
