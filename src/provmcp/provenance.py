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
from collections import deque
from collections.abc import Callable
from typing import Any, Self, TypeVar

from pydantic import BaseModel, Field, field_validator

T = TypeVar("T")


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
    """An in-memory record of the payloads the host has seen, by tag.

    Bounds (Week 11). Without them the store grows for the life of the
    daemon:

    - `max_per_server` keeps at most this many payloads per *source server*,
      evicting that server's oldest first. A cap per server, not a global
      one, means a chatty or hostile server can only push out its own old
      records, never another server's. It cannot "flush" the provenance of
      the content it wants to smuggle into a different server's call.
    - `ttl_seconds` drops payloads older than this when the store is written
      or read.

    Derived data (Week 11). Detectors re-derived the same things from every
    stored payload on every call: word runs, typed fields, sentence
    embeddings. `derived()` computes them once per payload and drops them
    with the payload. `cache_derived=False` turns that off, for before/after
    measurement.

    The store is single-process; multi-proxy coordination is out of scope.
    """

    def __init__(
        self,
        *,
        max_per_server: int | None = None,
        ttl_seconds: float | None = None,
        cache_derived: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_per_server is not None and max_per_server < 1:
            raise ValueError("max_per_server must be at least 1")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.max_per_server = max_per_server
        self.ttl_seconds = ttl_seconds
        self.cache_derived = cache_derived
        self._clock = clock
        self._payloads: dict[str, TaggedPayload] = {}
        self._recorded_at: dict[str, float] = {}
        self._by_server: dict[str, deque[str]] = {}
        self._derived: dict[str, dict[str, Any]] = {}
        self.evicted = 0

    def record(self, payload: TaggedPayload) -> None:
        tag_id = payload.tag.tag_id
        if tag_id in self._payloads:
            self._drop(tag_id)
        self._payloads[tag_id] = payload
        self._recorded_at[tag_id] = self._clock()
        queue = self._by_server.setdefault(payload.tag.server_id, deque())
        queue.append(tag_id)
        if self.max_per_server is not None:
            while len(queue) > self.max_per_server:
                self._drop(queue[0])
                self.evicted += 1
        self._expire()

    def payloads(self) -> list[TaggedPayload]:
        """Every live payload, oldest first."""
        self._expire()
        return list(self._payloads.values())

    def derived(self, tag_id: str, key: str, compute: Callable[[], T]) -> T:
        """`compute()` once per (payload, key); the result lives as long as the payload."""
        if not self.cache_derived or tag_id not in self._payloads:
            return compute()
        bucket = self._derived.setdefault(tag_id, {})
        if key not in bucket:
            bucket[key] = compute()
        value: T = bucket[key]
        return value

    def get(self, tag_id: str) -> TaggedPayload | None:
        return self._payloads.get(tag_id)

    def from_server(self, server_id: str) -> list[TaggedPayload]:
        return [p for p in self.payloads() if p.is_from(server_id)]

    def __len__(self) -> int:
        return len(self._payloads)

    def clear(self) -> None:
        self._payloads.clear()
        self._recorded_at.clear()
        self._by_server.clear()
        self._derived.clear()

    def _drop(self, tag_id: str) -> None:
        payload = self._payloads.pop(tag_id, None)
        self._recorded_at.pop(tag_id, None)
        self._derived.pop(tag_id, None)
        if payload is not None:
            queue = self._by_server.get(payload.tag.server_id)
            if queue:
                if queue[0] == tag_id:
                    queue.popleft()
                else:
                    queue.remove(tag_id)

    def _expire(self) -> None:
        if self.ttl_seconds is None:
            return
        cutoff = self._clock() - self.ttl_seconds
        # Insertion order is recording order, so expired payloads are at the front.
        for tag_id in list(self._recorded_at):
            if self._recorded_at[tag_id] > cutoff:
                break
            self._drop(tag_id)
            self.evicted += 1

    @classmethod
    def empty(cls) -> Self:
        return cls()
