"""Transparent JSON-RPC proxy.

Week 2 surface: the proxy now routes requests through an async Transport,
tags every response, and records the tagged payload in the provenance store.
Outbound inspection — the point of the whole project — comes in Week 7 once
the detectors are wired in.

The Router owns one Transport per connected server, keyed by server_id.
The Proxy class is the public API; tests pass a fake Router to exercise
pass-through without spinning up subprocesses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.registry import ServerRegistry
from provmcp.transports import Transport, TransportError

log = logging.getLogger(__name__)


@dataclass
class RpcRequest:
    """A minimal JSON-RPC 2.0 request envelope the host gives us."""

    method: str
    params: dict[str, Any]
    request_id: str | int | None
    target_server_id: str


@dataclass
class RpcResponse:
    """A minimal JSON-RPC 2.0 response envelope we return to the host."""

    result: Any
    request_id: str | int | None


class Router:
    """Owns one Transport per server_id and dispatches calls."""

    def __init__(self) -> None:
        self._transports: dict[str, Transport] = {}

    def register(self, server_id: str, transport: Transport) -> None:
        if server_id in self._transports:
            raise ValueError(f"transport already registered for {server_id!r}")
        self._transports[server_id] = transport

    def get(self, server_id: str) -> Transport:
        if server_id not in self._transports:
            raise KeyError(f"no transport for {server_id!r}")
        return self._transports[server_id]

    async def start_all(self) -> None:
        for transport in self._transports.values():
            await transport.start()

    async def close_all(self) -> None:
        for transport in self._transports.values():
            try:
                await transport.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                log.exception("transport close failed")

    def server_ids(self) -> list[str]:
        return list(self._transports.keys())


class Proxy:
    """Routes host calls, tags responses, records provenance."""

    def __init__(
        self,
        *,
        registry: ServerRegistry,
        store: ProvenanceStore,
        router: Router,
    ) -> None:
        self.registry = registry
        self.store = store
        self.router = router

    async def handle(self, request: RpcRequest) -> RpcResponse:
        record = self.registry.get(request.target_server_id)
        transport = self.router.get(request.target_server_id)

        log.debug("forwarding %s to %s", request.method, record.server_id)

        try:
            raw_result = await transport.call(request.method, request.params)
        except TransportError:
            raise

        tag = OriginTag(server_id=record.server_id, tool_name=request.method)
        self.store.record(TaggedPayload(content=raw_result, tag=tag))

        return RpcResponse(result=raw_result, request_id=request.request_id)
