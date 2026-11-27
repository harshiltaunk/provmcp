"""Transparent JSON-RPC proxy with live inspection.

Request flow for one host message:

1. Notifications (method `notifications/...`, no id) are forwarded with
   `Transport.notify` and produce no response.
2. If an Inspector is attached and the method is `tools/call`, the call is
   inspected first. A held or blocked call is never forwarded. The host
   receives an MCP tool result with `isError: true` explaining why.
3. Otherwise the request is forwarded to the backing server.
4. Results of content-bearing methods (`tools/call`, `resources/read`,
   `prompts/get`) are tagged with their origin and recorded in the provenance
   store, which later inspections compare against.

The Router owns one Transport per connected server, keyed by server_id.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from provmcp.inspector import Decision, Inspector, held_result
from provmcp.policy import PolicyAction
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.registry import ServerRegistry
from provmcp.transports import Transport

log = logging.getLogger(__name__)

# Methods whose results carry server-provided content worth tracking.
RECORDED_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})


@dataclass
class RpcRequest:
    """A minimal JSON-RPC 2.0 request envelope the host gives us."""

    method: str
    params: dict[str, Any]
    request_id: str | int | None
    target_server_id: str

    @property
    def is_notification(self) -> bool:
        return self.request_id is None and self.method.startswith("notifications/")


@dataclass
class RpcResponse:
    """A minimal JSON-RPC 2.0 response envelope we return to the host."""

    result: Any
    request_id: str | int | None
    decision: Decision | None = None


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
        if not self._transports:
            return
        await asyncio.gather(*(t.start() for t in self._transports.values()))

    async def close_all(self) -> None:
        for transport in self._transports.values():
            try:
                await transport.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                log.exception("transport close failed")

    def server_ids(self) -> list[str]:
        return list(self._transports.keys())


class Proxy:
    """Routes host calls, inspects tool calls, tags responses, records provenance."""

    def __init__(
        self,
        *,
        registry: ServerRegistry,
        store: ProvenanceStore,
        router: Router,
        inspector: Inspector | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        self.router = router
        self.inspector = inspector

    async def handle(self, request: RpcRequest) -> RpcResponse:
        record = self.registry.get(request.target_server_id)
        transport = self.router.get(request.target_server_id)

        if request.is_notification:
            await transport.notify(request.method, request.params)
            return RpcResponse(result=None, request_id=None)

        decision: Decision | None = None
        if self.inspector is not None and request.method == "tools/call":
            decision = self.inspector.inspect(
                store=self.store,
                target_server_id=record.server_id,
                params=request.params,
            )
            if decision.action is not PolicyAction.PASS:
                log.warning(
                    "%s call to %s: %s", decision.action.value, record.server_id, decision.reason
                )
                return RpcResponse(
                    result=held_result(decision),
                    request_id=request.request_id,
                    decision=decision,
                )

        log.debug("forwarding %s to %s", request.method, record.server_id)
        raw_result = await transport.call(request.method, request.params)

        if request.method in RECORDED_METHODS:
            tag = OriginTag(server_id=record.server_id, tool_name=request.method)
            self.store.record(TaggedPayload(content=raw_result, tag=tag))

        return RpcResponse(result=raw_result, request_id=request.request_id, decision=decision)
