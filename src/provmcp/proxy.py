"""Transparent JSON-RPC proxy — pass-through skeleton.

Week 1 goal: the proxy accepts a JSON-RPC request from the host, forwards it
to the correct backing server, tags the response, writes the tagged payload
to the provenance store, and returns the response unchanged to the host.

Later weeks add outbound inspection on `tools/call` requests, the three
detectors, and the policy engine. The structure below leaves clear seams
for each of those without breaking the pass-through contract.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.registry import ServerRegistry

log = logging.getLogger(__name__)


@dataclass
class RpcRequest:
    """A minimal JSON-RPC 2.0 request envelope."""

    method: str
    params: dict[str, Any]
    request_id: str | int | None
    target_server_id: str


@dataclass
class RpcResponse:
    """A minimal JSON-RPC 2.0 response envelope (success case only)."""

    result: Any
    request_id: str | int | None


class Proxy:
    """Routes host calls to the right server and tags server responses.

    Dependencies are injected so unit tests can stub the transport layer.
    The real HTTP transport lands in Week 2; this class is transport-agnostic.
    """

    def __init__(
        self,
        *,
        registry: ServerRegistry,
        store: ProvenanceStore,
    ) -> None:
        self.registry = registry
        self.store = store

    def handle(
        self,
        request: RpcRequest,
        *,
        transport_call: "TransportCall",
    ) -> RpcResponse:
        """Forward the request, tag the response, return it to the host."""
        record = self.registry.get(request.target_server_id)
        log.debug("forwarding %s to %s", request.method, record.server_id)

        raw_result = transport_call(record.endpoint, request.method, request.params)

        tag = OriginTag(server_id=record.server_id, tool_name=request.method)
        self.store.record(TaggedPayload(content=raw_result, tag=tag))

        return RpcResponse(result=raw_result, request_id=request.request_id)


# Type alias for the transport callable the proxy depends on.
# A production transport will be an async httpx client; tests pass a fake.
TransportCall = Any
