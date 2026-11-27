"""FastAPI server loop — ProvMCP as an HTTP JSON-RPC endpoint.

The server exposes two paths:

- POST /mcp/{server_id}
    Forward one JSON-RPC request to the named backing server, tag the
    response, record provenance, and return the response to the caller.

- GET /health
    Readiness check. Returns 200 with `{"status": "ok"}` once all
    transports have been started.

The intent for Week 3 is that any MCP-aware HTTP client — Claude Desktop
with an HTTP transport configuration, cURL, Postman — can send JSON-RPC
requests to this endpoint and talk to any configured backing server
through ProvMCP. The server does not yet inspect outbound calls; that is
Week 7 work.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from provmcp.proxy import Proxy, RpcRequest
from provmcp.transports import TransportError

log = logging.getLogger(__name__)


class JsonRpcEnvelope(BaseModel):
    """Loose JSON-RPC 2.0 envelope as accepted on the wire."""

    jsonrpc: str = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcError(BaseModel):
    """JSON-RPC error object."""

    code: int
    message: str
    data: Any | None = None


class JsonRpcResponse(BaseModel):
    """JSON-RPC 2.0 response envelope."""

    jsonrpc: str = "2.0"
    id: str | int | None = None
    result: Any | None = None
    error: JsonRpcError | None = None


def build_app(proxy: Proxy) -> FastAPI:
    """Build the FastAPI app around a pre-wired Proxy.

    The app owns the proxy's lifecycle: transports start on app startup
    and close on shutdown.
    """

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await proxy.router.start_all()
        log.info("started %d transport(s)", len(proxy.router.server_ids()))
        try:
            yield
        finally:
            await proxy.router.close_all()
            log.info("transports closed")

    app = FastAPI(
        title="ProvMCP",
        description="Runtime detection of cross-server confused-deputy attacks in MCP.",
        version="0.10.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        inspector = proxy.inspector
        return {
            "status": "ok",
            "servers": proxy.router.server_ids(),
            "store_size": len(proxy.store),
            "inspection": inspector is not None,
            "policy": inspector.template.value if inspector is not None else None,
            "pending_approvals": len(inspector.approvals.entries()) if inspector else 0,
        }

    @app.post("/mcp/{server_id}")
    async def mcp(server_id: str, envelope: JsonRpcEnvelope) -> JsonRpcResponse:
        if server_id not in proxy.registry:
            raise HTTPException(status_code=404, detail=f"unknown server: {server_id!r}")
        request = RpcRequest(
            method=envelope.method,
            params=envelope.params,
            request_id=envelope.id,
            target_server_id=server_id,
        )
        try:
            response = await proxy.handle(request)
        except TransportError as exc:
            return JsonRpcResponse(
                id=envelope.id,
                error=JsonRpcError(code=-32000, message=str(exc)),
            )
        return JsonRpcResponse(id=response.request_id, result=response.result)

    return app
