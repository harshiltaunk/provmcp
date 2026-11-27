"""HTTP transport.

Some MCP servers expose a JSON-RPC-over-HTTP endpoint instead of stdio. This
transport posts the envelope to that endpoint and returns the result. It is
the simpler of the two transports because HTTP is already request/response.

Lazy import of httpx keeps the dependency optional for stdio-only setups.
"""

from __future__ import annotations

import itertools
import json
from typing import Any

from provmcp.transports.base import Transport, TransportError


class HttpTransport(Transport):
    """JSON-RPC over HTTP POST."""

    def __init__(self, url: str, *, timeout_seconds: float = 30.0) -> None:
        if not url:
            raise ValueError("url must be non-empty")
        self._url = url
        self._timeout = timeout_seconds
        self._client: Any = None
        self._ids = itertools.count(1)

    async def start(self) -> None:
        if self._client is not None:
            return
        import httpx

        self._client = httpx.AsyncClient(timeout=self._timeout)

    async def call(self, method: str, params: dict[str, Any]) -> Any:
        if self._client is None:
            raise TransportError("transport not started")

        request_id = next(self._ids)
        envelope = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        try:
            response = await self._client.post(self._url, json=envelope)
        except Exception as exc:  # httpx error hierarchy is wide
            raise TransportError(f"request failed: {exc}") from exc

        if response.status_code >= 400:
            raise TransportError(f"HTTP {response.status_code}: {response.text[:200]}")

        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise TransportError(f"invalid JSON: {exc}") from exc

        if body.get("id") != request_id:
            raise TransportError(f"response id mismatch: {body.get('id')!r}")
        if body.get("error"):
            raise TransportError(f"server error: {body['error']}")
        return body.get("result")

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        if self._client is None:
            raise TransportError("transport not started")
        envelope = {"jsonrpc": "2.0", "method": method, "params": params}
        try:
            await self._client.post(self._url, json=envelope)
        except Exception as exc:  # httpx error hierarchy is wide
            raise TransportError(f"notification failed: {exc}") from exc

    async def close(self) -> None:
        if self._client is None:
            return
        await self._client.aclose()
        self._client = None
