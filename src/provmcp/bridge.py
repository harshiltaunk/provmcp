"""Stdio bridges: speak MCP over stdin/stdout so Claude Desktop can use ProvMCP.

Claude Desktop launches one subprocess per configured MCP server and talks to
it over stdin/stdout. A bridge is that subprocess. It reads JSON-RPC lines from
stdin, handles each one, and writes responses to stdout.

There are two bridges. They share the line loop and differ only in dispatch.

- `StdioBridge` (direct mode) owns a full Proxy in-process. Simple, but every
  bridge process has its own provenance store, so a bridge fronting the email
  server never sees what the calendar bridge returned. Cross-server detection
  cannot work in this mode. Use it only for single-server testing.

- `DaemonBridge` (daemon mode) holds no state. It relays each message to a
  running `provmcp run` daemon at `/mcp/<server_id>`. The daemon owns the one
  shared provenance store, so cross-server detection works across every
  bridge. This is the mode for real Claude Desktop use.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, TextIO

from provmcp.proxy import Proxy, RpcRequest
from provmcp.transports import TransportError

log = logging.getLogger(__name__)


class _LineBridge:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""

    def __init__(self, *, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        self._stdin = stdin or sys.stdin
        self._stdout = stdout or sys.stdout

    async def run(self) -> None:
        """Serve until stdin closes."""
        await self._start()
        try:
            await self._serve()
        finally:
            await self._stop()

    async def _start(self) -> None:
        return None

    async def _stop(self) -> None:
        return None

    async def _dispatch(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError

    async def _serve(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, self._stdin.readline)
            if not line:
                return  # EOF
            line = line.strip()
            if not line:
                continue
            await self._handle_line(line)

    async def _handle_line(self, line: str) -> None:
        try:
            envelope = json.loads(line)
        except json.JSONDecodeError as exc:
            self._write(error_envelope(None, -32700, f"parse error: {exc}"))
            return
        if not isinstance(envelope, dict):
            self._write(error_envelope(None, -32600, "request must be a JSON object"))
            return

        is_notification = "id" not in envelope
        method = envelope.get("method")
        if not isinstance(method, str) or not method:
            if not is_notification:
                self._write(
                    error_envelope(envelope.get("id"), -32600, "method must be a non-empty string")
                )
            return

        try:
            response = await self._dispatch(envelope)
        except Exception as exc:  # noqa: BLE001 — never crash the host's subprocess
            log.exception("bridge dispatch failed")
            response = error_envelope(envelope.get("id"), -32603, f"internal error: {exc}")

        if is_notification or response is None:
            return  # notifications never reply
        self._write(response)

    def _write(self, envelope: dict[str, Any]) -> None:
        self._stdout.write(json.dumps(envelope) + "\n")
        self._stdout.flush()


class StdioBridge(_LineBridge):
    """Direct mode: an in-process Proxy fronting one backing server."""

    def __init__(
        self,
        *,
        proxy: Proxy,
        server_id: str,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        if server_id not in proxy.registry:
            raise ValueError(f"unknown server_id: {server_id!r}")
        super().__init__(stdin=stdin, stdout=stdout)
        self.proxy = proxy
        self.server_id = server_id

    async def _start(self) -> None:
        await self.proxy.router.start_all()

    async def _stop(self) -> None:
        await self.proxy.router.close_all()

    async def _dispatch(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        params = envelope.get("params")
        request = RpcRequest(
            method=envelope["method"],
            params=params if isinstance(params, dict) else {},
            request_id=envelope.get("id"),
            target_server_id=self.server_id,
        )
        try:
            response = await self.proxy.handle(request)
        except TransportError as exc:
            return error_envelope(envelope.get("id"), -32000, str(exc))
        return {"jsonrpc": "2.0", "id": response.request_id, "result": response.result}


class DaemonBridge(_LineBridge):
    """Daemon mode: relay every message to a running `provmcp run` daemon."""

    def __init__(
        self,
        *,
        daemon_url: str,
        server_id: str,
        client: Any = None,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(stdin=stdin, stdout=stdout)
        self.endpoint = f"{daemon_url.rstrip('/')}/mcp/{server_id}"
        self.server_id = server_id
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout_seconds

    async def _start(self) -> None:
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(timeout=self._timeout)

    async def _stop(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def _dispatch(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        request_id = envelope.get("id")
        try:
            response = await self._client.post(self.endpoint, json=envelope)
        except Exception as exc:  # httpx error hierarchy is wide
            return error_envelope(
                request_id,
                -32000,
                f"ProvMCP daemon not reachable at {self.endpoint}: {exc}. "
                "Start it with `provmcp run -c <config>`.",
            )
        if response.status_code >= 400:
            return error_envelope(
                request_id, -32001, f"daemon HTTP {response.status_code}: {response.text[:200]}"
            )
        body = response.json()
        out: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        if body.get("error"):
            out["error"] = body["error"]
        else:
            out["result"] = body.get("result")
        return out


def error_envelope(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
