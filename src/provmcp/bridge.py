"""Stdio bridge — speak MCP over stdin/stdout as a backing-style server.

Claude Desktop's default MCP transport is stdio: it launches a configured
command and talks to it over the subprocess's stdin/stdout. For ProvMCP to
sit between Claude Desktop and a backing server, ProvMCP itself needs to
present an stdio interface.

The bridge is the dual of `StdioTransport`. It reads JSON-RPC envelopes
one line at a time from stdin, routes each to the configured backing
server via the Proxy, and writes the JSON-RPC response back on stdout.

Week 4 configuration: one bridge instance fronts exactly one backing
server, identified by the `--server` flag at startup. This mirrors the
one-command-per-server pattern Claude Desktop already uses. The bridge
is launched as `provmcp bridge -c <config> -s <server_id>` and Claude
Desktop's `claude_desktop_config.json` simply swaps its original
command for this one.
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


class StdioBridge:
    """Read JSON-RPC envelopes from stdin, write results to stdout."""

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
        self.proxy = proxy
        self.server_id = server_id
        self._stdin = stdin or sys.stdin
        self._stdout = stdout or sys.stdout

    async def run(self) -> None:
        """Serve until stdin closes."""
        await self.proxy.router.start_all()
        try:
            await self._serve()
        finally:
            await self.proxy.router.close_all()

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
            self._write(_error_envelope(None, -32700, f"parse error: {exc}"))
            return

        is_notification = "id" not in envelope
        request_id = envelope.get("id")
        method = envelope.get("method")
        params = envelope.get("params") or {}

        if not isinstance(method, str) or not method:
            if not is_notification:
                self._write(
                    _error_envelope(request_id, -32600, "method must be a non-empty string")
                )
            return

        request = RpcRequest(
            method=method,
            params=params if isinstance(params, dict) else {},
            request_id=request_id,
            target_server_id=self.server_id,
        )
        try:
            response = await self.proxy.handle(request)
        except TransportError as exc:
            if not is_notification:
                self._write(_error_envelope(request_id, -32000, str(exc)))
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("bridge handler crashed")
            if not is_notification:
                self._write(_error_envelope(request_id, -32603, f"internal error: {exc}"))
            return

        if is_notification:
            return  # notifications never reply

        self._write(
            {
                "jsonrpc": "2.0",
                "id": response.request_id,
                "result": response.result,
            }
        )

    def _write(self, envelope: dict[str, Any]) -> None:
        self._stdout.write(json.dumps(envelope) + "\n")
        self._stdout.flush()


def _error_envelope(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
