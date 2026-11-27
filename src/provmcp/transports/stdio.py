"""Stdio transport.

Many MCP servers (including Anthropic's reference `filesystem`, `time`, and
`fetch` servers) run as local subprocesses that speak JSON-RPC over stdin and
stdout, one JSON message per line. This transport launches that subprocess,
writes requests to its stdin, and reads responses from its stdout.

The implementation is deliberately simple: one request in flight at a time,
responses matched by `id`. MCP clients in real hosts multiplex many requests;
Week 2's goal is correctness for the sequential case we exercise in tests.
Concurrency hardening lands in Week 4 once we have real multi-call traces.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
from typing import Any

from provmcp.transports.base import Transport, TransportError


class StdioTransport(Transport):
    """JSON-RPC over the stdin/stdout of a child process."""

    def __init__(self, command: list[str]) -> None:
        if not command:
            raise ValueError("command must contain at least the executable")
        self._command = command
        self._process: asyncio.subprocess.Process | None = None
        self._ids = itertools.count(1)
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self._process is not None:
            return
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    def _pipes(self) -> tuple[asyncio.StreamWriter, asyncio.StreamReader]:
        if self._process is None:
            raise TransportError("transport not started")
        if self._process.stdin is None or self._process.stdout is None:
            raise TransportError("child process has no pipes")
        return self._process.stdin, self._process.stdout

    async def _write(self, writer: asyncio.StreamWriter, envelope: dict[str, Any]) -> None:
        try:
            writer.write((json.dumps(envelope) + "\n").encode("utf-8"))
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise TransportError(f"write failed: {exc}") from exc

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        writer, _ = self._pipes()
        async with self._lock:
            await self._write(writer, {"jsonrpc": "2.0", "method": method, "params": params})

    async def call(self, method: str, params: dict[str, Any]) -> Any:
        writer, reader = self._pipes()
        async with self._lock:
            request_id = next(self._ids)
            await self._write(
                writer,
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            )
            while True:
                raw = await reader.readline()
                if not raw:
                    raise TransportError("child closed stdout before responding")
                try:
                    response = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    raise TransportError(f"invalid JSON from child: {exc}") from exc
                if "method" in response:
                    # Server-initiated notification or request (logging, progress).
                    # Not ours to answer here; skip and keep reading.
                    continue
                if response.get("id") != request_id:
                    raise TransportError(
                        f"response id {response.get('id')!r} does not match request {request_id}"
                    )
                if response.get("error"):
                    raise TransportError(f"server error: {response['error']}")
                return response.get("result")

    async def close(self) -> None:
        if self._process is None:
            return
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
        with contextlib.suppress(ProcessLookupError):
            self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=2.0)
        except TimeoutError:
            self._process.kill()
            await self._process.wait()
        self._process = None
