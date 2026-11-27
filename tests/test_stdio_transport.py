"""Integration tests for the stdio transport using the echo subprocess."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from provmcp.transports.stdio import StdioTransport

ECHO = str(Path(__file__).parent.parent / "examples" / "dummy_server" / "echo_server.py")


async def test_stdio_roundtrip_echoes_method_and_params() -> None:
    transport = StdioTransport([sys.executable, ECHO])
    await transport.start()
    try:
        result = await transport.call("tools/call", {"name": "ping"})
        assert result == {
            "echoed_method": "tools/call",
            "echoed_params": {"name": "ping"},
        }
    finally:
        await transport.close()


async def test_stdio_multiple_sequential_calls_share_process() -> None:
    transport = StdioTransport([sys.executable, ECHO])
    await transport.start()
    try:
        r1 = await transport.call("m1", {"n": 1})
        r2 = await transport.call("m2", {"n": 2})
        r3 = await transport.call("m3", {"n": 3})
        assert r1["echoed_method"] == "m1"
        assert r2["echoed_method"] == "m2"
        assert r3["echoed_method"] == "m3"
    finally:
        await transport.close()


async def test_stdio_rejects_empty_command() -> None:
    with pytest.raises(ValueError):
        StdioTransport([])


async def test_stdio_close_is_idempotent() -> None:
    transport = StdioTransport([sys.executable, ECHO])
    await transport.start()
    await transport.close()
    await transport.close()  # no error the second time
