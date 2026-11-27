"""Tests for the stdio bridge."""

from __future__ import annotations

import io
import json
from typing import Any

from provmcp.bridge import StdioBridge
from provmcp.provenance import ProvenanceStore
from provmcp.proxy import Proxy, Router
from provmcp.registry import ServerRecord, ServerRegistry, TrustClass
from provmcp.transports.base import Transport


class FakeTransport(Transport):
    def __init__(self, canned: dict[str, Any]) -> None:
        self.canned = canned
        self.started = False
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def start(self) -> None:
        self.started = True

    async def call(self, method: str, params: dict[str, Any]) -> Any:
        self.calls.append((method, dict(params)))
        return self.canned.get(method, {})

    async def close(self) -> None:
        self.closed = True


def _build_bridge(input_text: str) -> tuple[StdioBridge, io.StringIO, FakeTransport]:
    registry = ServerRegistry(
        [
            ServerRecord(
                server_id="time",
                display_name="Time",
                endpoint="stdio://time",
                trust=TrustClass.TRUSTED,
            ),
        ]
    )
    router = Router()
    transport = FakeTransport(
        {
            "tools/list": {"tools": [{"name": "get_current_time"}]},
            "tools/call": {"result": "ok"},
        }
    )
    router.register("time", transport)
    proxy = Proxy(registry=registry, store=ProvenanceStore.empty(), router=router)
    stdin = io.StringIO(input_text)
    stdout = io.StringIO()
    bridge = StdioBridge(proxy=proxy, server_id="time", stdin=stdin, stdout=stdout)
    return bridge, stdout, transport


def _parse_lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


async def test_bridge_forwards_one_request() -> None:
    envelope = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    bridge, out, transport = _build_bridge(json.dumps(envelope) + "\n")
    await bridge.run()
    responses = _parse_lines(out)
    assert len(responses) == 1
    assert responses[0]["id"] == 1
    assert responses[0]["result"] == {"tools": [{"name": "get_current_time"}]}
    assert transport.calls == [("tools/list", {})]
    assert transport.started is True
    assert transport.closed is True


async def test_bridge_handles_multiple_requests_in_order() -> None:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_current_time"}},
    ]
    bridge, out, _ = _build_bridge("\n".join(json.dumps(r) for r in requests) + "\n")
    await bridge.run()
    responses = _parse_lines(out)
    assert [r["id"] for r in responses] == [1, 2]


async def test_bridge_does_not_reply_to_notifications() -> None:
    notification = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    bridge, out, _ = _build_bridge(json.dumps(notification) + "\n")
    await bridge.run()
    assert out.getvalue() == ""


async def test_bridge_returns_parse_error_on_bad_json() -> None:
    bridge, out, _ = _build_bridge("{this is not json\n")
    await bridge.run()
    responses = _parse_lines(out)
    assert len(responses) == 1
    assert responses[0]["error"]["code"] == -32700


async def test_bridge_rejects_unknown_server() -> None:
    import pytest

    registry = ServerRegistry(
        [
            ServerRecord(
                server_id="time",
                display_name="Time",
                endpoint="stdio://time",
                trust=TrustClass.TRUSTED,
            ),
        ]
    )
    router = Router()
    router.register("time", FakeTransport({}))
    proxy = Proxy(registry=registry, store=ProvenanceStore.empty(), router=router)
    with pytest.raises(ValueError):
        StdioBridge(proxy=proxy, server_id="nope")
