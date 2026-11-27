"""Tests for DaemonBridge: stdin/stdout relay to a `provmcp run` daemon."""

from __future__ import annotations

import io
import json
from typing import Any

import httpx

from provmcp.bridge import DaemonBridge


def _bridge(
    lines: list[dict[str, Any] | str], handler: Any
) -> tuple[DaemonBridge, io.StringIO, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    text = "\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines) + "\n"
    out = io.StringIO()
    bridge = DaemonBridge(
        daemon_url="http://127.0.0.1:7337/",
        server_id="email",
        client=client,
        stdin=io.StringIO(text),
        stdout=out,
    )
    return bridge, out, seen


def _out(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


def _ok(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": {"ok": True}, "error": None}
    )


async def test_relays_request_to_the_server_endpoint() -> None:
    bridge, out, seen = _bridge([{"jsonrpc": "2.0", "id": 7, "method": "tools/list"}], _ok)
    await bridge.run()
    assert str(seen[0].url) == "http://127.0.0.1:7337/mcp/email"
    assert _out(out) == [{"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}]


async def test_notifications_are_relayed_but_not_answered() -> None:
    bridge, out, seen = _bridge(
        [{"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}], _ok
    )
    await bridge.run()
    assert len(seen) == 1
    assert out.getvalue() == ""


async def test_daemon_error_field_is_passed_through() -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": None,
                "error": {"code": -32000, "message": "child died"},
            },
        )

    bridge, out, _ = _bridge([{"jsonrpc": "2.0", "id": 1, "method": "tools/call"}], failing)
    await bridge.run()
    response = _out(out)[0]
    assert response["error"]["message"] == "child died"
    assert "result" not in response


async def test_http_404_becomes_jsonrpc_error() -> None:
    def missing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "unknown server"})

    bridge, out, _ = _bridge([{"jsonrpc": "2.0", "id": 3, "method": "tools/list"}], missing)
    await bridge.run()
    response = _out(out)[0]
    assert response["id"] == 3
    assert response["error"]["code"] == -32001


async def test_unreachable_daemon_is_reported_not_crashed() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    bridge, out, _ = _bridge([{"jsonrpc": "2.0", "id": 4, "method": "tools/list"}], down)
    await bridge.run()
    response = _out(out)[0]
    assert response["error"]["code"] == -32000
    assert "provmcp run" in response["error"]["message"]
