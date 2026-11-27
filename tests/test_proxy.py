"""Tests for the proxy skeleton — pass-through plus tagging."""

from __future__ import annotations

from provmcp.provenance import ProvenanceStore
from provmcp.proxy import Proxy, RpcRequest
from provmcp.registry import ServerRecord, ServerRegistry, TrustClass


def _make_proxy() -> tuple[Proxy, ProvenanceStore]:
    registry = ServerRegistry([
        ServerRecord(
            server_id="calendar",
            display_name="Calendar",
            endpoint="http://127.0.0.1/cal",
            trust=TrustClass.LIMITED,
        ),
        ServerRecord(
            server_id="email",
            display_name="Email",
            endpoint="http://127.0.0.1/mail",
            trust=TrustClass.LIMITED,
        ),
    ])
    store = ProvenanceStore.empty()
    return Proxy(registry=registry, store=store), store


def _fake_transport_factory(canned: dict[tuple[str, str], object]):
    """Return a transport callable that looks up (endpoint, method) in a dict."""

    def _call(endpoint: str, method: str, params: dict[str, object]) -> object:
        del params  # unused in the fake
        return canned[(endpoint, method)]

    return _call


def test_handle_returns_result_unchanged() -> None:
    proxy, _ = _make_proxy()
    transport = _fake_transport_factory({
        ("http://127.0.0.1/cal", "tools/list"): {"tools": ["get_events"]},
    })
    request = RpcRequest(
        method="tools/list",
        params={},
        request_id=1,
        target_server_id="calendar",
    )
    response = proxy.handle(request, transport_call=transport)
    assert response.result == {"tools": ["get_events"]}
    assert response.request_id == 1


def test_handle_records_tagged_payload() -> None:
    proxy, store = _make_proxy()
    transport = _fake_transport_factory({
        ("http://127.0.0.1/cal", "tools/call"): {"text": "Coffee with Soraya at 10am"},
    })
    request = RpcRequest(
        method="tools/call",
        params={"name": "get_next_event"},
        request_id="r-1",
        target_server_id="calendar",
    )
    proxy.handle(request, transport_call=transport)
    assert len(store) == 1
    tagged = store.from_server("calendar")[0]
    assert tagged.content == {"text": "Coffee with Soraya at 10am"}
    assert tagged.tag.tool_name == "tools/call"


def test_multiple_servers_recorded_independently() -> None:
    proxy, store = _make_proxy()
    transport = _fake_transport_factory({
        ("http://127.0.0.1/cal", "tools/call"): {"text": "lunch with sam"},
        ("http://127.0.0.1/mail", "tools/call"): {"text": "invoice from vendor"},
    })
    proxy.handle(
        RpcRequest(
            method="tools/call", params={}, request_id=1, target_server_id="calendar",
        ),
        transport_call=transport,
    )
    proxy.handle(
        RpcRequest(
            method="tools/call", params={}, request_id=2, target_server_id="email",
        ),
        transport_call=transport,
    )
    assert len(store) == 2
    assert len(store.from_server("calendar")) == 1
    assert len(store.from_server("email")) == 1
