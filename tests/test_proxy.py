"""Tests for the proxy — async pass-through, tagging, routing."""

from __future__ import annotations

from typing import Any

import pytest

from provmcp.provenance import ProvenanceStore
from provmcp.proxy import Proxy, Router, RpcRequest
from provmcp.registry import ServerRecord, ServerRegistry, TrustClass
from provmcp.transports.base import Transport


class FakeTransport(Transport):
    """Transport that returns canned results keyed by (method, params)."""

    def __init__(self, canned: dict[tuple[str, str], Any]) -> None:
        self._canned = canned
        self.started = False
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def start(self) -> None:
        self.started = True

    async def call(self, method: str, params: dict[str, Any]) -> Any:
        self.calls.append((method, dict(params)))
        key = (method, _stable_key(params))
        return self._canned[key]

    async def close(self) -> None:
        self.closed = True


def _stable_key(params: dict[str, Any]) -> str:
    import json

    return json.dumps(params, sort_keys=True)


def _build(canned: dict[str, dict[tuple[str, str], Any]]) -> tuple[Proxy, ProvenanceStore, Router]:
    registry = ServerRegistry(
        [
            ServerRecord(
                server_id="calendar",
                display_name="Calendar",
                endpoint="stdio://calendar",
                trust=TrustClass.LIMITED,
            ),
            ServerRecord(
                server_id="email",
                display_name="Email",
                endpoint="stdio://email",
                trust=TrustClass.LIMITED,
            ),
        ]
    )
    store = ProvenanceStore.empty()
    router = Router()
    for server_id, table in canned.items():
        router.register(server_id, FakeTransport(table))
    return Proxy(registry=registry, store=store, router=router), store, router


async def test_handle_returns_result_unchanged() -> None:
    proxy, _, _ = _build(
        {
            "calendar": {("tools/list", "{}"): {"tools": ["get_events"]}},
        }
    )
    response = await proxy.handle(
        RpcRequest(
            method="tools/list",
            params={},
            request_id=1,
            target_server_id="calendar",
        )
    )
    assert response.result == {"tools": ["get_events"]}
    assert response.request_id == 1


async def test_handle_records_tagged_payload() -> None:
    proxy, store, _ = _build(
        {
            "calendar": {
                ("tools/call", '{"name": "get_next_event"}'): {"text": "Coffee at 10am"},
            },
        }
    )
    await proxy.handle(
        RpcRequest(
            method="tools/call",
            params={"name": "get_next_event"},
            request_id="r-1",
            target_server_id="calendar",
        )
    )
    assert len(store) == 1
    tagged = store.from_server("calendar")[0]
    assert tagged.content == {"text": "Coffee at 10am"}
    assert tagged.tag.tool_name == "tools/call"


async def test_router_rejects_duplicate_registration() -> None:
    router = Router()
    router.register("x", FakeTransport({}))
    with pytest.raises(ValueError):
        router.register("x", FakeTransport({}))


async def test_router_raises_on_unknown_server() -> None:
    router = Router()
    with pytest.raises(KeyError):
        router.get("missing")


async def test_router_start_and_close_propagate() -> None:
    router = Router()
    t = FakeTransport({})
    router.register("x", t)
    await router.start_all()
    await router.close_all()
    assert t.started is True
    assert t.closed is True


async def test_router_starts_transports_concurrently() -> None:
    """start_all should run transport starts in parallel, not serially.

    Each transport sleeps 100ms during start. Four transports in parallel
    should finish well under 400ms; serial would take ~400ms or more.
    """
    import asyncio
    import time

    class SlowStart(FakeTransport):
        async def start(self) -> None:
            await asyncio.sleep(0.1)
            await super().start()

    router = Router()
    for i in range(4):
        router.register(f"s{i}", SlowStart({}))

    t0 = time.perf_counter()
    await router.start_all()
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.3, f"start_all took {elapsed:.3f}s; expected < 0.3s"
    await router.close_all()


async def test_router_start_all_empty_is_a_noop() -> None:
    await Router().start_all()
    await Router().close_all()
