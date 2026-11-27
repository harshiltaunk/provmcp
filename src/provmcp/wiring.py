"""Wiring: build runtime objects from a parsed config.

Keeps the CLI thin. Everything that turns a `ProvMcpConfig` into a live
`Proxy` goes here, so the integration test can call the same code the CLI
calls, without going through argparse or typer.
"""

from __future__ import annotations

from provmcp.config import ProvMcpConfig
from provmcp.provenance import ProvenanceStore
from provmcp.proxy import Proxy, Router
from provmcp.registry import ServerRecord, ServerRegistry
from provmcp.transports import HttpTransport, StdioTransport, Transport


def build_registry(config: ProvMcpConfig) -> ServerRegistry:
    """Turn config server entries into a ServerRegistry."""
    records = [
        ServerRecord(
            server_id=s.id,
            display_name=s.display_name,
            endpoint=_endpoint_description(s.transport, s.command, s.url),
            trust=s.trust,
        )
        for s in config.servers
    ]
    return ServerRegistry(records)


def build_router(config: ProvMcpConfig) -> Router:
    """Build a Router with one Transport per configured server."""
    router = Router()
    for s in config.servers:
        transport: Transport
        if s.transport == "stdio":
            transport = StdioTransport(s.command)
        else:
            assert s.url is not None  # validated in config
            transport = HttpTransport(s.url)
        router.register(s.id, transport)
    return router


def build_proxy(config: ProvMcpConfig) -> Proxy:
    """Build a Proxy that is ready to `await router.start_all()` and serve."""
    return Proxy(
        registry=build_registry(config),
        store=ProvenanceStore.empty(),
        router=build_router(config),
    )


def _endpoint_description(transport: str, command: list[str], url: str | None) -> str:
    if transport == "stdio":
        return "stdio://" + " ".join(command)
    return url or "http://unknown"
