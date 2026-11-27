"""Command-line entry point."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from provmcp import __version__
from provmcp.config import load_config
from provmcp.proxy import RpcRequest
from provmcp.server import build_app
from provmcp.wiring import build_proxy

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()


@app.command()
def version() -> None:
    """Print the ProvMCP version."""
    console.print(f"provmcp [bold]{__version__}[/bold]")


@app.command()
def doctor() -> None:
    """Report Python version and import health."""
    console.print(f"python: [bold]{sys.version.split()[0]}[/bold]")
    ok = True
    for module in ("pydantic", "fastapi", "httpx", "typer", "uvicorn"):
        try:
            __import__(module)
            console.print(f"  {module}: [green]ok[/green]")
        except ImportError as exc:
            console.print(f"  {module}: [red]missing[/red] ({exc})")
            ok = False
    if not ok:
        raise typer.Exit(code=1)


@app.command(name="list-servers")
def list_servers(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
) -> None:
    """Show the servers declared in a config file."""
    cfg = load_config(config)
    table = Table(title="Configured servers")
    table.add_column("id", style="bold")
    table.add_column("display name")
    table.add_column("trust")
    table.add_column("transport")
    table.add_column("endpoint")
    for s in cfg.servers:
        endpoint = " ".join(s.command) if s.transport == "stdio" else (s.url or "-")
        table.add_row(s.id, s.display_name, s.trust.value, s.transport, endpoint)
    console.print(table)


@app.command()
def ping(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    server: Annotated[str, typer.Option("--server", "-s")],
    method: Annotated[str, typer.Option("--method", "-m")] = "tools/list",
) -> None:
    """Send one JSON-RPC call to a server through the proxy and print the result.

    Performs the MCP initialize handshake first so real servers accept the
    subsequent call.
    """
    cfg = load_config(config)
    proxy = build_proxy(cfg)

    async def go() -> None:
        await proxy.router.start_all()
        try:
            await proxy.handle(
                RpcRequest(
                    method="initialize",
                    params={
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "provmcp-ping", "version": __version__},
                    },
                    request_id=1,
                    target_server_id=server,
                )
            )
            transport = proxy.router.get(server)
            with contextlib.suppress(Exception):
                await transport.call("notifications/initialized", {})
            response = await proxy.handle(
                RpcRequest(
                    method=method,
                    params={},
                    request_id=2,
                    target_server_id=server,
                )
            )
            console.print_json(data=response.result)
        finally:
            await proxy.router.close_all()

    asyncio.run(go())


@app.command()
def run(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    host: Annotated[str | None, typer.Option("--host")] = None,
    port: Annotated[int | None, typer.Option("--port")] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
) -> None:
    """Start the ProvMCP HTTP server loop.

    Loads the config, wires a Proxy, and serves JSON-RPC over HTTP so MCP
    clients can connect at `/mcp/<server_id>`.
    """
    cfg = load_config(config)
    bind_host = host or cfg.proxy.host
    bind_port = port or cfg.proxy.port
    fastapi_app = build_app(build_proxy(cfg))
    console.print(
        f"ProvMCP serving {len(cfg.servers)} server(s) on "
        f"[bold]http://{bind_host}:{bind_port}[/bold]"
    )
    uvicorn.run(fastapi_app, host=bind_host, port=bind_port, log_level=log_level)


@app.command(name="export-claude-config")
def export_claude_config(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 7337,
) -> None:
    """Print a Claude Desktop config stanza that points at ProvMCP.

    Writes the JSON to stdout so you can paste it (or pipe it) into the
    Claude Desktop config file at:

        ~/Library/Application Support/Claude/claude_desktop_config.json

    One MCP host entry per ProvMCP-managed server, each pointing at the
    correct `/mcp/<server_id>` endpoint.
    """
    cfg = load_config(config)
    stanza = {
        "mcpServers": {
            s.id: {
                "url": f"http://{host}:{port}/mcp/{s.id}",
                "transport": "http",
            }
            for s in cfg.servers
        }
    }
    print(json.dumps(stanza, indent=2))


if __name__ == "__main__":
    app()
