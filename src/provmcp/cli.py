"""Command-line entry point."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from provmcp import __version__
from provmcp.config import load_config
from provmcp.proxy import RpcRequest
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
    for module in ("pydantic", "fastapi", "httpx", "typer"):
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
            # MCP handshake: initialize then notifications/initialized.
            await proxy.handle(
                RpcRequest(
                    method="initialize",
                    params={
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "provmcp-ping", "version": "0.2.0"},
                    },
                    request_id=1,
                    target_server_id=server,
                )
            )
            # Notification: no id, no response expected. Fire-and-forget via
            # the transport directly since handle() assumes a reply.
            transport = proxy.router.get(server)
            try:
                await transport.call("notifications/initialized", {})
            except Exception:  # noqa: BLE001 — notifications may not reply
                pass

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


if __name__ == "__main__":
    app()
