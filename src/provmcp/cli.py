"""Command-line entry point.

Only the `version` and `doctor` subcommands are wired in Week 1. The `run`
subcommand lands in Week 2 when the HTTP transport arrives.
"""

from __future__ import annotations

import sys

import typer
from rich.console import Console

from provmcp import __version__

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
    for module in ("pydantic", "fastapi", "httpx"):
        try:
            __import__(module)
            console.print(f"  {module}: [green]ok[/green]")
        except ImportError as exc:
            console.print(f"  {module}: [red]missing[/red] ({exc})")
            ok = False
    if not ok:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
