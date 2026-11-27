"""Transport abstraction.

A transport takes a JSON-RPC request, sends it to a backing MCP server, and
returns the raw result. The proxy never cares which transport it holds —
stdio for local subprocess servers, HTTP for remote ones, or a fake for
tests. The abstraction keeps the proxy transport-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class TransportError(RuntimeError):
    """Raised when a transport cannot reach or hear back from a server."""


class Transport(ABC):
    """Common shape for every transport implementation."""

    @abstractmethod
    async def start(self) -> None:
        """Spin up whatever the transport needs (process, socket, etc.)."""

    @abstractmethod
    async def call(self, method: str, params: dict[str, Any]) -> Any:
        """Send a JSON-RPC request and return the raw `result` field."""

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification: no id, no response expected.

        The default falls back to `call` and discards the result, which keeps
        simple test doubles working. Real transports override this.
        """
        await self.call(method, params)

    @abstractmethod
    async def close(self) -> None:
        """Release underlying resources. Safe to call more than once."""
