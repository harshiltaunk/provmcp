"""Registry of connected MCP servers.

Each connected server has an identity, a declared capability set, and a trust
class that the policy engine reads when deciding what to do with a cross-origin
flow. The registry is populated at proxy startup from the config file.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TrustClass(str, Enum):
    """How far the user trusts outputs from this server.

    - `trusted`     — local, known-good (e.g. filesystem on the user's Mac)
    - `limited`     — third-party but vetted (e.g. the user's own calendar)
    - `untrusted`   — arbitrary network content (e.g. a fetch server reading
                      web pages the user did not write)
    """

    TRUSTED = "trusted"
    LIMITED = "limited"
    UNTRUSTED = "untrusted"


class ServerRecord(BaseModel):
    """What ProvMCP knows about one connected server."""

    server_id: str
    display_name: str
    endpoint: str
    trust: TrustClass = TrustClass.LIMITED
    tools: list[str] = Field(default_factory=list)


class ServerRegistry:
    """Lookup table keyed by server_id."""

    def __init__(self, records: list[ServerRecord] | None = None) -> None:
        self._records: dict[str, ServerRecord] = {}
        for record in records or []:
            self.add(record)

    def add(self, record: ServerRecord) -> None:
        if record.server_id in self._records:
            raise ValueError(f"duplicate server_id: {record.server_id!r}")
        self._records[record.server_id] = record

    def get(self, server_id: str) -> ServerRecord:
        if server_id not in self._records:
            raise KeyError(f"unknown server_id: {server_id!r}")
        return self._records[server_id]

    def all(self) -> list[ServerRecord]:
        return list(self._records.values())

    def __contains__(self, server_id: object) -> bool:
        return isinstance(server_id, str) and server_id in self._records

    def __len__(self) -> int:
        return len(self._records)
