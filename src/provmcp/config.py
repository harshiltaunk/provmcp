"""Config loader.

ProvMCP is configured by a single TOML file. The file declares the proxy's
listening address and one section per connected MCP server, with each server's
transport details and trust class.

Example:

    [proxy]
    host = "127.0.0.1"
    port = 7337
    policy = "warn_and_confirm"

    [[servers]]
    id = "filesystem"
    display_name = "Filesystem (reference)"
    trust = "trusted"
    transport = "stdio"
    command = ["uvx", "mcp-server-filesystem", "/Users/harshil/Documents"]

    [[servers]]
    id = "time"
    display_name = "Time (reference)"
    trust = "trusted"
    transport = "stdio"
    command = ["uvx", "mcp-server-time"]
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from provmcp.policy import PolicyTemplate
from provmcp.registry import TrustClass


class ServerConfig(BaseModel):
    """One connected MCP server as it appears in the TOML file."""

    id: str
    display_name: str
    trust: TrustClass = TrustClass.LIMITED
    transport: Literal["stdio", "http"] = "stdio"
    command: list[str] = Field(default_factory=list)
    url: str | None = None

    @field_validator("id")
    @classmethod
    def _non_empty_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("server id must be non-empty")
        return value

    def validate_transport(self) -> None:
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"server {self.id!r}: stdio transport needs a command")
        if self.transport == "http" and not self.url:
            raise ValueError(f"server {self.id!r}: http transport needs a url")


class ProxyConfig(BaseModel):
    """The [proxy] section of the TOML file."""

    host: str = "127.0.0.1"
    port: int = 7337
    policy: PolicyTemplate = PolicyTemplate.WARN_AND_CONFIRM
    detector_threshold: float = 0.6


class ProvMcpConfig(BaseModel):
    """The whole TOML file."""

    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    servers: list[ServerConfig] = Field(default_factory=list)

    def validate_all(self) -> None:
        seen: set[str] = set()
        for server in self.servers:
            if server.id in seen:
                raise ValueError(f"duplicate server id: {server.id!r}")
            seen.add(server.id)
            server.validate_transport()


def load_config(path: str | Path) -> ProvMcpConfig:
    """Load and validate a TOML config file."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    config = ProvMcpConfig.model_validate(data)
    config.validate_all()
    return config
