"""Config loader.

ProvMCP is configured by a single TOML file with three kinds of section:

- ``[proxy]`` — listening address, default policy, decision threshold, file
  locations for the audit log and the approval store, and optional
  per-server-pair policy overrides.
- ``[detection]`` — which detectors run on live traffic and their settings.
- ``[[servers]]`` — one entry per backing MCP server.

Example:

    [proxy]
    host = "127.0.0.1"
    port = 7337
    policy = "warn_and_confirm"
    detector_threshold = 0.6
    audit_log = "../logs/audit.jsonl"        # relative to this file
    approvals_file = "../logs/approvals.json"

    [[proxy.pair_policies]]
    source = "calendar"
    target = "email"
    policy = "strict"

    [detection]
    detectors = ["substring", "structured"]
    allowlist = ["dana.lee@fresnostate.edu"]

    [[servers]]
    id = "time"
    display_name = "Time (reference)"
    trust = "trusted"
    transport = "stdio"
    command = ["uvx", "mcp-server-time"]

Relative file paths are resolved against the directory that holds the config
file, so the config behaves the same no matter which directory a process is
started from. Claude Desktop, for example, launches bridges from `/`.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, PrivateAttr, field_validator

from provmcp.policy import PolicyTemplate
from provmcp.registry import TrustClass

DetectorName = Literal["substring", "structured", "embedding"]


def _default_detectors() -> list[DetectorName]:
    return ["substring", "structured"]


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


class PairPolicy(BaseModel):
    """Override the default policy for one (source server, target server) pair."""

    source: str
    target: str
    policy: PolicyTemplate


class ProxyConfig(BaseModel):
    """The [proxy] section of the TOML file."""

    host: str = "127.0.0.1"
    port: int = 7337
    policy: PolicyTemplate = PolicyTemplate.WARN_AND_CONFIRM
    detector_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    audit_log: str | None = None
    approvals_file: str | None = None
    approval_ttl_seconds: float = Field(default=600.0, gt=0)
    pair_policies: list[PairPolicy] = Field(default_factory=list)


class DetectionConfig(BaseModel):
    """The [detection] section: which detectors inspect live traffic."""

    enabled: bool = True
    detectors: list[DetectorName] = Field(default_factory=_default_detectors)
    substring_min_run: int = Field(default=8, ge=2)
    embedding_threshold: float = Field(default=0.72, gt=0.0, le=1.0)
    allowlist: list[str] = Field(default_factory=list)


class ProvMcpConfig(BaseModel):
    """The whole TOML file."""

    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    servers: list[ServerConfig] = Field(default_factory=list)

    _config_dir: Path | None = PrivateAttr(default=None)

    def validate_all(self) -> None:
        seen: set[str] = set()
        for server in self.servers:
            if server.id in seen:
                raise ValueError(f"duplicate server id: {server.id!r}")
            seen.add(server.id)
            server.validate_transport()
        for pair in self.proxy.pair_policies:
            for side in (pair.source, pair.target):
                if side not in seen:
                    raise ValueError(f"pair policy names unknown server: {side!r}")
        if self.detection.enabled and not self.detection.detectors:
            raise ValueError("detection is enabled but no detectors are listed")

    def resolve_path(self, value: str | None) -> Path | None:
        """Expand `~` and resolve a relative path against the config file's directory."""
        if value is None:
            return None
        path = Path(value).expanduser()
        if not path.is_absolute() and self._config_dir is not None:
            path = self._config_dir / path
        return path.resolve()


def load_config(path: str | Path) -> ProvMcpConfig:
    """Load and validate a TOML config file."""
    config_path = Path(path)
    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    config = ProvMcpConfig.model_validate(data)
    config._config_dir = config_path.resolve().parent
    config.validate_all()
    return config
