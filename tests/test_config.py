"""Tests for the TOML config loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from provmcp.config import load_config
from provmcp.policy import PolicyTemplate
from provmcp.registry import TrustClass


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "provmcp.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_loads_minimal_config(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
[proxy]
host = "127.0.0.1"
port = 7337

[[servers]]
id = "time"
display_name = "Time"
trust = "trusted"
transport = "stdio"
command = ["uvx", "mcp-server-time"]
""",
    )
    config = load_config(path)
    assert config.proxy.host == "127.0.0.1"
    assert config.proxy.port == 7337
    assert config.proxy.policy is PolicyTemplate.WARN_AND_CONFIRM
    assert len(config.servers) == 1
    server = config.servers[0]
    assert server.id == "time"
    assert server.trust is TrustClass.TRUSTED
    assert server.transport == "stdio"
    assert server.command == ["uvx", "mcp-server-time"]


def test_rejects_stdio_without_command(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
[[servers]]
id = "broken"
display_name = "Broken"
transport = "stdio"
""",
    )
    with pytest.raises(ValueError):
        load_config(path)


def test_rejects_http_without_url(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
[[servers]]
id = "broken"
display_name = "Broken"
transport = "http"
""",
    )
    with pytest.raises(ValueError):
        load_config(path)


def test_rejects_duplicate_server_ids(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
[[servers]]
id = "a"
display_name = "A"
transport = "stdio"
command = ["echo"]

[[servers]]
id = "a"
display_name = "A again"
transport = "stdio"
command = ["echo"]
""",
    )
    with pytest.raises(ValueError):
        load_config(path)


def test_policy_round_trip(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
[proxy]
policy = "strict"
""",
    )
    config = load_config(path)
    assert config.proxy.policy is PolicyTemplate.STRICT
