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


SERVERS = """
[[servers]]
id = "calendar"
display_name = "Calendar"
command = ["echo"]

[[servers]]
id = "email"
display_name = "Email"
command = ["echo"]
"""


def test_detection_defaults(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, SERVERS))
    assert config.detection.enabled is True
    assert config.detection.detectors == ["substring", "structured"]
    assert config.proxy.audit_log is None
    assert config.proxy.pair_policies == []


def test_pair_policy_parsed(tmp_path: Path) -> None:
    body = (
        '[[proxy.pair_policies]]\nsource = "calendar"\ntarget = "email"\npolicy = "strict"\n'
        + SERVERS
    )
    config = load_config(_write(tmp_path, body))
    pair = config.proxy.pair_policies[0]
    assert (pair.source, pair.target, pair.policy) == ("calendar", "email", PolicyTemplate.STRICT)


def test_pair_policy_with_unknown_server_rejected(tmp_path: Path) -> None:
    body = (
        '[[proxy.pair_policies]]\nsource = "calendar"\ntarget = "slack"\npolicy = "strict"\n'
        + SERVERS
    )
    with pytest.raises(ValueError):
        load_config(_write(tmp_path, body))


def test_enabled_detection_needs_a_detector(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_config(_write(tmp_path, "[detection]\ndetectors = []\n" + SERVERS))


def test_unknown_detector_name_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_config(_write(tmp_path, '[detection]\ndetectors = ["regex"]\n' + SERVERS))


def test_relative_paths_resolve_against_config_dir(tmp_path: Path) -> None:
    sub = tmp_path / "configs"
    sub.mkdir()
    path = sub / "p.toml"
    path.write_text('[proxy]\naudit_log = "../logs/a.jsonl"\n' + SERVERS, encoding="utf-8")
    config = load_config(path)
    assert config.resolve_path(config.proxy.audit_log) == (tmp_path / "logs" / "a.jsonl").resolve()
    assert config.resolve_path(None) is None
