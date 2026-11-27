"""Tests for the wiring that turns a parsed config into a live Proxy."""

from __future__ import annotations

from pathlib import Path

from provmcp.config import load_config
from provmcp.transports.http import HttpTransport
from provmcp.transports.stdio import StdioTransport
from provmcp.wiring import build_proxy, build_registry, build_router


def _config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "x.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_build_registry_from_config(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        """
[[servers]]
id = "a"
display_name = "Alpha"
transport = "stdio"
command = ["echo"]
trust = "trusted"

[[servers]]
id = "b"
display_name = "Beta"
transport = "http"
url = "http://127.0.0.1:9000"
trust = "untrusted"
""",
    )
    cfg = load_config(path)
    registry = build_registry(cfg)
    assert len(registry) == 2
    assert registry.get("a").display_name == "Alpha"


def test_build_router_picks_stdio_or_http(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        """
[[servers]]
id = "a"
display_name = "A"
transport = "stdio"
command = ["echo"]

[[servers]]
id = "b"
display_name = "B"
transport = "http"
url = "http://127.0.0.1:9000"
""",
    )
    cfg = load_config(path)
    router = build_router(cfg)
    assert isinstance(router.get("a"), StdioTransport)
    assert isinstance(router.get("b"), HttpTransport)


def test_build_proxy_end_to_end(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        """
[[servers]]
id = "a"
display_name = "A"
transport = "stdio"
command = ["echo"]
""",
    )
    proxy = build_proxy(load_config(path))
    assert "a" in [r.server_id for r in proxy.registry.all()]
    assert proxy.router.server_ids() == ["a"]
    assert len(proxy.store) == 0


def test_build_inspector_follows_detection_section(tmp_path: Path) -> None:
    from provmcp.detectors import CompositeDetector, StructuredFieldDetector
    from provmcp.wiring import build_inspector

    servers = '[[servers]]\nid = "a"\ndisplay_name = "A"\ncommand = ["echo"]\n'
    one = load_config(_config(tmp_path, '[detection]\ndetectors = ["structured"]\n' + servers))
    inspector = build_inspector(one)
    assert inspector is not None
    inner = getattr(inspector.detector, "detector", inspector.detector)  # gated since 0.9.0
    assert isinstance(inner, StructuredFieldDetector)

    both = load_config(_config(tmp_path, servers))
    built = build_inspector(both)
    assert built is not None
    assert isinstance(built.detector, CompositeDetector)

    off = load_config(_config(tmp_path, "[detection]\nenabled = false\n" + servers))
    assert build_inspector(off) is None
