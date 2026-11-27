"""Week 11: bounded store, per-payload caches, and the benchmark harness."""

from __future__ import annotations

import importlib.util
import os
import random
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from provmcp.config import DetectionConfig, ProvMcpConfig
from provmcp.detectors import StructuredFieldDetector, SubstringDetector
from provmcp.perf import (
    bench_detector,
    bench_proxy_stdio,
    percentiles,
    rss_mb,
    synthetic_call,
    synthetic_payload,
)
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.svgchart import grouped_value_bars
from provmcp.wiring import build_detector, build_proxy
from tests.test_live_enforcement import REPO

HAS_DAEMON = all(importlib.util.find_spec(m) for m in ("fastapi", "uvicorn", "httpx"))


def _payload(server: str, text: str = "x") -> TaggedPayload:
    return TaggedPayload(content=text, tag=OriginTag(server_id=server))


def test_cap_is_per_server_so_one_server_cannot_flush_another() -> None:
    store = ProvenanceStore(max_per_server=3)
    victim = _payload("calendar", "Exfil@Evil.Example")
    store.record(victim)
    for i in range(50):  # a chatty or hostile server
        store.record(_payload("noisy", f"spam {i}"))
    assert store.get(victim.tag.tag_id) is not None
    assert len(store.from_server("noisy")) == 3
    assert [p.content for p in store.from_server("noisy")] == ["spam 47", "spam 48", "spam 49"]
    assert store.evicted == 47


def test_ttl_expires_old_payloads_on_read_and_write() -> None:
    now = [0.0]
    store = ProvenanceStore(ttl_seconds=10, clock=lambda: now[0])
    old = _payload("a", "old")
    store.record(old)
    now[0] = 5
    store.record(_payload("a", "newer"))
    now[0] = 12
    assert [p.content for p in store.payloads()] == ["newer"]
    now[0] = 20
    assert store.payloads() == [] and len(store) == 0


def test_derived_data_is_computed_once_and_dropped_with_the_payload() -> None:
    store = ProvenanceStore(max_per_server=1)
    first = _payload("a")
    store.record(first)
    calls: list[int] = []

    def compute() -> int:
        calls.append(1)
        return 42

    assert store.derived(first.tag.tag_id, "k", compute) == 42
    assert store.derived(first.tag.tag_id, "k", compute) == 42
    assert len(calls) == 1
    store.record(_payload("a"))  # evicts `first`
    assert store.derived(first.tag.tag_id, "k", compute) == 42
    assert len(calls) == 2  # not cached for an evicted payload
    assert first.tag.tag_id not in store._derived  # noqa: SLF001


def test_cache_can_be_switched_off() -> None:
    store = ProvenanceStore(cache_derived=False)
    payload = _payload("a")
    store.record(payload)
    calls: list[int] = []
    for _ in range(3):
        store.derived(payload.tag.tag_id, "k", lambda: calls.append(1) or 0)
    assert len(calls) == 3


def test_invalid_bounds_are_rejected() -> None:
    with pytest.raises(ValueError):
        ProvenanceStore(max_per_server=0)
    with pytest.raises(ValueError):
        ProvenanceStore(ttl_seconds=0)


def test_cached_and_uncached_detectors_find_exactly_the_same() -> None:
    rng = random.Random(3)
    payloads = [synthetic_payload(i, rng) for i in range(30)]
    calls = [synthetic_call(i, rng) for i in range(10)]
    calls += [  # calls that do reuse content from stored payloads
        {"name": "send", "arguments": {"to": "owner7@corp7.example", "body": "hi"}},
        {"name": "fetch", "arguments": {"url": "https://wiki3.example/page/3"}},
        {"name": "write", "arguments": {"path": "/srv/data/proj12/notes.txt"}},
    ]
    detectors = [
        SubstringDetector(),
        SubstringDetector(score_mode="coverage"),
        StructuredFieldDetector(),
        build_detector(ProvMcpConfig(detection=DetectionConfig())),
    ]
    stores = {}
    for cached in (True, False):
        store = ProvenanceStore(cache_derived=cached)
        for i, content in enumerate(payloads):
            store.record(TaggedPayload(content=content, tag=OriginTag(server_id=f"s{i % 3}")))
        stores[cached] = store
    for detector in detectors:
        for call in calls:
            found = {
                cached: sorted(
                    (f.source_server_id, round(f.confidence, 6), f.excerpt)
                    for f in detector.scan(
                        store=stores[cached], target_server_id="dst", outbound_params=call
                    )
                )
                for cached in (True, False)
            }
            # scan twice with the cache, to use the cached path as well
            again = sorted(
                (f.source_server_id, round(f.confidence, 6), f.excerpt)
                for f in detector.scan(
                    store=stores[True], target_server_id="dst", outbound_params=call
                )
            )
            assert found[True] == found[False] == again
    hits = build_detector(ProvMcpConfig(detection=DetectionConfig())).scan(
        store=stores[True], target_server_id="dst", outbound_params=calls[-3]
    )
    assert hits  # the reuse calls are actually detected


def test_proxy_store_is_bounded_by_default() -> None:
    config = ProvMcpConfig()
    assert config.proxy.provenance_max_per_server == 1000
    assert config.proxy.provenance_ttl_seconds is None
    assert build_proxy(config).store.max_per_server == 1000


def test_percentiles_use_nearest_rank() -> None:
    stats = percentiles([float(i) for i in range(1, 101)])
    assert (stats["p50"], stats["p95"], stats["p99"], stats["max"]) == (50.0, 95.0, 99.0, 100.0)
    assert percentiles([])["n"] == 0


def test_rss_of_this_process_is_measurable() -> None:
    value = rss_mb(os.getpid())
    assert value is not None and value > 5


def test_synthetic_workload_never_matches_by_accident() -> None:
    rng = random.Random(0)
    store = ProvenanceStore()
    for i in range(50):
        payload = synthetic_payload(i, rng)
        assert 800 < len(payload["content"][0]["text"]) < 1400
        store.record(TaggedPayload(content=payload, tag=OriginTag(server_id="src")))
    detector = build_detector(ProvMcpConfig(detection=DetectionConfig(thresholds={})))
    for i in range(20):
        assert (
            detector.scan(
                store=store, target_server_id="dst", outbound_params=synthetic_call(i, rng)
            )
            == []
        )


def test_bench_detector_reports_percentiles() -> None:
    row = bench_detector(
        "structured", StructuredFieldDetector(), store_size=20, calls=10, cached=True
    )
    assert row["n"] == 10 and row["store_size"] == 20 and row["p95"] >= row["p50"] >= 0


async def test_bench_proxy_stdio_measures_added_latency() -> None:
    result = await bench_proxy_stdio(20)
    assert result["direct"]["n"] == result["through_proxy"]["n"] == 20
    assert result["store_size_end"] == 20  # every echoed result recorded, none held


def test_value_chart_is_valid_svg_with_log_axis_and_target() -> None:
    svg = grouped_value_bars(
        "Latency",
        "sub",
        ["a", "b"],
        [("10", [(0.05, 0.08), (2.0, 3.5)]), ("100", [(0.4, 0.6), None])],
        unit="ms",
        target=50,
        log=True,
    )
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "target 50.0 ms" in svg and "not measured" in svg
    assert "0.010 ms" in svg and "100 ms" in svg  # decade ticks


@pytest.mark.skipif(not HAS_DAEMON, reason="needs fastapi, uvicorn and httpx")
async def test_live_daemon_store_stays_within_its_bound() -> None:
    from provmcp.perf import bench_daemon_latency, bench_daemon_memory

    latency = await bench_daemon_latency(10, 2)
    assert latency["sequential"]["n"] == 10 and latency["rss_idle_mb"]
    memory = await bench_daemon_memory(40, max_per_server=5, sample_every=20)
    assert [s["store_size"] for s in memory["samples"][1:]] == [10, 10]  # 2 servers x 5


def test_benchmark_script_quick_run(tmp_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "bench_week11.py"),
            "--quick",
            "--skip-http",
            "--skip-embedding",
            "--out",
            str(tmp_path / "p.md"),
            "--json",
            str(tmp_path / "p.json"),
            "--figures",
            str(tmp_path / "fig"),
        ],
        check=True,
        capture_output=True,
        cwd=REPO,
    )
    report = (tmp_path / "p.md").read_text()
    assert "## 1. Detector cost per call" in report and "Added by ProvMCP" in report
    assert (tmp_path / "fig" / "week11-detector-latency.svg").exists()
