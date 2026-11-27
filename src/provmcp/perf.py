"""Week 11 performance measurement: latency and memory against the proposal's targets.

Targets: under 50 ms added per tool call, and under 100 MB of memory.

What is measured:

- `bench_detector`: one detector's `scan` time per outbound call, with a
  provenance store of a given size. With and without the per-payload cache
  (`ProvenanceStore(cache_derived=...)`).
- `bench_proxy_stdio`: the same calls sent straight to a stdio MCP server,
  and through an in-process ProvMCP Proxy with the default detection. The
  difference is what ProvMCP adds.
- `bench_daemon_latency`: calls over HTTP to a real `provmcp run` daemon,
  sequential and concurrent, with process memory (RSS).
- `bench_daemon_memory`: RSS of the daemon across a long session, with an
  unbounded and a bounded provenance store.
- `probe_embedding`: in a fresh process, the memory and time the embedding
  model costs.

The synthetic workload is realistic in shape: about 1 KB tool results that
contain an email address, a URL, a file path and an ID, and outbound calls
that never match them, so nothing is held and every call is fully
inspected. Words are at most 7 characters, so no accidental 8-character
substring matches occur.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import random
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

from provmcp.config import DetectionConfig, ProvMcpConfig, ProxyConfig, ServerConfig
from provmcp.detectors.base import Detector
from provmcp.policy import PolicyTemplate
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.proxy import RpcRequest
from provmcp.transports.stdio import StdioTransport
from provmcp.wiring import build_proxy

REPO_ROOT = Path(__file__).resolve().parents[2]
ECHO = REPO_ROOT / "examples" / "dummy_server" / "echo_server.py"
_VOCABULARY = (
    "the a of and to in we our for team plan next week sync notes about review build "
    "test fix ship data model agent tool call send read write note task meet room time "
    "date budget draft report memo update status owner risk issue goal item list check"
)
WORDS = _VOCABULARY.split()


def percentiles(samples: Sequence[float]) -> dict[str, float]:
    """Nearest-rank p50 / p95 / p99, mean and max (milliseconds in, milliseconds out)."""
    if not samples:
        return {"n": 0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "max": 0.0}
    ordered = sorted(samples)

    def rank(q: float) -> float:
        return ordered[max(0, math.ceil(q * len(ordered)) - 1)]

    return {
        "n": len(ordered),
        "p50": round(rank(0.50), 4),
        "p95": round(rank(0.95), 4),
        "p99": round(rank(0.99), 4),
        "mean": round(sum(ordered) / len(ordered), 4),
        "max": round(ordered[-1], 4),
    }


def rss_mb(pid: int) -> float | None:
    """Resident memory of a process in MB, via `ps` (same units on macOS and Linux)."""
    try:
        out = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return round(int(out) / 1024, 1) if out else None


def _text(rng: random.Random, words: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(words))


def synthetic_payload(i: int, rng: random.Random) -> dict[str, Any]:
    """A ~1 KB MCP tool result with one email, URL, path and ID in it."""
    body = (
        f"{_text(rng, 60)}. Contact owner{i}@corp{i % 50}.example about it. "
        f"See https://wiki{i % 20}.example/page/{i} and /srv/data/proj{i}/notes.txt. "
        f"Ticket {100000 + i}. {_text(rng, 80)}."
    )
    return {"content": [{"type": "text", "text": body}], "isError": False}


def synthetic_call(i: int, rng: random.Random) -> dict[str, Any]:
    """An outbound `tools/call` that shares nothing with any payload."""
    return {
        "name": "send",
        "arguments": {
            "to": f"peer{i}@fresnostate.edu",
            "subject": _text(rng, 5),
            "body": _text(rng, 50),
        },
    }


def bench_detector(
    name: str,
    detector: Detector,
    *,
    store_size: int,
    calls: int,
    cached: bool,
    seed: int = 0,
) -> dict[str, Any]:
    """Time `detector.scan` per call against a store of `store_size` payloads."""
    rng = random.Random(seed)
    store = ProvenanceStore(cache_derived=cached)
    for i in range(store_size):
        server = "src" if i % 4 else "other"
        store.record(
            TaggedPayload(content=synthetic_payload(i, rng), tag=OriginTag(server_id=server))
        )
    params = [synthetic_call(i, rng) for i in range(calls + 1)]
    start = time.perf_counter()
    detector.scan(store=store, target_server_id="dst", outbound_params=params[0])
    first_ms = (time.perf_counter() - start) * 1000
    samples: list[float] = []
    for p in params[1:]:
        start = time.perf_counter()
        detector.scan(store=store, target_server_id="dst", outbound_params=p)
        samples.append((time.perf_counter() - start) * 1000)
    return {
        "detector": name,
        "store_size": store_size,
        "cached": cached,
        "first_call_ms": round(first_ms, 3),
        **percentiles(samples),
    }


def two_echo_servers(detection: DetectionConfig | None = None, **proxy: Any) -> ProvMcpConfig:
    """Two echo servers ('a', 'b') behind ProvMCP in audit mode, so nothing is held."""
    command = [sys.executable, str(ECHO)]
    return ProvMcpConfig(
        proxy=ProxyConfig(policy=PolicyTemplate.AUDIT, **proxy),
        detection=detection or DetectionConfig(),
        servers=[ServerConfig(id=sid, display_name=sid, command=command) for sid in ("a", "b")],
    )


async def bench_proxy_stdio(calls: int, *, seed: int = 0) -> dict[str, Any]:
    """Per-call latency straight to a stdio server, and through an in-process Proxy."""
    rng = random.Random(seed)
    params = [synthetic_call(i, rng) for i in range(calls)]
    for p in params:  # make each echoed result a ~1 KB payload worth recording
        p["arguments"]["body"] += " " + _text(rng, 120)

    direct = StdioTransport([sys.executable, str(ECHO)])
    await direct.start()
    direct_ms: list[float] = []
    try:
        for p in params:
            start = time.perf_counter()
            await direct.call("tools/call", p)
            direct_ms.append((time.perf_counter() - start) * 1000)
    finally:
        await direct.close()

    proxy = build_proxy(two_echo_servers())
    await proxy.router.start_all()
    proxied_ms: list[float] = []
    try:
        for i, p in enumerate(params):
            request = RpcRequest(
                method="tools/call", params=p, request_id=i, target_server_id="ab"[i % 2]
            )
            start = time.perf_counter()
            await proxy.handle(request)
            proxied_ms.append((time.perf_counter() - start) * 1000)
    finally:
        await proxy.router.close_all()
    d, q = percentiles(direct_ms), percentiles(proxied_ms)
    return {
        "calls": calls,
        "direct": d,
        "through_proxy": q,
        "added_p50_ms": round(q["p50"] - d["p50"], 4),
        "added_p95_ms": round(q["p95"] - d["p95"], 4),
        "store_size_end": len(proxy.store),
    }


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def _toml_config(
    port: int,
    *,
    max_per_server: int,
    detectors: Sequence[str],
    thresholds: dict[str, float] | None = None,
) -> str:
    command = json.dumps([sys.executable, str(ECHO)])
    names = json.dumps(list(detectors))
    extra = ""
    if thresholds:
        pairs = ", ".join(f"{k} = {v}" for k, v in thresholds.items())
        extra = f"thresholds = {{ {pairs} }}\n"
    servers = "".join(
        f'[[servers]]\nid = "{sid}"\ndisplay_name = "{sid}"\ncommand = {command}\n\n'
        for sid in ("a", "b")
    )
    return (
        f'[proxy]\nport = {port}\npolicy = "audit"\n'
        f"provenance_max_per_server = {max_per_server}\n\n"
        f"[detection]\ndetectors = {names}\n{extra}\n{servers}"
    )


@contextlib.asynccontextmanager
async def running_daemon(
    *,
    max_per_server: int = 1000,
    detectors: Sequence[str] = ("substring", "structured"),
    thresholds: dict[str, float] | None = None,
) -> AsyncIterator[tuple[str, int]]:
    """Start `provmcp run` on a free port; yield (base url, pid)."""
    import httpx

    port = free_port()
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "bench.toml"
        config.write_text(
            _toml_config(
                port, max_per_server=max_per_server, detectors=detectors, thresholds=thresholds
            ),
            encoding="utf-8",
        )
        exe = Path(sys.executable).parent / "provmcp"
        proc = subprocess.Popen(
            [str(exe), "run", "-c", str(config), "--log-level", "warning"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            async with httpx.AsyncClient() as client:
                for _ in range(100):
                    try:
                        if (await client.get(f"{url}/health")).status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    await asyncio.sleep(0.1)
                else:
                    raise RuntimeError("provmcp run did not start")
            yield url, proc.pid
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


async def _post(client: Any, url: str, i: int, params: dict[str, Any]) -> float:
    envelope = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": params}
    start = time.perf_counter()
    response = await client.post(f"{url}/mcp/{'ab'[i % 2]}", json=envelope)
    response.raise_for_status()
    return (time.perf_counter() - start) * 1000


async def bench_daemon_latency(
    calls: int,
    concurrency: int,
    *,
    detectors: Sequence[str] = ("substring", "structured"),
    thresholds: dict[str, float] | None = None,
    seed: int = 0,
) -> dict[str, Any]:
    """Sequential and concurrent HTTP latency through a real daemon, plus its memory."""
    import httpx

    rng = random.Random(seed)
    params = [synthetic_call(i, rng) for i in range(calls)]
    async with running_daemon(detectors=detectors, thresholds=thresholds) as (url, pid):
        idle = rss_mb(pid)
        async with httpx.AsyncClient(timeout=120) as client:
            await _post(client, url, 0, params[0])  # warm-up: loads models, starts caches
            sequential = [await _post(client, url, i, p) for i, p in enumerate(params)]
            gate = asyncio.Semaphore(concurrency)

            async def one(i: int, p: dict[str, Any]) -> float:
                async with gate:
                    return await _post(client, url, i, p)

            start = time.perf_counter()
            concurrent = await asyncio.gather(*(one(i, p) for i, p in enumerate(params)))
            wall = time.perf_counter() - start
        busy = rss_mb(pid)
    return {
        "detectors": list(detectors),
        "calls": calls,
        "concurrency": concurrency,
        "sequential": percentiles(sequential),
        "concurrent": percentiles(list(concurrent)),
        "throughput_calls_per_s": round(calls / wall, 1),
        "rss_idle_mb": idle,
        "rss_after_mb": busy,
    }


async def bench_daemon_memory(
    calls: int, *, max_per_server: int, sample_every: int, seed: int = 0
) -> dict[str, Any]:
    """Daemon RSS across a long session of ~1 KB results, sampled every N calls."""
    import httpx

    rng = random.Random(seed)
    async with running_daemon(max_per_server=max_per_server) as (url, pid):
        samples: list[dict[str, float | int | None]] = [{"calls": 0, "rss_mb": rss_mb(pid)}]
        async with httpx.AsyncClient(timeout=60) as client:
            for i in range(1, calls + 1):
                p = synthetic_call(i, rng)
                p["arguments"]["body"] += " " + _text(rng, 120)
                await _post(client, url, i, p)
                if i % sample_every == 0:
                    health = (await client.get(f"{url}/health")).json()
                    samples.append(
                        {"calls": i, "rss_mb": rss_mb(pid), "store_size": health.get("store_size")}
                    )
    return {"max_per_server": max_per_server, "calls": calls, "samples": samples}


def probe_embedding(model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> dict[str, Any]:
    """Run in a fresh process: memory and time of loading and using the embedding model."""
    code = (
        "import json, os, time\n"
        "from provmcp.perf import rss_mb, percentiles\n"
        "pid = os.getpid(); out = {'rss_start_mb': rss_mb(pid)}\n"
        "t = time.perf_counter(); from sentence_transformers import SentenceTransformer\n"
        "out['import_s'] = round(time.perf_counter() - t, 2); out['rss_import_mb'] = rss_mb(pid)\n"
        f"t = time.perf_counter(); m = SentenceTransformer({model_name!r})\n"
        "out['load_s'] = round(time.perf_counter() - t, 2); out['rss_loaded_mb'] = rss_mb(pid)\n"
        "m.encode(['warm up the model once'])\n"
        "s = []\n"
        "for i in range(50):\n"
        "    t = time.perf_counter(); m.encode([f'send the notes for sprint {i} to the team'])\n"
        "    s.append((time.perf_counter() - t) * 1000)\n"
        "out['encode_one_sentence_ms'] = percentiles(s); out['rss_after_mb'] = rss_mb(pid)\n"
        "print(json.dumps(out))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip().splitlines()[-1] if result.stderr else "failed"}
    parsed: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    return parsed
