"""Week 11: performance overhead against the proposal's targets (<50 ms per call, <100 MB).

    python scripts/bench_week11.py            # full run, about 5-10 minutes
    python scripts/bench_week11.py --quick    # a smoke run, under a minute

Writes docs/results/perf-week11.md, docs/results/perf-week11.json and SVG
figures in docs/results/figures/. Timings depend on the machine: run it on
the machine you report. The embedding parts run when sentence-transformers is
installed (set HF_HUB_OFFLINE=1 to use the cached model). No model API is
called.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import platform
from datetime import date
from pathlib import Path
from typing import Any

from provmcp import __version__
from provmcp.config import DetectionConfig, ProvMcpConfig
from provmcp.detectors import EmbeddingDetector, StructuredFieldDetector, SubstringDetector
from provmcp.detectors.base import Detector
from provmcp.perf import (
    bench_daemon_latency,
    bench_daemon_memory,
    bench_detector,
    bench_proxy_stdio,
    probe_embedding,
)
from provmcp.svgchart import grouped_value_bars
from provmcp.wiring import build_detector

REPO = Path(__file__).parent.parent
TARGET_MS = 50.0
TARGET_MB = 100.0


def verdict(ok: bool) -> str:
    return "**meets target**" if ok else "**misses target**"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--quick", action="store_true", help="small sizes, for verification")
    parser.add_argument("--skip-http", action="store_true", help="skip the daemon benchmarks")
    parser.add_argument("--skip-embedding", action="store_true")
    parser.add_argument(
        "--calibration", type=Path, default=REPO / "docs/results/calibration-week9.json"
    )
    parser.add_argument("--out", type=Path, default=REPO / "docs/results/perf-week11.md")
    parser.add_argument("--json", type=Path, default=REPO / "docs/results/perf-week11.json")
    parser.add_argument("--figures", type=Path, default=REPO / "docs/results/figures")
    args = parser.parse_args()

    quick = args.quick
    sizes = [10, 100] if quick else [10, 100, 1000]
    calls = 20 if quick else 200
    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    thresholds: dict[str, float] = dict(calibration.get("thresholds", {}))
    embedding = (
        not args.skip_embedding
        and importlib.util.find_spec("sentence_transformers") is not None
        and "embedding" in thresholds
    )
    machine = f"{platform.system()} {platform.machine()}, Python {platform.python_version()}"
    summary: dict[str, Any] = {"provmcp": __version__, "machine": machine, "quick": quick}
    md = [
        "# Week 11 performance",
        "",
        f"- **date:** {date.today().isoformat()}",
        f"- **provmcp:** {__version__}",
        f"- **machine:** {machine}",
        f"- **mode:** {'quick (smoke sizes)' if quick else 'full'}",
        f"- **targets:** under {TARGET_MS:g} ms added per tool call; under {TARGET_MB:g} MB",
        "- Workload: ~1 KB tool results with an email, URL, path and ID each; outbound "
        "calls that match nothing, so every call is fully inspected and none is held.",
        "",
        "## 1. Detector cost per call",
        "",
        "Time for one `scan` of an outbound call against a provenance store of N "
        "payloads, in ms. *Cached* is the 0.11 store (per-payload work done once); "
        "*no cache* is the behaviour up to 0.10.",
        "",
        "| detector | cache | store size | p50 | p95 | p99 | first call |",
        "|---|---|---|---|---|---|---|",
    ]

    detectors: list[tuple[str, Detector, list[int], int]] = [
        ("substring", SubstringDetector(), sizes, calls),
        ("structured", StructuredFieldDetector(), sizes, calls),
        ("0.9.0 default", build_detector(ProvMcpConfig(detection=DetectionConfig())), sizes, calls),
    ]
    if embedding:
        emb = EmbeddingDetector(threshold=thresholds["embedding"])
        detectors.append(("embedding", emb, sizes, 5 if quick else 30))
    rows: list[dict[str, Any]] = []
    for name, detector, ns, n_calls in detectors:
        for cached in (True, False):
            for n in ns:
                if name == "embedding" and not cached and n > 100:
                    continue  # re-encodes every payload on every call: minutes per call
                row = bench_detector(name, detector, store_size=n, calls=n_calls, cached=cached)
                rows.append(row)
                md.append(
                    f"| {name} | {'yes' if cached else 'no'} | {n} | {row['p50']:.3f} "
                    f"| {row['p95']:.3f} | {row['p99']:.3f} | {row['first_call_ms']:.1f} |"
                )
    summary["detectors"] = rows
    worst_default = max(r["p95"] for r in rows if r["detector"] == "0.9.0 default" and r["cached"])
    md += [
        "",
        f"0.9.0 default, cached, worst p95 over all store sizes: {worst_default:.2f} ms: "
        f"{verdict(worst_default < TARGET_MS)}.",
        "",
    ]
    categories: list[str] = []
    for name, *_ in detectors:
        categories += [name, f"{name}, no cache"]
    series: list[tuple[str, list[tuple[float, float] | None]]] = []
    for n in sizes:
        values: list[tuple[float, float] | None] = []
        for name, *_ in detectors:
            for cached in (True, False):
                match = [
                    r
                    for r in rows
                    if r["detector"] == name and r["cached"] == cached and r["store_size"] == n
                ]
                values.append((match[0]["p50"], match[0]["p95"]) if match else None)
        series.append((f"{n} payloads", values))
    args.figures.mkdir(parents=True, exist_ok=True)
    (args.figures / "week11-detector-latency.svg").write_text(
        grouped_value_bars(
            "Detector time per tool call",
            "Bar: median; whisker: 95th percentile. Log scale. Line: the 50 ms target.",
            categories,
            series,
            unit="ms",
            target=TARGET_MS,
            target_label="target",
            log=True,
        ),
        encoding="utf-8",
    )
    md += ["![Detector latency](figures/week11-detector-latency.svg)", ""]

    md += ["## 2. Added latency through the proxy (stdio, in-process)", ""]
    proxy = asyncio.run(bench_proxy_stdio(50 if quick else 500))
    summary["proxy_stdio"] = proxy
    md += [
        "| path | p50 ms | p95 ms | p99 ms |",
        "|---|---|---|---|",
        f"| straight to the server | {proxy['direct']['p50']:.3f} | {proxy['direct']['p95']:.3f} "
        f"| {proxy['direct']['p99']:.3f} |",
        f"| through ProvMCP (0.9.0 default detection) | {proxy['through_proxy']['p50']:.3f} "
        f"| {proxy['through_proxy']['p95']:.3f} | {proxy['through_proxy']['p99']:.3f} |",
        "",
        f"Added by ProvMCP: {proxy['added_p50_ms']:.3f} ms at p50, {proxy['added_p95_ms']:.3f} ms "
        f"at p95, with {proxy['store_size_end']} payloads stored by the end: "
        f"{verdict(proxy['added_p95_ms'] < TARGET_MS)}.",
        "",
    ]

    if args.skip_http:
        md += ["## 3. Daemon over HTTP", "", "Skipped (--skip-http).", ""]
    else:
        n_http = 50 if quick else 500
        default_http = asyncio.run(bench_daemon_latency(n_http, 8))
        runs = [("0.9.0 default", default_http)]
        if embedding:
            runs.append(
                (
                    "default + embedding",
                    asyncio.run(
                        bench_daemon_latency(
                            20 if quick else 100,
                            8,
                            detectors=("substring", "structured", "embedding"),
                            thresholds=thresholds,
                        )
                    ),
                )
            )
        summary["daemon_latency"] = dict(runs)
        md += [
            "## 3. Daemon over HTTP (`provmcp run`, real loopback requests)",
            "",
            "| detection | calls | sequential p50 / p95 ms | 8 concurrent p50 / p95 ms "
            "| throughput | RSS idle / after |",
            "|---|---|---|---|---|---|",
        ]
        for label, r in runs:
            md.append(
                f"| {label} | {r['calls']} | {r['sequential']['p50']:.2f} / "
                f"{r['sequential']['p95']:.2f} | {r['concurrent']['p50']:.2f} / "
                f"{r['concurrent']['p95']:.2f} | {r['throughput_calls_per_s']} calls/s "
                f"| {r['rss_idle_mb']} / {r['rss_after_mb']} MB |"
            )
        md.append("")
        total = 1000 if quick else 10000
        every = 250 if quick else 1000
        bounded_cap = 100 if quick else 1000
        unbounded = asyncio.run(
            bench_daemon_memory(total, max_per_server=10**9, sample_every=every)
        )
        bounded = asyncio.run(
            bench_daemon_memory(total, max_per_server=bounded_cap, sample_every=every)
        )
        summary["daemon_memory"] = {"unbounded": unbounded, "bounded": bounded}
        md += [
            f"### Memory over a long session ({total} calls, ~1 KB results)",
            "",
            f"| calls | unbounded store: RSS MB (payloads) | bounded ({bounded_cap} per server): "
            "RSS MB (payloads) |",
            "|---|---|---|",
        ]
        for a, b in zip(unbounded["samples"], bounded["samples"], strict=True):
            md.append(
                f"| {a['calls']} | {a['rss_mb']} ({a.get('store_size', '-')}) "
                f"| {b['rss_mb']} ({b.get('store_size', '-')}) |"
            )
        end_u = unbounded["samples"][-1]["rss_mb"] or 0.0
        end_b = bounded["samples"][-1]["rss_mb"] or 0.0
        md += [
            "",
            f"After {total} calls: unbounded {end_u} MB ({verdict(end_u < TARGET_MB)}); "
            f"bounded {end_b} MB ({verdict(end_b < TARGET_MB)}).",
            "",
        ]
        checkpoints = [f"{s['calls']} calls" for s in unbounded["samples"]]
        (args.figures / "week11-memory.svg").write_text(
            grouped_value_bars(
                "Daemon memory over a long session",
                "Resident set size of `provmcp run`. Line: the 100 MB target.",
                checkpoints,
                [
                    ("unbounded store", [(s["rss_mb"] or 0.0,) * 2 for s in unbounded["samples"]]),
                    (
                        f"bounded, {bounded_cap} per server",
                        [(s["rss_mb"] or 0.0,) * 2 for s in bounded["samples"]],
                    ),
                ],
                unit="MB",
                target=TARGET_MB,
                target_label="target",
            ),
            encoding="utf-8",
        )
        md += ["![Memory](figures/week11-memory.svg)", ""]

    md += ["## 4. The embedding model on its own", ""]
    if embedding:
        probe = probe_embedding()
        summary["embedding_probe"] = probe
        if "error" in probe:
            md += [f"Probe failed: {probe['error']}", ""]
        else:
            encode = probe["encode_one_sentence_ms"]
            loaded_mb = probe["rss_after_mb"] or 0
            md += [
                "Measured in a fresh Python process.",
                "",
                "| step | time | RSS after |",
                "|---|---|---|",
                f"| start | - | {probe['rss_start_mb']} MB |",
                f"| import sentence-transformers | {probe['import_s']} s "
                f"| {probe['rss_import_mb']} MB |",
                f"| load all-MiniLM-L6-v2 | {probe['load_s']} s | {probe['rss_loaded_mb']} MB |",
                f"| encode one sentence (p50 / p95) | {encode['p50']:.1f} / {encode['p95']:.1f} ms "
                f"| {probe['rss_after_mb']} MB |",
                "",
                f"Memory with the model loaded: {verdict(loaded_mb < TARGET_MB)}.",
                "",
            ]
    else:
        md += ["Not run (sentence-transformers not installed, or --skip-embedding).", ""]

    report = "\n".join(md)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    args.json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(report)
    print(f"wrote {args.out}, {args.json} and figures in {args.figures}")


if __name__ == "__main__":
    main()
