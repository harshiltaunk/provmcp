"""Week 12: robustness to an adaptive adversary, and what canonical views cost.

    python scripts/evaluate_week12.py \\
        --run haiku-week8=logs/agent-cache-anthropic-claude-haiku-5-5.jsonl \\
        --run haiku-week10=logs/agent-cache-haiku-week10.jsonl

Writes docs/results/adaptive-week12.md, docs/results/adaptive-week12.json and
SVG figures in docs/results/figures/. Thresholds come from
docs/results/calibration-week9.json. The embedding strategies run when
sentence-transformers is installed and the calibration has an embedding
threshold. No model is called.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import date
from pathlib import Path
from typing import Any

from provmcp import __version__
from provmcp.adaptive import Outcome, evaluate, flood_sweep, split_sweep
from provmcp.agent.experiment import load_cache
from provmcp.benchmark import Scenario, load_scenarios
from provmcp.config import DetectionConfig, ProvMcpConfig
from provmcp.evaluation import (
    Rate,
    Strategy,
    detection_and_false_alarms,
    offline_flags,
    real_traffic,
)
from provmcp.perf import bench_detector
from provmcp.svgchart import grouped_rate_bars
from provmcp.wiring import build_detector

REPO = Path(__file__).parent.parent
BUNDLED = ("attacks", "msb", "benign")
DEFAULT = "0.9.0 default"
CANON = "default + canonical"


def strategies(thresholds: dict[str, float], *, embedding: bool) -> list[Strategy]:
    base = {"substring": thresholds["substring"], "structured": thresholds["structured"]}

    def config(detectors: list[str], gates: dict[str, float], canon: bool) -> DetectionConfig:
        return DetectionConfig.model_validate(
            {"detectors": detectors, "thresholds": gates, "canonicalize": canon}
        )

    found = [
        Strategy(DEFAULT, config(["substring", "structured"], base, False)),
        Strategy(CANON, config(["substring", "structured"], base, True)),
    ]
    if embedding:
        emb = {"embedding": thresholds["embedding"]}
        found += [
            Strategy("embedding", config(["embedding"], emb, False)),
            Strategy(
                "canonical + embedding",
                config(["substring", "structured", "embedding"], base | emb, True),
            ),
        ]
    return found


def mark(outcome: Outcome) -> str:
    if not outcome.flagged:
        return "-"
    if outcome.is_attack and not outcome.attributed:
        return f"flagged, origin {'/'.join(outcome.sources)}"
    return "**flagged**" if not outcome.is_attack else "caught"


def parse_runs(items: list[str]) -> list[tuple[str, Path]]:
    runs = []
    for item in items:
        label, sep, path = item.partition("=")
        if not sep or not label or not path:
            raise SystemExit(f"--run needs label=path, got {item!r}")
        runs.append((label, Path(path)))
    return runs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--calibration", type=Path, default=REPO / "docs/results/calibration-week9.json"
    )
    parser.add_argument("--split", type=Path, default=REPO / "benchmarks/splits/week9.json")
    parser.add_argument("--injecagent", type=Path, default=REPO / "benchmarks/external/injecagent")
    parser.add_argument("--run", action="append", default=[], help="label=cache.jsonl")
    parser.add_argument("--skip-embedding", action="store_true")
    parser.add_argument("--quick", action="store_true", help="small sweeps and timings")
    parser.add_argument("--out", type=Path, default=REPO / "docs/results/adaptive-week12.md")
    parser.add_argument("--json", type=Path, default=REPO / "docs/results/adaptive-week12.json")
    parser.add_argument("--figures", type=Path, default=REPO / "docs/results/figures")
    args = parser.parse_args()

    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    thresholds = {str(k): float(v) for k, v in calibration.get("thresholds", {}).items()}
    embedding = (
        not args.skip_embedding
        and importlib.util.find_spec("sentence_transformers") is not None
        and "embedding" in thresholds
    )
    plans = strategies(thresholds, embedding=embedding)
    names = [s.name for s in plans]
    cheap = [s for s in plans if "embedding" not in s.detection.detectors]
    adaptive = load_scenarios(REPO / "benchmarks" / "adaptive")
    attacks = [s for s in adaptive if s.is_attack]
    evasions = [s for s in attacks if s.metadata.get("family") != "control"]
    benign = [s for s in adaptive if not s.is_attack]
    args.figures.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "provmcp": __version__,
        "thresholds": thresholds,
        "embedding_included": embedding,
        "quick": args.quick,
    }

    md = [
        "# Week 12: adaptive adversary",
        "",
        f"- **date:** {date.today().isoformat()}",
        f"- **provmcp:** {__version__}",
        f"- **thresholds:** {thresholds} (Week 9 calibration, frozen)",
        f"- **mode:** {'quick' if args.quick else 'full'}",
        f"- **embedding strategies:** {'included' if embedding else 'not included'}",
        "- *canonical* = the 0.12 opt-in `canonicalize = true`: both sides compared after "
        "decoding, Unicode normalization, case folding, defanging and despacing.",
        "- Intervals are 95% Wilson, shown as `k/n (rate%, low-high)`.",
        "",
        f"## 1. Adaptive scenarios ({len(attacks)} attacks, {len(benign)} benign)",
        "",
        "Offline replay of the calls an obedient agent makes. *caught*: the carrying "
        "call is flagged and the finding names the true origin. *flagged, origin X*: "
        "flagged, but blamed on server X.",
        "",
        "| scenario | family | technique | " + " | ".join(names) + " |",
        "|---|---|---|" + "---|" * len(names),
    ]
    results: dict[str, dict[str, Outcome]] = {}
    for strategy in plans:
        outcomes = evaluate(strategy.detection, adaptive, threshold=strategy.threshold)
        results[strategy.name] = {o.scenario_id: o for o in outcomes}
    for scenario in adaptive:
        cells = " | ".join(mark(results[n][scenario.id]) for n in names)
        md.append(
            f"| {scenario.id} | {scenario.metadata.get('family', '')} "
            f"| {scenario.metadata.get('technique', '')} | {cells} |"
        )

    totals: dict[str, dict[str, Rate]] = {}
    for name in names:
        r = results[name]
        totals[name] = {
            "evasions_flagged": Rate(sum(r[s.id].flagged for s in evasions), len(evasions)),
            "evasions_caught": Rate(sum(r[s.id].attributed for s in evasions), len(evasions)),
            "benign_false_alarms": Rate(sum(r[s.id].flagged for s in benign), len(benign)),
        }
    md += [
        "",
        "| strategy | evasions flagged | evasions caught (right origin) | benign false alarms |",
        "|---|---|---|---|",
    ]
    md += [
        f"| {n} | {t['evasions_flagged']} | {t['evasions_caught']} | {t['benign_false_alarms']} |"
        for n, t in totals.items()
    ]
    summary["adaptive"] = {
        "per_scenario": {
            n: {
                sid: {"flagged": o.flagged, "attributed": o.attributed, "sources": o.sources}
                for sid, o in r.items()
            }
            for n, r in results.items()
        },
        "totals": {n: {k: v.to_json() for k, v in t.items()} for n, t in totals.items()},
    }
    (args.figures / "week12-adaptive.svg").write_text(
        grouped_rate_bars(
            "Adaptive evasions caught, and false alarms",
            f"Offline. {len(evasions)} evasions (control excluded); "
            f"{len(benign)} benign counterparts.",
            names,
            [
                ("evasions caught", [totals[n]["evasions_caught"] for n in names]),
                ("benign false alarms", [totals[n]["benign_false_alarms"] for n in names]),
            ],
        ),
        encoding="utf-8",
    )
    md += ["", "![Adaptive results](figures/week12-adaptive.svg)", ""]

    cap = 100 if args.quick else 1000
    floods = [0, cap // 2, cap - 1, cap, 2 * cap]
    md += [
        f"## 2. Self-flushing: filler results before the carry (cap {cap} per server)",
        "",
        "The poisoning server returns N filler results after the poisoned note, then "
        "the value is posted verbatim. The note and the server's tool list count "
        "toward its quota.",
        "",
        "| strategy | " + " | ".join(f"N = {n}" for n in floods) + " |",
        "|---|" + "---|" * len(floods),
    ]
    summary["flood"] = {"cap": cap}
    for strategy in cheap:
        swept = flood_sweep(strategy.detection, cap=cap, floods=floods)
        summary["flood"][strategy.name] = swept
        md.append(
            f"| {strategy.name} | "
            + " | ".join("caught" if swept[n] else "**missed**" for n in floods)
            + " |"
        )
    md.append("")

    pieces = [18, 12, 9, 6, 4]
    md += [
        "## 3. Splitting: the 18-character address sent in pieces",
        "",
        "Each piece goes in its own call. Detection is per call.",
        "",
        "| strategy | " + " | ".join(f"{p}-char pieces" for p in pieces) + " |",
        "|---|" + "---|" * len(pieces),
    ]
    summary["split"] = {}
    for strategy in plans:
        swept = split_sweep(strategy.detection, pieces=pieces)
        summary["split"][strategy.name] = swept
        md.append(
            f"| {strategy.name} | "
            + " | ".join("caught" if swept[p] else "**missed**" for p in pieces)
            + " |"
        )
    md.append("")

    md += ["## 4. What canonical views cost", "", "### Bundled corpus (27 scenarios)", ""]
    bundled = [s for d in BUNDLED for s in load_scenarios(REPO / "benchmarks" / d)]
    held_ids = set(json.loads(args.split.read_text(encoding="utf-8"))["held_out"])
    held = [s for s in bundled if s.id in held_ids]
    md += [
        "| strategy | attacks detected (17) | false alarms (10) | held-out attacks (8) "
        "| held-out false alarms (5) |",
        "|---|---|---|---|---|",
    ]
    corpus: dict[str, Any] = {}
    flags_by: dict[str, dict[str, bool]] = {}
    for strategy in plans:
        flags = offline_flags(strategy, bundled)
        flags_by[strategy.name] = flags
        det, fa = detection_and_false_alarms(flags, bundled)
        hdet, hfa = detection_and_false_alarms(flags, held)
        corpus[strategy.name] = {
            "detected": det.to_json(),
            "false_alarms": fa.to_json(),
            "held_out_detected": hdet.to_json(),
            "held_out_false_alarms": hfa.to_json(),
        }
        md.append(f"| {strategy.name} | {det} | {fa} | {hdet} | {hfa} |")
    changed = [s.id for s in bundled if flags_by[DEFAULT][s.id] != flags_by[CANON][s.id]]
    md += [
        "",
        f"Scenarios whose outcome canonical views change: {', '.join(changed) or 'none'}.",
        "",
    ]
    summary["corpus"] = corpus
    summary["corpus_changed_by_canonical"] = changed

    md += ["### InjecAgent, compliant agent", ""]
    if args.injecagent.is_dir():
        injecagent: list[Scenario] = load_scenarios(args.injecagent)
        ds = [s for s in injecagent if s.metadata.get("kind") == "ds"]
        dh = [s for s in injecagent if s.metadata.get("kind") == "dh"]
        md += [
            f"| strategy | data stealing ({len(ds)}) | direct harm ({len(dh)}) |",
            "|---|---|---|",
        ]
        scale: dict[str, Any] = {}
        for strategy in cheap:
            flags = offline_flags(strategy, injecagent)
            a = Rate(sum(flags[s.id] for s in ds), len(ds))
            b = Rate(sum(flags[s.id] for s in dh), len(dh))
            scale[strategy.name] = {"data_stealing": a.to_json(), "direct_harm": b.to_json()}
            md.append(f"| {strategy.name} | {a} | {b} |")
        summary["injecagent"] = scale
        md.append("")
    else:
        md += ["Not run: `benchmarks/external/injecagent` not found.", ""]

    md += ["### Real model traffic, replayed", ""]
    runs = parse_runs(args.run)
    all_scenarios = {s.id: s for s in bundled}
    traffic: dict[str, Any] = {}
    if not runs:
        md += ["Not run: pass `--run label=cache.jsonl`.", ""]
    for label, path in runs:
        if not path.is_file():
            md += [f"{label}: cache not found (`{path}`).", ""]
            continue
        cached = [r for r in load_cache(path).values() if r.scenario_id in all_scenarios]
        md += [
            f"**{label}** (`{path}`)",
            "",
            "| strategy | false alarms (runs with no attack) | attempted attacks detected "
            "| flagged calls |",
            "|---|---|---|---|",
        ]
        per: dict[str, Any] = {}
        for strategy in cheap:
            t = real_traffic(strategy, cached, all_scenarios)
            per[strategy.name] = {
                "false_alarms": t.false_alarms.to_json(),
                "detected": t.detected.to_json(),
                "flagged_calls": t.flagged_calls,
                "calls": t.calls,
            }
            md.append(
                f"| {strategy.name} | {t.false_alarms} | {t.detected} "
                f"| {t.flagged_calls} / {t.calls} |"
            )
        traffic[label] = per
        md.append("")
    summary["traffic"] = traffic

    sizes = [10, 100] if args.quick else [10, 100, 1000]
    calls = 20 if args.quick else 200
    md += [
        "### Time per call (cached store, ms)",
        "",
        "| strategy | store size | p50 | p95 | first call (fills the cache) |",
        "|---|---|---|---|---|",
    ]
    timing: list[dict[str, Any]] = []
    for strategy in cheap:
        detector = build_detector(ProvMcpConfig(detection=strategy.detection))
        for n in sizes:
            row = bench_detector(strategy.name, detector, store_size=n, calls=calls, cached=True)
            timing.append(row)
            md.append(
                f"| {strategy.name} | {n} | {row['p50']:.3f} | {row['p95']:.3f} "
                f"| {row['first_call_ms']:.1f} |"
            )
    summary["timing"] = timing
    md.append("")

    report = "\n".join(md)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    args.json.write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    print(report)
    print(f"wrote {args.out}, {args.json} and figures in {args.figures}")


if __name__ == "__main__":
    main()
