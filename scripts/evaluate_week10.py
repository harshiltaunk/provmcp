"""Week 10: full detection-accuracy evaluation, every strategy at every level.

    python scripts/evaluate_week10.py \\
        --run haiku-week8=logs/agent-cache-anthropic-claude-haiku-5-5.jsonl \\
        --run haiku-week10=logs/agent-cache-haiku-week10.jsonl

Writes docs/results/eval-week10.md, docs/results/eval-week10.json and SVG
figures in docs/results/figures/. Strategies come from
docs/results/calibration-week9.json. The embedding strategies run when
sentence-transformers is installed and the calibration has an embedding
threshold; pass --skip-embedding to leave them out. No model is called.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import date
from pathlib import Path

from provmcp import __version__
from provmcp.agent.experiment import load_cache
from provmcp.benchmark import Scenario, load_scenarios
from provmcp.evaluation import (
    Rate,
    detection_and_false_alarms,
    end_to_end,
    offline_flags,
    real_traffic,
    strategies_from_calibration,
)
from provmcp.svgchart import grouped_rate_bars

REPO = Path(__file__).parent.parent
BUNDLED = ("attacks", "msb", "benign")


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
    parser.add_argument("--out", type=Path, default=REPO / "docs/results/eval-week10.md")
    parser.add_argument("--json", type=Path, default=REPO / "docs/results/eval-week10.json")
    parser.add_argument("--figures", type=Path, default=REPO / "docs/results/figures")
    args = parser.parse_args()

    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    embedding = (
        not args.skip_embedding
        and importlib.util.find_spec("sentence_transformers") is not None
        and "embedding" in calibration.get("thresholds", {})
    )
    strategies = strategies_from_calibration(calibration, embedding=embedding)
    bundled = [s for d in BUNDLED for s in load_scenarios(REPO / "benchmarks" / d)]
    held_ids = set(json.loads(args.split.read_text(encoding="utf-8"))["held_out"])
    held = [s for s in bundled if s.id in held_ids]
    injecagent: list[Scenario] = []
    if args.injecagent.is_dir():
        injecagent = [
            s for s in load_scenarios(args.injecagent) if s.metadata.get("cross_server", True)
        ]
    all_scenarios = {s.id: s for s in bundled + injecagent}
    runs = parse_runs(args.run)
    args.figures.mkdir(parents=True, exist_ok=True)
    figure_rel = Path("figures")
    summary: dict[str, object] = {
        "provmcp": __version__,
        "calibration": calibration,
        "embedding_included": embedding,
    }

    md = [
        "# Week 10 evaluation",
        "",
        f"- **date:** {date.today().isoformat()}",
        f"- **provmcp:** {__version__}",
        f"- **calibration:** `{args.calibration.name}` "
        f"(thresholds {calibration.get('thresholds')}, substring score "
        f"{calibration.get('substring_score')})",
        f"- **embedding strategies:** {'included' if embedding else 'not included'}",
        "- **intervals:** 95% Wilson score intervals, shown as `k/n (rate%, low-high)`",
        "- Every strategy except *Week 7 settings* tracks tool metadata and uses its "
        "own calibrated threshold.",
        "",
        "## 1. Corpus: 27 bundled scenarios, offline",
        "",
        "| strategy | attacks detected (17) | benign false alarms (10) "
        "| held-out attacks (8) | held-out false alarms (5) |",
        "|---|---|---|---|---|",
    ]
    corpus: dict[str, dict[str, Rate]] = {}
    flags_by_strategy: dict[str, dict[str, bool]] = {}
    for strategy in strategies:
        flags = offline_flags(strategy, bundled)
        flags_by_strategy[strategy.name] = flags
        det, fa = detection_and_false_alarms(flags, bundled)
        hdet, hfa = detection_and_false_alarms(flags, held)
        corpus[strategy.name] = {
            "detected": det,
            "false_alarms": fa,
            "held_out_detected": hdet,
            "held_out_false_alarms": hfa,
        }
        md.append(f"| {strategy.name} | {det} | {fa} | {hdet} | {hfa} |")
    names = [s.name for s in strategies]
    (args.figures / "week10-corpus.svg").write_text(
        grouped_rate_bars(
            "Detection and false alarms on the 27 bundled scenarios",
            "Offline replay. Detection over 17 attacks; false alarms over 10 benign scenarios.",
            names,
            [
                ("attacks detected", [corpus[n]["detected"] for n in names]),
                ("benign false alarms", [corpus[n]["false_alarms"] for n in names]),
            ],
        ),
        encoding="utf-8",
    )
    md += ["", f"![Corpus results]({figure_rel / 'week10-corpus.svg'})", ""]

    md += [
        "### Which attack techniques each strategy catches",
        "",
        "| scenario | technique | " + " | ".join(names) + " |",
        "|---|---|" + "---|" * len(names),
    ]
    for scenario in (s for s in bundled if s.is_attack):
        technique = scenario.metadata.get("technique") or scenario.metadata.get("attack") or ""
        marks = " | ".join("yes" if flags_by_strategy[n][scenario.id] else "-" for n in names)
        md.append(f"| {scenario.id} | {technique} | {marks} |")
    summary["corpus"] = {n: {k: v.to_json() for k, v in d.items()} for n, d in corpus.items()}

    md += ["", "## 2. Compliant agent at scale: InjecAgent, offline", ""]
    if injecagent:
        ds = [s for s in injecagent if s.metadata.get("kind") == "ds"]
        dh = [s for s in injecagent if s.metadata.get("kind") == "dh"]
        md += [
            f"{len(injecagent)} cross-server cases replayed with the calls an obedient agent "
            "makes. Data stealing sends the stolen record to the attacker's address; "
            "direct harm passes the attacker's most specific token to the attacker's tool.",
            "",
            f"| strategy | data stealing detected ({len(ds)}) | direct harm detected ({len(dh)}) |",
            "|---|---|---|",
        ]
        scale: dict[str, tuple[Rate, Rate]] = {}
        for strategy in strategies:
            flags = offline_flags(strategy, injecagent)
            scale[strategy.name] = (
                Rate(sum(flags[s.id] for s in ds), len(ds)),
                Rate(sum(flags[s.id] for s in dh), len(dh)),
            )
            md.append(
                f"| {strategy.name} | {scale[strategy.name][0]} | {scale[strategy.name][1]} |"
            )
        (args.figures / "week10-injecagent.svg").write_text(
            grouped_rate_bars(
                "Detection on InjecAgent attacks, compliant agent",
                f"Offline replay of {len(injecagent)} cross-server cases.",
                names,
                [
                    ("data stealing", [scale[n][0] for n in names]),
                    ("direct harm", [scale[n][1] for n in names]),
                ],
            ),
            encoding="utf-8",
        )
        md += ["", f"![InjecAgent results]({figure_rel / 'week10-injecagent.svg'})"]
        summary["injecagent"] = {
            n: {"data_stealing": a.to_json(), "direct_harm": b.to_json()}
            for n, (a, b) in scale.items()
        }
    else:
        md.append("Not run: `benchmarks/external/injecagent` not found (import InjecAgent first).")

    md += ["", "## 3. Real model traffic: cached runs replayed", ""]
    traffic_summary: dict[str, object] = {}
    e2e_summary: dict[str, object] = {}
    if not runs:
        md.append("Not run: pass `--run label=cache.jsonl`.")
    for label, path in runs:
        if not path.is_file():
            md += [f"### {label}", "", f"Cache not found: `{path}`.", ""]
            continue
        results = list(load_cache(path).values())
        results = [r for r in results if r.scenario_id in all_scenarios]
        models = sorted({f"{r.backend} / {r.model}" for r in results})
        md += [
            f"### {label}: {', '.join(models)}",
            "",
            f"`{path}`, {sum(r.condition == 'audit' for r in results)} audit episodes replayed.",
            "",
            "| strategy | false alarms (runs with no attack) | attempted attacks detected "
            "| flagged calls |",
            "|---|---|---|---|",
        ]
        per: dict[str, object] = {}
        traffic: dict[str, tuple[Rate, Rate]] = {}
        for strategy in strategies:
            t = real_traffic(strategy, results, all_scenarios)
            traffic[strategy.name] = (t.detected, t.false_alarms)
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
        traffic_summary[label] = per
        fig = f"week10-traffic-{label}.svg"
        (args.figures / fig).write_text(
            grouped_rate_bars(
                f"Real traffic replay: {label}",
                f"{', '.join(models)}. False alarms over runs with no attack.",
                names,
                [
                    ("attempted attacks detected", [traffic[n][0] for n in names]),
                    ("false alarms", [traffic[n][1] for n in names]),
                ],
            ),
            encoding="utf-8",
        )
        md += ["", f"![Traffic {label}]({figure_rel / fig})", ""]
        rows = end_to_end(results, all_scenarios)
        md += [
            "End to end (live). Attack success = succeeded / valid attack runs; "
            "task completion = benign runs whose task reached its server.",
            "",
            "| condition | detection settings in force | attack success | task completion |",
            "|---|---|---|---|",
        ]
        md += [
            f"| {r.condition} | `{r.detection}` | {r.attack_success} | {r.task_completion} |"
            for r in rows
        ]
        md.append("")
        e2e_summary[label] = [
            {
                "condition": r.condition,
                "detection": r.detection,
                "attack_success": r.attack_success.to_json(),
                "task_completion": r.task_completion.to_json(),
            }
            for r in rows
        ]
    summary["traffic"] = traffic_summary
    summary["end_to_end"] = e2e_summary

    report = "\n".join(md) + "\n"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    args.json.write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    print(report)
    print(f"wrote {args.out}, {args.json} and figures in {args.figures}")


if __name__ == "__main__":
    main()
