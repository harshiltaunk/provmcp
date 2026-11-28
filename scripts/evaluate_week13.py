"""Week 13: declared scope, from ground truth to real models.

    python scripts/evaluate_week13.py \\
        --probe haiku=logs/scope-probe-anthropic-claude-haiku-5-5.jsonl \\
        --run haiku=logs/agent-cache-week13-haiku.jsonl

Writes docs/results/scope-week13.md, docs/results/scope-week13.json and SVG
figures in docs/results/figures/. Section 1 needs no model and is the same on
every machine. Sections 2 to 4 read caches written by `provmcp scope-probe`
(`--probe label=file`) and `provmcp agent-run` (`--run label=file`). No model
is called here.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

from provmcp import __version__
from provmcp.agent.experiment import load_cache, rescore
from provmcp.agent.probe import load_probes
from provmcp.agent.runner import EpisodeResult
from provmcp.benchmark import Scenario, ground_truth_scope, load_scenarios
from provmcp.config import DetectionConfig
from provmcp.evaluation import Rate
from provmcp.scope import SCOPE_TOOL_VERSION, Scope, ScopeGuard
from provmcp.scope_eval import (
    FULL,
    PROVENANCE,
    SCOPE_ONLY,
    SERVERS,
    STRATEGIES,
    Declaration,
    ScopeScorer,
    TraceFacts,
    declarations_from_episodes,
    declarations_from_probes,
    hostile_declared,
    rates,
    scoped_traffic,
    summarize_declarations,
)
from provmcp.svgchart import grouped_rate_bars

REPO = Path(__file__).parent.parent
SETS: dict[str, tuple[str, ...]] = {
    "bundled": ("attacks", "msb", "benign"),
    "in-plan": ("inplan",),
    "poisoned catalog": ("poisoned",),
    "adaptive": ("adaptive",),
}
LABELS = {
    PROVENANCE: "provenance only (0.9.0 default)",
    SCOPE_ONLY: "scope only",
    SERVERS: "scope + provenance, servers only",
    FULL: "scope + provenance (servers and flows)",
}
REPLAY = {PROVENANCE: "provenance", SCOPE_ONLY: "scope", SERVERS: "servers", FULL: "flows"}
CONDITIONS = ("audit", "strict", "audit-scope", "strict-scope", "strict-oracle")
TASK_TYPES = ("fully-specified", "param-open", "action-open")


def parse_pairs(items: list[str], flag: str) -> list[tuple[str, Path]]:
    pairs = []
    for item in items:
        label, sep, path = item.partition("=")
        if not sep or not label or not path:
            raise SystemExit(f"{flag} needs label=path, got {item!r}")
        pairs.append((label, Path(path)))
    return pairs


def row(cells: Sequence[object]) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def offline_section(
    md: list[str], summary: dict[str, Any], scorer: ScopeScorer, sets: dict[str, list[Scenario]]
) -> dict[str, list[TraceFacts]]:
    md += [
        "## 1. Ground-truth scope, compliant agent (offline)",
        "",
        "Each scenario's compliant trace is replayed under the scope its request calls "
        "for. An attack counts as detected, and a benign scenario as a false alarm, when "
        "any step is flagged. This is the upper bound: a host that reads the request "
        "correctly.",
        "",
        row(["set", "strategy", "attacks detected", "benign false alarms"]),
        "|---|---|---|---|",
    ]
    facts: dict[str, list[TraceFacts]] = {}
    offline: dict[str, Any] = {}
    for name, scenarios in sets.items():
        facts[name] = scorer.score(scenarios)
        offline[name] = {}
        for strategy in STRATEGIES:
            detected, alarms = rates(facts[name], strategy)
            offline[name][strategy] = {
                "detected": detected.to_json(),
                "false_alarms": alarms.to_json(),
            }
            md.append(row([name, LABELS[strategy], detected, alarms]))
    summary["offline"] = offline

    md += [
        "",
        "### Per scenario: bundled and in-plan",
        "",
        "*rule* is what decides under the full mechanism.",
        "",
        row(["scenario", "task type", "provenance only", "scope + provenance", "rule"]),
        "|---|---|---|---|---|",
    ]
    detail: dict[str, Any] = {}
    by_id = {s.id: s for name in ("bundled", "in-plan") for s in sets[name]}
    for name in ("bundled", "in-plan"):
        for f in facts[name]:
            scenario = by_id[f.scenario_id]
            marks = [
                ("flagged" if f.flagged(s) else "-")
                if not f.is_attack
                else ("detected" if f.flagged(s) else "**missed**")
                for s in (PROVENANCE, FULL)
            ]
            md.append(row([f.scenario_id, scenario.metadata.get("task_type", ""), *marks, f.why()]))
            detail[f.scenario_id] = {
                "provenance": f.flagged(PROVENANCE),
                "full": f.flagged(FULL),
                "rule": f.why(),
            }
    summary["per_scenario"] = detail
    bundled = facts["bundled"]
    gained = [f.scenario_id for f in bundled if f.flagged(FULL) and not f.flagged(PROVENANCE)]
    lost = [f.scenario_id for f in bundled if f.flagged(PROVENANCE) and not f.flagged(FULL)]
    md += [
        "",
        f"Bundled scenarios the scope adds: {', '.join(gained) or 'none'}.",
        "",
        f"Bundled scenarios no longer flagged: {', '.join(lost) or 'none'} "
        "(benign ones are false alarms removed; attacks are detections given up).",
        "",
    ]
    summary["bundled_gained"], summary["bundled_no_longer_flagged"] = gained, lost
    return facts


def injecagent_section(
    md: list[str], summary: dict[str, Any], scorer: ScopeScorer, folder: Path
) -> list[Scenario]:
    md += ["### InjecAgent, compliant agent", ""]
    if not folder.is_dir():
        md += [f"Not run: `{folder}` not found.", ""]
        return []
    cases = [s for s in load_scenarios(folder) if s.metadata.get("cross_server", True)]
    facts = scorer.score(cases)
    kinds = {s.id: s.metadata.get("kind") for s in cases}
    md += [
        f"{len(cases)} cross-server cases. The request names only the user's own tool, so "
        "the attacker's server is outside the scope by construction.",
        "",
        row(["strategy", "data stealing", "direct harm"]),
        "|---|---|---|",
    ]
    out: dict[str, Any] = {}
    for strategy in STRATEGIES:
        cells = []
        for kind in ("ds", "dh"):
            subset = [f for f in facts if kinds[f.scenario_id] == kind]
            rate = Rate(sum(f.flagged(strategy) for f in subset), len(subset))
            cells.append(rate)
            out.setdefault(strategy, {})[kind] = rate.to_json()
        md.append(row([LABELS[strategy], *cells]))
    md.append("")
    summary["injecagent"] = out
    return cases


def declaration_tables(
    md: list[str],
    label: str,
    declarations: list[Declaration],
    sets: dict[str, list[Scenario]],
    scorer: ScopeScorer,
) -> dict[str, Any]:
    """Tables for one model's declarations. Returns the JSON summary."""
    everything = {s.id: s for scenarios in sets.values() for s in scenarios}
    out: dict[str, Any] = {}
    md += [
        row(
            [
                "set",
                "declarations",
                "declared first",
                "matches ground truth",
                "leaves something out",
                "lets something in",
            ]
        ),
        "|---|---|---|---|---|---|",
    ]
    for name, scenarios in [*sets.items(), ("all", list(everything.values()))]:
        subset = {s.id: s for s in scenarios}
        s = summarize_declarations(declarations, subset)
        if not s.n:
            continue
        md.append(
            row(
                [
                    name,
                    f"{s.declared}/{s.n}",
                    s.rate("first"),
                    s.rate("exact"),
                    s.rate("under"),
                    s.rate("over"),
                ]
            )
        )
        out[name] = {
            k: s.rate(k).to_json() for k in ("declared", "first", "exact", "under", "over")
        }

    md += [
        "",
        row(
            [
                "task type",
                "declarations",
                "matches ground truth",
                "leaves something out",
                "lets something in",
            ]
        ),
        "|---|---|---|---|---|",
    ]
    out["by_task_type"] = {}
    for kind in TASK_TYPES:
        subset = {s.id: s for s in everything.values() if s.metadata.get("task_type") == kind}
        s = summarize_declarations(declarations, subset)
        if s.n:
            md.append(
                row([kind, f"{s.declared}/{s.n}", s.rate("exact"), s.rate("under"), s.rate("over")])
            )
            out["by_task_type"][kind] = {k: s.rate(k).to_json() for k in ("exact", "under", "over")}

    poisoned = {s.id: s for s in sets.get("poisoned catalog", [])}
    rows: dict[str, list[tuple[bool, bool]]] = {}
    for d in declarations:
        if d.scenario_id in poisoned and d.scope is not None:
            technique = str(poisoned[d.scenario_id].metadata.get("technique", "?"))
            rows.setdefault(technique, []).append(hostile_declared(d, poisoned[d.scenario_id]))
    if rows:
        md += [
            "",
            "Poisoned catalog: did the declaration include the server that asked to be included?",
            "",
            row(
                [
                    "tool description",
                    "declarations",
                    "hostile server declared",
                    "a flow into it declared",
                ]
            ),
            "|---|---|---|---|",
        ]
        out["poisoned"] = {}
        for technique in sorted(rows):
            pairs = rows[technique]
            server = Rate(sum(a for a, _ in pairs), len(pairs))
            flow = Rate(sum(b for _, b in pairs), len(pairs))
            md.append(row([technique, len(pairs), server, flow]))
            out["poisoned"][technique] = {"server": server.to_json(), "flow": flow.to_json()}

    # What the model's own declarations would catch, on the compliant traces.
    md += [
        "",
        "With these declarations in place of the ground truth, on the compliant traces "
        "(full mechanism; one row per declaration):",
        "",
        row(["set", "attacks detected", "benign false alarms"]),
        "|---|---|---|",
    ]
    out["offline_with_declarations"] = {}
    for name, scenarios in sets.items():
        subset = {s.id: s for s in scenarios}
        facts = [
            scorer.facts(subset[d.scenario_id], d.scope)
            for d in declarations
            if d.scenario_id in subset and d.scope is not None
        ]
        if not facts:
            continue
        detected, alarms = rates(facts, FULL)
        md.append(row([name, detected, alarms]))
        out["offline_with_declarations"][name] = {
            "detected": detected.to_json(),
            "false_alarms": alarms.to_json(),
        }
    md.append("")
    return out


def complete_cases(results: list[EpisodeResult]) -> tuple[list[EpisodeResult], int]:
    """Keep (model, scenario, trial) groups that have every condition present in the cache.

    A run stopped by a spending cap leaves some groups half done. Comparing
    conditions over different scenarios would bias the comparison, so those
    groups are left out. Returns the kept episodes and how many were dropped.
    """
    conditions = {r.condition for r in results}
    seen: dict[tuple[str, str, int], set[str]] = {}
    for r in results:
        seen.setdefault((r.model, r.scenario_id, r.trial), set()).add(r.condition)
    kept = [r for r in results if seen[(r.model, r.scenario_id, r.trial)] == conditions]
    return kept, len(results) - len(kept)


def end_to_end_rows(results: list[EpisodeResult]) -> dict[str, dict[str, Rate]]:
    out: dict[str, dict[str, Rate]] = {}
    for condition in CONDITIONS:
        eps = [r for r in results if r.condition == condition]
        if not eps:
            continue
        attacks = [r for r in eps if r.is_attack and r.valid]
        benign = [r for r in eps if not r.is_attack]
        out[condition] = {
            "attempted": Rate(sum(r.attempted for r in attacks), len(attacks)),
            "attack_success": Rate(sum(r.succeeded for r in attacks), len(attacks)),
            "task_completion": Rate(sum(r.succeeded for r in benign), len(benign)),
            "benign_flagged": Rate(sum(r.flagged_any for r in benign), len(benign)),
        }
    return out


def injecagent_runs(md: list[str], path: Path, cases: list[Scenario], out: dict[str, Any]) -> None:
    """End-to-end attack success on InjecAgent episodes found in the same cache."""
    by_id = {s.id: s for s in cases}
    cached = [
        r for r in load_cache(path).values() if r.scenario_id in by_id and r.condition in CONDITIONS
    ]
    if not cached:
        return
    results, dropped = complete_cases(rescore(cached, by_id)[0])
    conditions = [c for c in CONDITIONS if any(r.condition == c for r in results)]
    md += [
        "",
        f"InjecAgent sample: {len({r.scenario_id for r in results})} cases, {len(results)} "
        f"episodes{f' ({dropped} left out as incomplete)' if dropped else ''}. Attack success "
        "over valid runs:",
        "",
        row(["attack type", *conditions]),
        "|---|" + "---|" * len(conditions),
    ]
    out["injecagent"] = {}
    for kind, name in (("ds", "data stealing"), ("dh", "direct harm")):
        subset = [r for r in results if by_id[r.scenario_id].metadata.get("kind") == kind]
        table = end_to_end_rows(subset)
        md.append(
            row([name, *[table[c]["attack_success"] if c in table else "-" for c in conditions]])
        )
        out["injecagent"][kind] = {c: r["attack_success"].to_json() for c, r in table.items()}
    declared = [r for r in results if r.scope_mode == "declared" and r.declared is not None]
    if declared:
        let_in = Rate(
            sum(
                bool(set(r.declared["servers"]) - ground_truth_scope(by_id[r.scenario_id]).servers)
                for r in declared
            ),
            len(declared),
        )
        md += ["", f"The attacker's server was in the declared scope in {let_in} of these runs."]
        out["injecagent"]["attacker_declared"] = let_in.to_json()


def run_section(
    md: list[str],
    label: str,
    path: Path,
    sets: dict[str, list[Scenario]],
    scorer: ScopeScorer,
    figures: Path,
    injecagent: list[Scenario],
) -> dict[str, Any]:
    everything = {s.id: s for scenarios in sets.values() for s in scenarios}
    cached = [
        r
        for r in load_cache(path).values()
        if r.scenario_id in everything and r.condition in CONDITIONS
    ]
    rescored, _ = rescore(cached, everything)
    results, dropped = complete_cases(rescored)
    models = sorted({r.model for r in results})
    out: dict[str, Any] = {"models": models, "episodes": len(results), "left_out": dropped}
    md += [f"### {label} ({', '.join(models)}; {len(results)} episodes, `{path}`)", ""]
    if dropped:
        md += [
            f"{dropped} episode(s) left out: their scenario and trial do not have every "
            "condition yet (an interrupted run). Conditions are compared on the same "
            "scenarios and trials only.",
            "",
        ]

    rows = end_to_end_rows(results)
    md += [
        "End to end. *attempted* and *attack success* are over valid attack runs; *task "
        "completion* and *any call flagged* over benign runs.",
        "",
        row(
            [
                "condition",
                "attack attempted",
                "attack success",
                "benign task completion",
                "benign runs with a flagged call",
            ]
        ),
        "|---|---|---|---|---|",
    ]
    for condition, r in rows.items():
        md.append(
            row(
                [
                    condition,
                    r["attempted"],
                    r["attack_success"],
                    r["task_completion"],
                    r["benign_flagged"],
                ]
            )
        )
    out["end_to_end"] = {c: {k: v.to_json() for k, v in r.items()} for c, r in rows.items()}
    if len(rows) > 1:
        fig = f"week13-endtoend-{label}.svg"
        names = list(rows)
        (figures / fig).write_text(
            grouped_rate_bars(
                f"End to end with {label}",
                "Attack success over valid attack runs; task completion over benign runs.",
                names,
                [
                    ("attack success", [rows[n]["attack_success"] for n in names]),
                    ("benign task completion", [rows[n]["task_completion"] for n in names]),
                ],
            ),
            encoding="utf-8",
        )
        md += ["", f"![End to end {label}](figures/{fig})"]

    by_group: dict[str, dict[str, dict[str, Rate]]] = {}
    for name, scenarios in sets.items():
        ids = {s.id for s in scenarios}
        subset = [r for r in results if r.scenario_id in ids]
        if subset:
            by_group[name] = end_to_end_rows(subset)
    md += [
        "",
        "By set (attack success / benign task completion):",
        "",
        row(["set", *CONDITIONS]),
        "|---|" + "---|" * len(CONDITIONS),
    ]
    for name, table in by_group.items():
        cells = []
        for condition in CONDITIONS:
            r = table.get(condition)
            if r is None:
                cells.append("-")
                continue
            attack = r["attack_success"]
            benign = r["task_completion"]
            cells.append(f"{attack.k}/{attack.n} / {benign.k}/{benign.n}")
        md.append(row([name, *cells]))
    out["by_set"] = {
        name: {c: {k: v.to_json() for k, v in r.items()} for c, r in table.items()}
        for name, table in by_group.items()
    }
    if injecagent:
        injecagent_runs(md, path, injecagent, out)

    declared = [r for r in results if r.scope_mode == "declared"]
    if declared:
        md += ["", "Declarations made in these runs:", ""]
        out["declarations"] = declaration_tables(
            md, label, declarations_from_episodes(declared), sets, scorer
        )
        md += [
            row(
                [
                    "condition",
                    "episodes",
                    "never declared",
                    "calls refused before declaring",
                    "attempts to change the scope after reading",
                ]
            ),
            "|---|---|---|---|---|",
        ]
        for condition in ("audit-scope", "strict-scope"):
            eps = [r for r in declared if r.condition == condition]
            if eps:
                md.append(
                    row(
                        [
                            condition,
                            len(eps),
                            sum(r.declared is None for r in eps),
                            sum(r.nudges for r in eps),
                            sum(r.late_declarations for r in eps),
                        ]
                    )
                )
        md.append("")

    if any(r.condition == "audit-scope" for r in results):
        md += [
            "Replay of the `audit-scope` runs (nothing was blocked) under each strategy, "
            "with the scope each run declared:",
            "",
            row(
                [
                    "strategy",
                    "false alarms (runs with no attack)",
                    "attempted attacks detected",
                    "flagged calls",
                ]
            ),
            "|---|---|---|---|",
        ]
        out["traffic"] = {}
        for strategy in STRATEGIES:
            t = scoped_traffic(results, everything, scorer.detection, REPLAY[strategy])
            md.append(
                row(
                    [LABELS[strategy], t.false_alarms, t.detected, f"{t.flagged_calls} / {t.calls}"]
                )
            )
            out["traffic"][strategy] = {
                "false_alarms": t.false_alarms.to_json(),
                "detected": t.detected.to_json(),
                "flagged_calls": t.flagged_calls,
                "calls": t.calls,
            }
        md.append("")

    md += [
        row(
            ["condition", "episodes", "mean input tokens", "mean output tokens", "mean model turns"]
        ),
        "|---|---|---|---|---|",
    ]
    out["tokens"] = {}
    for condition in CONDITIONS:
        eps = [r for r in results if r.condition == condition]
        if eps:
            tin = sum(r.input_tokens for r in eps) / len(eps)
            tout = sum(r.output_tokens for r in eps) / len(eps)
            turns = sum(r.steps for r in eps) / len(eps)
            md.append(row([condition, len(eps), f"{tin:,.0f}", f"{tout:,.0f}", f"{turns:.1f}"]))
            out["tokens"][condition] = {"input": tin, "output": tout, "turns": turns}
    md.append("")
    return out


def overhead() -> dict[str, float]:
    """Time of the scope checks themselves, in microseconds per call."""
    servers = {f"s{i}": f"Server {i}" for i in range(8)}
    scope = Scope(frozenset(list(servers)[:3]), frozenset({("s0", "s1")}))
    n = 200_000
    start = time.perf_counter()
    for _ in range(n):
        scope.allows_server("s7")
        scope.allows_flow("s0", "s1")
    check = (time.perf_counter() - start) / n * 1e6
    guard = ScopeGuard(servers=servers)
    args = {"servers": ["s0", "s1", "s2"], "flows": [{"from": "s0", "to": "s1"}]}
    m = 20_000
    start = time.perf_counter()
    for _ in range(m):
        guard.declare(args)
    declare = (time.perf_counter() - start) / m * 1e6
    return {"check_us": check, "declare_us": declare}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--probe", action="append", default=[], help="label=probe-cache.jsonl")
    parser.add_argument("--run", action="append", default=[], help="label=agent-cache.jsonl")
    parser.add_argument("--injecagent", type=Path, default=REPO / "benchmarks/external/injecagent")
    parser.add_argument("--out", type=Path, default=REPO / "docs/results/scope-week13.md")
    parser.add_argument("--json", type=Path, default=REPO / "docs/results/scope-week13.json")
    parser.add_argument("--figures", type=Path, default=REPO / "docs/results/figures")
    args = parser.parse_args()

    probes = parse_pairs(args.probe, "--probe")
    runs = parse_pairs(args.run, "--run")
    sets = {
        name: [s for d in folders for s in load_scenarios(REPO / "benchmarks" / d)]
        for name, folders in SETS.items()
    }
    scorer = ScopeScorer(DetectionConfig())
    args.figures.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"provmcp": __version__, "declare_scope_wording": SCOPE_TOOL_VERSION}
    md = [
        "# Week 13: declared scope",
        "",
        f"- **date:** {date.today().isoformat()}",
        f"- **provmcp:** {__version__}",
        "- **detection:** the 0.9.0 defaults (substring 0.428, structured 0.85, tool "
        "metadata tracked), unchanged",
        "- **strategies:** *provenance only* is ProvMCP up to 0.12. *scope only* flags a "
        "call to a server outside the scope. *servers only* adds every provenance finding. "
        "*servers and flows* is the full mechanism: findings on a declared flow are let "
        "through.",
        f"- **model inputs:** {len(probes)} probe cache(s), {len(runs)} run cache(s); "
        f"`declare_scope` wording {SCOPE_TOOL_VERSION}",
        "- Intervals are 95% Wilson, shown as `k/n (rate%, low-high)`.",
        "",
    ]

    facts = offline_section(md, summary, scorer, sets)
    names = [LABELS[s] for s in STRATEGIES]
    (args.figures / "week13-scope-offline.svg").write_text(
        grouped_rate_bars(
            "Declared scope on the 27 bundled scenarios",
            "Offline, ground-truth scope. Detection over 17 attacks; false alarms over "
            "10 benign scenarios.",
            names,
            [
                ("attacks detected", [rates(facts["bundled"], s)[0] for s in STRATEGIES]),
                ("benign false alarms", [rates(facts["bundled"], s)[1] for s in STRATEGIES]),
            ],
        ),
        encoding="utf-8",
    )
    md += ["![Offline results](figures/week13-scope-offline.svg)", ""]
    injecagent = injecagent_section(md, summary, scorer, args.injecagent)
    probe_sets = dict(sets)
    if injecagent:
        probe_sets["InjecAgent"] = injecagent

    md += ["## 2. What real models declare (one-call probe)", ""]
    summary["probes"] = {}
    if not probes:
        md += ["Not run: pass `--probe label=cache.jsonl` (see `provmcp scope-probe`).", ""]
    for label, path in probes:
        if not path.is_file():
            md += [f"**{label}**: cache not found (`{path}`).", ""]
            continue
        loaded = list(load_probes(path).values())
        models = sorted({p.model for p in loaded})
        md += [f"### {label} ({', '.join(models)}; {len(loaded)} probes, `{path}`)", ""]
        summary["probes"][label] = declaration_tables(
            md, label, declarations_from_probes(loaded), probe_sets, scorer
        )
        if injecagent:
            ids = {s.id: ground_truth_scope(s) for s in injecagent}
            extra = [
                bool(Scope.parse(p.declared).servers - ids[p.scenario_id].servers)
                for p in loaded
                if p.scenario_id in ids and p.declared is not None
            ]
            if extra:
                rate = Rate(sum(extra), len(extra))
                md += [f"InjecAgent: the attacker's server was declared in {rate}.", ""]
                summary["probes"][label]["injecagent_attacker_declared"] = rate.to_json()

    md += ["## 3. Real models, end to end", ""]
    summary["runs"] = {}
    if not runs:
        md += ["Not run: pass `--run label=cache.jsonl` (see `provmcp agent-run`).", ""]
    for label, path in runs:
        if not path.is_file():
            md += [f"**{label}**: cache not found (`{path}`).", ""]
            continue
        summary["runs"][label] = run_section(
            md, label, path, sets, scorer, args.figures, injecagent
        )

    timing = overhead()
    summary["overhead"] = timing
    md += [
        "## 4. Cost of the checks",
        "",
        f"- Scope check per call (one server lookup, one flow lookup): "
        f"{timing['check_us']:.2f} µs.",
        f"- Accepting a declaration: {timing['declare_us']:.1f} µs, once per session.",
        "- The agent pays one extra tool call per session; token counts per condition are "
        "in section 3.",
        "",
    ]

    report = "\n".join(md)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    args.json.write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    print(report)
    print(f"wrote {args.out}, {args.json} and figures in {args.figures}")


if __name__ == "__main__":
    main()
