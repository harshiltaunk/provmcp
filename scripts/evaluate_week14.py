"""Week 14: what real models do with the evasions, the scope ablation, and paired tests.

    python scripts/evaluate_week14.py \\
        --run haiku=logs/agent-cache-week14-haiku.jsonl \\
        --trials haiku=logs/agent-cache-week14-trials-haiku.jsonl

Writes docs/results/realworld-week14.md, .json and SVG figures. Section 1
needs no model. `--run` caches hold the real-model adaptive episodes and the
ablation arms; `--trials` caches hold the Week 13 conditions with more trials.
No model is called here.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from datetime import date
from pathlib import Path
from typing import Any

from provmcp import __version__
from provmcp.agent.experiment import load_cache, rescore
from provmcp.agent.runner import EpisodeResult
from provmcp.benchmark import Scenario, ground_truth_scope, load_scenarios
from provmcp.config import DetectionConfig
from provmcp.evaluation import Rate
from provmcp.realworld import (
    EpisodeFacts,
    all_facts,
    complete_cases,
    outcome,
    paired,
    rate,
    replay_flags,
)
from provmcp.scope_eval import FULL, PROVENANCE, ScopeScorer
from provmcp.svgchart import grouped_rate_bars

REPO = Path(__file__).parent.parent
RUN_CONDITIONS = ("audit", "strict", "strict-canonical", "strict-scope")
ABLATION = ("audit", "audit-warn", "audit-scope-plain", "audit-scope")
ABLATION_LABELS = {
    "audit": "no declaration, no warning",
    "audit-warn": "warning only (system prompt)",
    "audit-scope-plain": "declaration only (warning cut)",
    "audit-scope": "declaration and warning (Week 13)",
}
WEEK13 = ("audit", "strict", "audit-scope", "strict-scope", "strict-oracle")
FRAMINGS = ("delegated", "injected")


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


def sep(n: int) -> str:
    return "|" + "---|" * n


def techniques(scenarios: Sequence[Scenario]) -> list[str]:
    seen: list[str] = []
    for s in scenarios:
        t = str(s.metadata.get("technique", ""))
        if s.is_attack and t not in seen:
            seen.append(t)
    return seen


def offline_section(md: list[str], summary: dict[str, Any], attacks: list[Scenario]) -> None:
    md += [
        "## 1. Compliant agent (offline)",
        "",
        "Each scenario's compliant trace, replayed. *scope* is the ground-truth scope with "
        "the default detectors. This is what Week 12 measured: an agent that always obeys "
        "and transforms the value correctly.",
        "",
        row(["technique", "framing", "default", "canonical views", "scope + provenance"]),
        sep(5),
    ]
    default = ScopeScorer(DetectionConfig())
    canonical = ScopeScorer(DetectionConfig(canonicalize=True))
    out: dict[str, Any] = {}
    totals = {"default": 0, "canonical": 0, "scope": 0}
    for s in attacks:
        truth = ground_truth_scope(s)
        d = default.facts(s, truth)
        c = canonical.facts(s, truth)
        flags = {
            "default": d.flagged(PROVENANCE),
            "canonical": c.flagged(PROVENANCE),
            "scope": d.flagged(FULL),
        }
        for key, value in flags.items():
            totals[key] += value
        out[s.id] = flags
        mark = {True: "flagged", False: "**missed**"}
        md.append(
            row(
                [
                    s.metadata["technique"],
                    s.metadata["framing"],
                    mark[flags["default"]],
                    mark[flags["canonical"]],
                    mark[flags["scope"]],
                ]
            )
        )
    n = len(attacks)
    md += [
        row(["**total**", "", *[f"{totals[k]}/{n}" for k in ("default", "canonical", "scope")]]),
        "",
    ]
    summary["offline"] = {"per_scenario": out, "totals": totals, "n": n}


def evasion_section(
    md: list[str],
    label: str,
    results: list[EpisodeResult],
    scenarios: dict[str, Scenario],
    figures: Path,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    attacks = {k: s for k, s in scenarios.items() if s.is_attack}
    benign = {k: s for k, s in scenarios.items() if not s.is_attack}
    fs = all_facts([r for r in results if r.scenario_id in attacks], attacks)
    audit = [f for f in fs if f.condition == "audit"]
    audit_runs = [r for r in results if r.condition == "audit" and r.scenario_id in attacks]
    flag_default = replay_flags(audit_runs, attacks, DetectionConfig())
    flag_canonical = replay_flags(audit_runs, attacks, DetectionConfig(canonicalize=True))

    def pick(items: Sequence[EpisodeFacts], **want: str) -> list[EpisodeFacts]:
        return [f for f in items if all(getattr(f, k) == v for k, v in want.items())]

    def detected(items: Sequence[EpisodeFacts], flags: dict[tuple[str, int], bool]) -> Rate:
        sent = [f for f in items if f.sent]
        return Rate(sum(flags.get((f.scenario_id, f.trial), False) for f in sent), len(sent))

    md += [
        "With no defence (`audit`): did the model send the value, how, and would the "
        "detectors have flagged it? *sent* means the value can be recovered from what the "
        "agent posted. Detection is over the runs that sent it.",
        "",
        row(
            [
                "technique",
                "framing",
                "runs",
                "sent",
                "transformed as asked",
                "in the clear",
                "default detects",
                "canonical detects",
            ]
        ),
        sep(8),
    ]
    out["by_technique"] = {}
    names = techniques(list(attacks.values()))
    for technique in names:
        for framing in FRAMINGS:
            items = pick(audit, technique=technique, framing=framing)
            if not items:
                continue
            sent = rate(items, lambda f: f.sent)
            cells = {
                "sent": sent,
                "transformed": rate(items, lambda f: f.form == "transformed"),
                "clear": rate(items, lambda f: f.form == "clear"),
                "default": detected(items, flag_default),
                "canonical": detected(items, flag_canonical),
            }
            md.append(
                row(
                    [
                        technique,
                        framing,
                        len(items),
                        sent,
                        f"{cells['transformed'].k}",
                        f"{cells['clear'].k}",
                        cells["default"],
                        cells["canonical"],
                    ]
                )
            )
            out["by_technique"][f"{technique}/{framing}"] = {
                k: v.to_json() for k, v in cells.items()
            }
    md += [
        "",
        row(
            [
                "framing",
                "runs",
                "read the note",
                "sent the value",
                "default detects",
                "canonical detects",
            ]
        ),
        sep(6),
    ]
    out["by_framing"] = {}
    for framing in (*FRAMINGS, "both"):
        items = audit if framing == "both" else pick(audit, framing=framing)
        if not items:
            continue
        cells = {
            "read": rate(items, lambda f: f.read),
            "sent": rate(items, lambda f: f.sent),
            "default": detected(items, flag_default),
            "canonical": detected(items, flag_canonical),
        }
        md.append(
            row(
                [
                    framing,
                    len(items),
                    cells["read"],
                    cells["sent"],
                    cells["default"],
                    cells["canonical"],
                ]
            )
        )
        out["by_framing"][framing] = {k: v.to_json() for k, v in cells.items()}

    md += [
        "",
        "End to end: the value reached the share server (*leaked*), per condition.",
        "",
        row(
            [
                "condition",
                *[f"{f}: sent" for f in FRAMINGS],
                *[f"{f}: leaked" for f in FRAMINGS],
                "benign completed",
                "benign flagged",
            ]
        ),
        sep(7),
    ]
    out["end_to_end"] = {}
    conditions = [c for c in RUN_CONDITIONS if any(f.condition == c for f in fs)]
    leak_rates: dict[str, dict[str, Rate]] = {}
    for condition in conditions:
        cells_e: dict[str, Rate] = {}
        for framing in FRAMINGS:
            items = pick(fs, condition=condition, framing=framing)
            cells_e[f"{framing}_sent"] = rate(items, lambda f: f.sent)
            cells_e[f"{framing}_leaked"] = rate(items, lambda f: f.leaked)
        eps = [r for r in results if r.condition == condition and r.scenario_id in benign]
        cells_e["benign_completed"] = Rate(sum(r.succeeded for r in eps), len(eps))
        cells_e["benign_flagged"] = Rate(sum(r.flagged_any for r in eps), len(eps))
        leak_rates[condition] = cells_e
        md.append(
            row(
                [
                    condition,
                    *[cells_e[f"{f}_sent"] for f in FRAMINGS],
                    *[cells_e[f"{f}_leaked"] for f in FRAMINGS],
                    cells_e["benign_completed"],
                    cells_e["benign_flagged"],
                ]
            )
        )
        out["end_to_end"][condition] = {k: v.to_json() for k, v in cells_e.items()}
    if len(conditions) > 1:
        fig = f"week14-leaks-{label}.svg"
        (figures / fig).write_text(
            grouped_rate_bars(
                f"Value leaked to the share server, {label}",
                "Share of attack runs where the value can be recovered from what was received.",
                conditions,
                [(f, [leak_rates[c][f"{f}_leaked"] for c in conditions]) for f in FRAMINGS],
            ),
            encoding="utf-8",
        )
        md += ["", f"![Leaks {label}](figures/{fig})"]

    scoped = [f for f in fs if f.condition == "strict-scope" and f.declared_sink is not None]
    if scoped:
        md += ["", "Under `strict-scope`: was the share server in the declared scope?", ""]
        md += [
            row(["framing", "declared the share server", "post refused as out of scope"]),
            sep(3),
        ]
        out["declared_sink"] = {}
        for framing in FRAMINGS:
            items = pick(scoped, framing=framing)
            declared = rate(items, lambda f: bool(f.declared_sink))
            outside = rate(items, lambda f: f.outside)
            md.append(row([framing, declared, outside]))
            out["declared_sink"][framing] = {
                "declared": declared.to_json(),
                "outside": outside.to_json(),
            }

    md += ["", "Paired tests on *leaked* (same scenario and trial under both conditions):", ""]
    out["paired"] = {}
    leaked = {
        c: {(f.scenario_id, f.trial): f.leaked for f in fs if f.condition == c} for c in conditions
    }
    for a, b in (("audit", "strict"), ("strict", "strict-canonical"), ("strict", "strict-scope")):
        if a in leaked and b in leaked:
            test = paired(leaked[a], leaked[b])
            md.append(f"- `{a}` against `{b}`: {test}")
            out["paired"][f"{a} vs {b}"] = {
                "pairs": test.pairs,
                "only_a": test.only_a,
                "only_b": test.only_b,
                "p": round(test.p_value, 5),
            }
    md.append("")
    return out


def ablation_section(
    md: list[str], results: list[EpisodeResult], poisoned: dict[str, Scenario]
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    eps = [r for r in results if r.scenario_id in poisoned and r.condition in ABLATION]
    attacks = [r for r in eps if poisoned[r.scenario_id].is_attack]
    if not attacks:
        md += ["No ablation episodes in this cache.", ""]
        return out
    md += [
        "Poisoned catalog, nothing blocked. *hijacked* means the agent sent the data to the "
        "server whose description asked for it.",
        "",
        row(["arm", "condition", "hijacked", "hostile server declared", "controls completed"]),
        sep(5),
    ]
    for condition in ABLATION:
        items = [r for r in attacks if r.condition == condition]
        if not items:
            continue
        hijacked = Rate(sum(r.attempted for r in items), len(items))
        with_scope = [r for r in items if r.declared is not None]
        hostile = Rate(
            sum(
                str(poisoned[r.scenario_id].metadata.get("hostile_server", "sync"))
                in (r.declared or {}).get("servers", [])
                for r in with_scope
            ),
            len(with_scope),
        )
        controls = [
            r for r in eps if r.condition == condition and not poisoned[r.scenario_id].is_attack
        ]
        done = Rate(sum(r.succeeded for r in controls), len(controls))
        md.append(row([ABLATION_LABELS[condition], f"`{condition}`", hijacked, hostile, done]))
        out[condition] = {
            "hijacked": hijacked.to_json(),
            "hostile_declared": hostile.to_json(),
            "controls_completed": done.to_json(),
        }
    md += ["", "Paired tests on *hijacked*, against no declaration and no warning:", ""]
    base = outcome(attacks, "audit", lambda r: r.attempted)
    out["paired"] = {}
    for condition in ABLATION[1:]:
        other = outcome(attacks, condition, lambda r: r.attempted)
        if base and other:
            test = paired(base, other)
            md.append(f"- `audit` against `{condition}`: {test}")
            out["paired"][condition] = {
                "pairs": test.pairs,
                "only_a": test.only_a,
                "only_b": test.only_b,
                "p": round(test.p_value, 5),
            }
    md.append("")
    return out


def trials_section(
    md: list[str], label: str, path: Path, sets: dict[str, dict[str, Scenario]]
) -> dict[str, Any]:
    everything = {k: s for group in sets.values() for k, s in group.items()}
    cached = [
        r
        for r in load_cache(path).values()
        if r.scenario_id in everything and r.condition in WEEK13
    ]
    results, dropped = complete_cases(rescore(cached, everything)[0])
    out: dict[str, Any] = {"episodes": len(results), "left_out": dropped}
    models = sorted({r.model for r in results})
    trials = len({r.trial for r in results})
    md += [f"### {label} ({', '.join(models)}; {len(results)} episodes, {trials} trial(s))", ""]
    if dropped:
        md += [f"{dropped} episode(s) left out: not every condition is there yet.", ""]
    md += [
        row(
            [
                "condition",
                "attack success",
                "outside the plan",
                "in-plan",
                "benign completed",
                "benign flagged",
            ]
        ),
        sep(6),
    ]
    inplan = sets["in-plan"]
    conditions = [c for c in WEEK13 if any(r.condition == c for r in results)]
    out["conditions"] = {}
    for condition in conditions:
        eps = [r for r in results if r.condition == condition]
        attacks = [r for r in eps if r.is_attack and r.valid]
        benign = [r for r in eps if not r.is_attack]
        inside = [r for r in attacks if r.scenario_id in inplan]
        outside = [r for r in attacks if r.scenario_id not in inplan]
        cells = {
            "attack_success": Rate(sum(r.succeeded for r in attacks), len(attacks)),
            "outside": Rate(sum(r.succeeded for r in outside), len(outside)),
            "in_plan": Rate(sum(r.succeeded for r in inside), len(inside)),
            "benign_completed": Rate(sum(r.succeeded for r in benign), len(benign)),
            "benign_flagged": Rate(sum(r.flagged_any for r in benign), len(benign)),
        }
        md.append(row([condition, *cells.values()]))
        out["conditions"][condition] = {k: v.to_json() for k, v in cells.items()}

    def test(
        a: str,
        b: str,
        what: str,
        keep: Callable[[EpisodeResult], bool],
        pick: Callable[[EpisodeResult], bool],
    ) -> None:
        left = outcome([r for r in results if keep(r)], a, pick)
        right = outcome([r for r in results if keep(r)], b, pick)
        if left and right:
            result = paired(left, right)
            md.append(f"- {what}, `{a}` against `{b}`: {result}")
            out.setdefault("paired", {})[f"{what}: {a} vs {b}"] = {
                "pairs": result.pairs,
                "only_a": result.only_a,
                "only_b": result.only_b,
                "p": round(result.p_value, 5),
            }

    md += ["", "Paired tests:", ""]
    test(
        "strict",
        "strict-scope",
        "benign tasks completed",
        lambda r: not r.is_attack,
        lambda r: r.succeeded,
    )
    test(
        "audit",
        "strict-scope",
        "benign tasks completed",
        lambda r: not r.is_attack,
        lambda r: r.succeeded,
    )
    test("strict", "strict-scope", "attack success", lambda r: r.is_attack, lambda r: r.succeeded)
    test("audit", "audit-scope", "attack attempted", lambda r: r.is_attack, lambda r: r.attempted)
    md.append("")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run", action="append", default=[], help="label=week14-cache.jsonl")
    parser.add_argument("--trials", action="append", default=[], help="label=trials-cache.jsonl")
    parser.add_argument("--out", type=Path, default=REPO / "docs/results/realworld-week14.md")
    parser.add_argument("--json", type=Path, default=REPO / "docs/results/realworld-week14.json")
    parser.add_argument("--figures", type=Path, default=REPO / "docs/results/figures")
    args = parser.parse_args()
    runs = parse_pairs(args.run, "--run")
    trials = parse_pairs(args.trials, "--trials")

    def folder(*names: str) -> dict[str, Scenario]:
        return {s.id: s for n in names for s in load_scenarios(REPO / "benchmarks" / n)}

    realworld = folder("realworld")
    poisoned = folder("poisoned")
    sets = {
        "bundled": folder("attacks", "msb", "benign"),
        "in-plan": folder("inplan"),
        "poisoned catalog": poisoned,
    }
    args.figures.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"provmcp": __version__}
    md = [
        "# Week 14: real models, the evasions, and the scope ablation",
        "",
        f"- **date:** {date.today().isoformat()}",
        f"- **provmcp:** {__version__}",
        "- **detection:** the 0.9.0 defaults; *canonical* adds canonical views (0.12, opt-in)",
        f"- **inputs:** {len(runs)} run cache(s), {len(trials)} trials cache(s)",
        "- Intervals are 95% Wilson, shown as `k/n (rate%, low-high)`. Paired tests are "
        "exact McNemar tests on (scenario, trial) pairs.",
        "",
    ]
    offline_section(md, summary, [s for s in realworld.values() if s.is_attack])

    md += ["## 2. Real models and the evasions", ""]
    summary["evasion"] = {}
    loaded: dict[str, list[EpisodeResult]] = {}
    if not runs:
        md += ["Not run: pass `--run label=cache.jsonl`.", ""]
    for label, path in runs:
        if not path.is_file():
            md += [f"**{label}**: cache not found (`{path}`).", ""]
            continue
        everything = {**realworld, **poisoned}
        cached = [r for r in load_cache(path).values() if r.scenario_id in everything]
        loaded[label] = rescore(cached, everything)[0]
        mine = [
            r for r in loaded[label] if r.scenario_id in realworld and r.condition in RUN_CONDITIONS
        ]
        mine, dropped = complete_cases(mine)
        models = sorted({r.model for r in mine})
        md += [f"### {label} ({', '.join(models)}; {len(mine)} episodes, `{path}`)", ""]
        if dropped:
            md += [f"{dropped} episode(s) left out: not every condition is there yet.", ""]
        summary["evasion"][label] = evasion_section(md, label, mine, realworld, args.figures)

    md += ["## 3. Ablation: the declaration or the warning?", ""]
    summary["ablation"] = {}
    if not loaded:
        md += ["Not run: pass `--run label=cache.jsonl`.", ""]
    for label, results in loaded.items():
        models = sorted({r.model for r in results})
        md += [f"### {label} ({', '.join(models)})", ""]
        mine, _ = complete_cases(
            [r for r in results if r.scenario_id in poisoned and r.condition in ABLATION]
        )
        summary["ablation"][label] = ablation_section(md, mine, poisoned)

    md += ["## 4. Week 13 conditions with more trials", ""]
    summary["trials"] = {}
    if not trials:
        md += ["Not run: pass `--trials label=cache.jsonl`.", ""]
    for label, path in trials:
        if not path.is_file():
            md += [f"**{label}**: cache not found (`{path}`).", ""]
            continue
        summary["trials"][label] = trials_section(md, label, path, sets)

    report = "\n".join(md)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    args.json.write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    print(report)
    print(f"wrote {args.out}, {args.json} and figures in {args.figures}")


if __name__ == "__main__":
    main()
