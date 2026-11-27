"""Pick a decision threshold per detector on a calibration split; report on held-out.

Week 5 chose the embedding threshold on the same scenarios it was scored on,
which is optimistic. This script fixes that:

1. Every scenario in the split file is replayed offline (`BenchmarkRunner`)
   with tool metadata tracked (pass --no-tool-metadata to turn it off).
2. Each detector variant gives every scenario a score: the highest
   confidence of any finding in the trace (0 if none).
3. On the *calibration* part only, the threshold that maximizes Youden's
   J = TPR - FPR is chosen; ties go to the higher threshold (fewer alarms).
4. Those thresholds are applied unchanged to the *held-out* part.

Usage:
    python scripts/calibrate_detectors.py
    python scripts/calibrate_detectors.py --out docs/results/calibration-week9.md \\
        --json docs/results/calibration-week9.json

The embedding variant runs only when sentence-transformers is installed.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
from dataclasses import dataclass
from pathlib import Path

from provmcp.benchmark import BenchmarkRunner, Scenario, load_scenarios
from provmcp.detectors import (
    CompositeDetector,
    Detector,
    EmbeddingDetector,
    GatedDetector,
    StructuredFieldDetector,
    SubstringDetector,
)

REPO = Path(__file__).parent.parent
SUITES = ("attacks", "msb", "benign")


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def tpr(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def cells(self) -> str:
        return f"{self.tp} | {self.fp} | {self.tn} | {self.fn} | {self.tpr:.2f} | {self.fpr:.2f}"


def variants(embedding: bool) -> dict[str, Detector]:
    found: dict[str, Detector] = {
        "substring (longest)": SubstringDetector(score_mode="longest"),
        "substring (coverage)": SubstringDetector(score_mode="coverage"),
        "structured": StructuredFieldDetector(),
    }
    if embedding:
        found["embedding"] = EmbeddingDetector(threshold=0.01)
    return found


def score(detector: Detector, scenario: Scenario, metadata: bool) -> float:
    result = BenchmarkRunner(detector=detector, track_tool_metadata=metadata).run(scenario)
    return max((f.confidence for step in result.steps for f in step.findings), default=0.0)


def counts(scores: dict[str, float], scenarios: list[Scenario], threshold: float | None) -> Counts:
    c = Counts()
    for s in scenarios:
        hit = threshold is not None and scores[s.id] >= threshold
        if s.is_attack:
            c.tp += hit
            c.fn += not hit
        else:
            c.fp += hit
            c.tn += not hit
    return c


def floor3(value: float) -> float:
    """Round down to 3 decimals, so a scenario scored exactly at the threshold still fires."""
    return math.floor(value * 1000) / 1000


def choose(scores: dict[str, float], calibration: list[Scenario]) -> tuple[float | None, float]:
    """Threshold maximizing J on the calibration part (None if nothing ever fires).

    Candidates are the calibration scores rounded down to 3 decimals, the
    precision the config file stores.
    """
    candidates = sorted(
        {floor3(scores[s.id]) for s in calibration if scores[s.id] > 0}, reverse=True
    )
    best: float | None = None
    best_j = 0.0
    for t in candidates:  # descending, so ties keep the higher threshold
        c = counts(scores, calibration, t)
        if c.tpr - c.fpr > best_j:
            best, best_j = t, c.tpr - c.fpr
    return best, best_j


def flagged(detector: Detector, scenario: Scenario, metadata: bool) -> bool:
    result = BenchmarkRunner(detector=detector, track_tool_metadata=metadata).run(scenario)
    return any(step.findings for step in result.steps)


def policy_counts(detector: Detector, scenarios: list[Scenario], metadata: bool) -> Counts:
    c = Counts()
    for s in scenarios:
        hit = flagged(detector, s, metadata)
        if s.is_attack:
            c.tp += hit
            c.fn += not hit
        else:
            c.fp += hit
            c.tn += not hit
    return c


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--split", type=Path, default=REPO / "benchmarks/splits/week9.json")
    parser.add_argument("--no-tool-metadata", action="store_true")
    parser.add_argument("--skip-embedding", action="store_true", help="faster; for tests")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    split = json.loads(args.split.read_text(encoding="utf-8"))
    by_id = {s.id: s for d in SUITES for s in load_scenarios(REPO / "benchmarks" / d)}
    calibration = [by_id[i] for i in split["calibration"]]
    held_out = [by_id[i] for i in split["held_out"]]
    metadata = not args.no_tool_metadata
    has_embedding = (
        not args.skip_embedding and importlib.util.find_spec("sentence_transformers") is not None
    )

    lines = [
        "# Detector calibration (Week 9)",
        "",
        f"- split: `{args.split.name}`"
        f" (calibration {len(calibration)}: "
        f"{sum(s.is_attack for s in calibration)} attacks / "
        f"{sum(not s.is_attack for s in calibration)} benign; held-out {len(held_out)}: "
        f"{sum(s.is_attack for s in held_out)} attacks / "
        f"{sum(not s.is_attack for s in held_out)} benign)",
        f"- tool metadata tracked: {'yes' if metadata else 'no'}",
        "- rule: maximize J = TPR - FPR on calibration; ties go to the higher threshold",
        "- embedding: "
        + ("included" if has_embedding else "skipped (not installed or --skip-embedding)"),
        "",
        "## Per-detector thresholds",
        "",
        "| detector | threshold | J (cal) | cal TP | FP | TN | FN | TPR | FPR "
        "| held-out TP | FP | TN | FN | TPR | FPR |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    chosen: dict[str, float | None] = {}
    all_scores: dict[str, dict[str, float]] = {}
    for name, detector in variants(has_embedding).items():
        scores = {s.id: score(detector, s, metadata) for s in calibration + held_out}
        all_scores[name] = scores
        threshold, j = choose(scores, calibration)
        chosen[name] = threshold
        shown = f"{threshold:.3f}" if threshold is not None else "none"
        lines.append(
            f"| {name} | {shown} | {j:.2f} | {counts(scores, calibration, threshold).cells()} "
            f"| {counts(scores, held_out, threshold).cells()} |"
        )

    substring_mode = (
        "coverage"
        if choose(all_scores["substring (coverage)"], calibration)[1]
        >= choose(all_scores["substring (longest)"], calibration)[1]
        else "longest"
    )
    sub_t = chosen[f"substring ({substring_mode})"]
    struct_t = chosen["structured"]
    gated: list[Detector] = []
    thresholds: dict[str, float] = {}
    if sub_t is not None:
        gated.append(GatedDetector(SubstringDetector(score_mode=substring_mode), sub_t))
        thresholds["substring"] = sub_t
    if struct_t is not None:
        gated.append(GatedDetector(StructuredFieldDetector(), struct_t))
        thresholds["structured"] = struct_t
    emb_t = chosen.get("embedding")
    if emb_t is not None:
        gated.append(GatedDetector(EmbeddingDetector(threshold=emb_t), emb_t))
        thresholds["embedding"] = emb_t

    week7 = CompositeDetector(
        [
            GatedDetector(SubstringDetector(score_mode="longest"), 0.6),
            GatedDetector(StructuredFieldDetector(), 0.6),
        ]
    )
    calibrated = CompositeDetector(gated) if gated else week7
    policies = [
        ("Week 7 live default (longest substring + structured, 0.6, no metadata)", week7, False),
        ("Week 7 default + tool metadata", week7, True),
        (
            f"Week 9 calibrated ({substring_mode} substring, per-detector, metadata)",
            calibrated,
            True,
        ),
    ]
    lines += [
        "",
        "## Live policies",
        "",
        "| policy | split | TP | FP | TN | FN | TPR | FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for label, detector, meta in policies:
        for part, scenarios in (("calibration", calibration), ("held-out", held_out)):
            lines.append(
                f"| {label} | {part} | {policy_counts(detector, scenarios, meta).cells()} |"
            )

    lines += [
        "",
        "## Held-out scenarios",
        "",
        "| scenario | truth | " + " | ".join(all_scores) + " | Week 7 | Week 9 |",
        "|---|---|" + "---|" * (len(all_scores) + 2),
    ]
    for s in held_out:
        cells = []
        for name, scores in all_scores.items():
            t = chosen[name]
            mark = "**" if t is not None and scores[s.id] >= t else ""
            cells.append(f"{mark}{scores[s.id]:.2f}{mark}")
        w7 = "flag" if flagged(week7, s, False) else "-"
        w9 = "flag" if flagged(calibrated, s, True) else "-"
        truth = "attack" if s.is_attack else "benign"
        lines.append(f"| {s.id} | {truth} | " + " | ".join(cells) + f" | {w7} | {w9} |")

    rendered = ", ".join(f"{k} = {v}" for k, v in thresholds.items())
    lines += [
        "",
        "Bold scores reach the detector's calibrated threshold.",
        "",
        "## Recommended `[detection]` settings",
        "",
        "```toml",
        "[detection]",
        f"detectors = [{', '.join(repr(k).replace(chr(39), chr(34)) for k in thresholds)}]",
        f'substring_score = "{substring_mode}"',
        "track_tool_metadata = true",
        f"thresholds = {{ {rendered} }}",
        "```",
        "",
    ]
    report = "\n".join(lines)
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "substring_score": substring_mode,
            "thresholds": thresholds,
            "track_tool_metadata": metadata,
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
