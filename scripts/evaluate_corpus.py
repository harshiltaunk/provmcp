"""Evaluate every detector against the full scenario corpus.

Runs each detector configuration over all attack and benign scenarios and
prints, per detector, a confusion matrix plus precision, recall, and
false-positive rate. A per-scenario hit table shows which detector caught
which scenario, which is the view the final report needs.

Usage:
    python scripts/evaluate_corpus.py
    python scripts/evaluate_corpus.py --embedding-threshold 0.52
    python scripts/evaluate_corpus.py --out docs/results/eval-week6.md
    python scripts/evaluate_corpus.py --split benchmarks/splits/week6.json   # frozen Week 6 corpus

The embedding detector needs the optional extra (`pip install -e ".[embed]"`).
Without it, the embedding row reports zero detections and prints a warning.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from provmcp.benchmark import BenchmarkRunner, Scenario, load_scenarios
from provmcp.detectors import (
    CompositeDetector,
    Detector,
    EmbeddingDetector,
    StructuredFieldDetector,
    SubstringDetector,
)

REPO = Path(__file__).parent.parent
ATTACKS = REPO / "benchmarks" / "attacks"
BENIGN = REPO / "benchmarks" / "benign"


def split_ids(path: Path | None) -> set[str] | None:
    """Scenario ids listed in a split file (every list in it), or None for all."""
    if path is None:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {sid for value in data.values() if isinstance(value, list) for sid in value}


@dataclass
class Scores:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0


def build_detectors(embedding_threshold: float) -> dict[str, Detector]:
    return {
        "substring": SubstringDetector(min_run_length=8),
        "structured": StructuredFieldDetector(),
        "embedding": EmbeddingDetector(threshold=embedding_threshold),
        "composite": CompositeDetector(
            [
                SubstringDetector(min_run_length=8),
                StructuredFieldDetector(),
                EmbeddingDetector(threshold=embedding_threshold),
            ]
        ),
    }


def flagged(runner: BenchmarkRunner, scenario: Scenario) -> bool:
    return any(step.findings for step in runner.run(scenario).steps)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--embedding-threshold", type=float, default=0.72)
    parser.add_argument("--out", type=Path, default=None, help="write a markdown report here")
    parser.add_argument("--split", type=Path, default=None, help="only the ids in this split file")
    args = parser.parse_args()

    keep = split_ids(args.split)
    corpus = [
        s for s in load_scenarios(ATTACKS) + load_scenarios(BENIGN) if keep is None or s.id in keep
    ]
    detectors = build_detectors(args.embedding_threshold)

    scores: dict[str, Scores] = {name: Scores() for name in detectors}
    hits: dict[str, dict[str, bool]] = {s.id: {} for s in corpus}

    for name, detector in detectors.items():
        runner = BenchmarkRunner(detector=detector)
        for scenario in corpus:
            hit = flagged(runner, scenario)
            hits[scenario.id][name] = hit
            is_attack = scenario.ground_truth == "cross_server_influence"
            if is_attack and hit:
                scores[name].tp += 1
            elif is_attack:
                scores[name].fn += 1
            elif hit:
                scores[name].fp += 1
            else:
                scores[name].tn += 1

    names = list(detectors)
    lines: list[str] = []
    lines.append(f"# Corpus evaluation (embedding threshold {args.embedding_threshold:.3f})")
    lines.append("")
    n_attack = sum(s.ground_truth == "cross_server_influence" for s in corpus)
    lines.append(f"{n_attack} attack scenario(s), {len(corpus) - n_attack} benign scenario(s).")
    lines.append("")
    lines.append("## Per-detector scores")
    lines.append("")
    lines.append("| detector | TP | FP | TN | FN | precision | recall | FPR |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for name in names:
        sc = scores[name]
        lines.append(
            f"| {name} | {sc.tp} | {sc.fp} | {sc.tn} | {sc.fn} | "
            f"{sc.precision:.2f} | {sc.recall:.2f} | {sc.fpr:.2f} |"
        )
    lines.append("")
    lines.append("## Per-scenario hits")
    lines.append("")
    lines.append("| scenario | ground truth | " + " | ".join(names) + " |")
    lines.append("|---|---|" + "---|" * len(names))
    for scenario in corpus:
        marks = " | ".join("flag" if hits[scenario.id][n] else "-" for n in names)
        lines.append(f"| {scenario.id} | {scenario.ground_truth} | {marks} |")

    report = "\n".join(lines) + "\n"
    print(report)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
