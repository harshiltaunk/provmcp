"""Scan the embedding detector's threshold against the current corpus.

Runs every attack and every benign scenario at a grid of threshold values
from 0.50 to 0.95 in steps of 0.025. For each threshold, reports
TP, FP, TN, FN, precision, and recall so we can pick the operating point.

Usage:
    python scripts/sweep_embedding_threshold.py

Requires `sentence-transformers` to be installed:
    pip install 'provmcp[embed]'
"""

from __future__ import annotations

from pathlib import Path

from provmcp.benchmark import BenchmarkRunner, load_scenarios
from provmcp.detectors.embedding import EmbeddingDetector

REPO = Path(__file__).parent.parent
ATTACKS = REPO / "benchmarks" / "attacks"
BENIGN = REPO / "benchmarks" / "benign"


def precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall


def main() -> None:
    attacks = load_scenarios(ATTACKS)
    benign = load_scenarios(BENIGN)
    print(f"Loaded {len(attacks)} attack scenario(s) and {len(benign)} benign scenario(s)")
    print()
    print(f"{'thresh':>8}  {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}   P      R")

    for i in range(18, 39):  # 0.450 .. 0.950 step 0.025
        threshold = i / 40.0
        detector = EmbeddingDetector(threshold=threshold)
        runner = BenchmarkRunner(detector=detector)
        tp = fp = tn = fn = 0
        for scenario in attacks:
            flagged = any(step.findings for step in runner.run(scenario).steps)
            if flagged:
                tp += 1
            else:
                fn += 1
        for scenario in benign:
            flagged = any(step.findings for step in runner.run(scenario).steps)
            if flagged:
                fp += 1
            else:
                tn += 1
        p, r = precision_recall(tp, fp, fn)
        print(f"{threshold:>8.3f}  {tp:>3} {fp:>3} {tn:>3} {fn:>3}   {p:.2f}   {r:.2f}")


if __name__ == "__main__":
    main()
