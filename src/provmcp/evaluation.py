"""Week 10 evaluation: every detection strategy, scored at every level.

Levels, from most controlled to most realistic:

1. **Corpus** - the 27 bundled scenarios replayed offline. Detection rate over
   attacks, false-alarm rate over benign scenarios, for all scenarios and for
   the held-out part of the Week 9 split.
2. **Compliant agent at scale** - the imported InjecAgent cases replayed
   offline with the calls a fully obedient agent would make. Detection only:
   every case is an attack.
3. **Real model traffic** - cached LLM runs replayed through each strategy
   (`provmcp.agent.replay`). False alarms on runs with no attack, detection
   on the attacks the model actually attempted.
4. **End to end** - attack success and task completion measured live, per
   condition (audit = baseline, strict = blocking), from the cached runs.

Every rate carries a 95% Wilson score interval. With samples this small the
interval matters as much as the point estimate.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from provmcp.agent.experiment import rescore
from provmcp.agent.replay import build_replay_detector, replay_all
from provmcp.agent.runner import EpisodeResult
from provmcp.benchmark import BenchmarkRunner, Scenario
from provmcp.config import DetectionConfig, DetectorName


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass(frozen=True)
class Rate:
    k: int
    n: int

    @property
    def value(self) -> float:
        return self.k / self.n if self.n else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson(self.k, self.n)

    def __str__(self) -> str:
        if not self.n:
            return "-"
        lo, hi = self.interval
        return f"{self.k}/{self.n} ({100 * self.value:.0f}%, {100 * lo:.0f}-{100 * hi:.0f})"

    def to_json(self) -> dict[str, float | int]:
        lo, hi = self.interval
        return {
            "k": self.k,
            "n": self.n,
            "rate": round(self.value, 4),
            "ci_low": round(lo, 4),
            "ci_high": round(hi, 4),
        }


@dataclass(frozen=True)
class Strategy:
    name: str
    detection: DetectionConfig
    threshold: float = 0.6


def strategies_from_calibration(
    calibration: dict[str, object], *, embedding: bool
) -> list[Strategy]:
    """The strategies compared in Week 10, built from the Week 9 calibration file."""
    raw = calibration.get("thresholds")
    thresholds: dict[str, float] = (
        {str(k): float(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
    )
    score = str(calibration.get("substring_score", "longest"))

    def single(name: DetectorName) -> DetectionConfig:
        return DetectionConfig.model_validate(
            {
                "detectors": [name],
                "thresholds": {name: thresholds[name]},
                "substring_score": score,
                "track_tool_metadata": True,
            }
        )

    found = [
        Strategy("Week 7 settings", DetectionConfig(thresholds={}, track_tool_metadata=False)),
        Strategy("substring", single("substring")),
        Strategy("structured", single("structured")),
    ]
    if embedding and "embedding" in thresholds:
        found.append(Strategy("embedding", single("embedding")))
    found.append(
        Strategy(
            "0.9.0 default (substring + structured)",
            DetectionConfig.model_validate(
                {
                    "detectors": ["substring", "structured"],
                    "thresholds": {k: thresholds[k] for k in ("substring", "structured")},
                    "substring_score": score,
                    "track_tool_metadata": True,
                }
            ),
        )
    )
    if embedding and "embedding" in thresholds:
        found.append(
            Strategy(
                "default + embedding",
                DetectionConfig.model_validate(
                    {
                        "detectors": ["substring", "structured", "embedding"],
                        "thresholds": dict(thresholds),
                        "substring_score": score,
                        "track_tool_metadata": True,
                    }
                ),
            )
        )
    return found


def offline_flags(strategy: Strategy, scenarios: Sequence[Scenario]) -> dict[str, bool]:
    """Whether the strategy flags any step of each scenario's trace."""
    detector, minimum = build_replay_detector(strategy.detection, strategy.threshold)
    runner = BenchmarkRunner(
        detector=detector, track_tool_metadata=strategy.detection.track_tool_metadata
    )
    flags: dict[str, bool] = {}
    for scenario in scenarios:
        result = runner.run(scenario)
        flags[scenario.id] = any(
            f.confidence >= minimum for step in result.steps for f in step.findings
        )
    return flags


def detection_and_false_alarms(
    flags: dict[str, bool], scenarios: Sequence[Scenario]
) -> tuple[Rate, Rate]:
    attacks = [s for s in scenarios if s.is_attack]
    benign = [s for s in scenarios if not s.is_attack]
    return (
        Rate(sum(flags[s.id] for s in attacks), len(attacks)),
        Rate(sum(flags[s.id] for s in benign), len(benign)),
    )


@dataclass(frozen=True)
class TrafficResult:
    false_alarms: Rate
    detected: Rate
    flagged_calls: int
    calls: int


def real_traffic(
    strategy: Strategy, results: Sequence[EpisodeResult], scenarios: dict[str, Scenario]
) -> TrafficResult:
    """Replay audit-condition episodes through the strategy."""
    audit = [r for r in results if r.condition == "audit"]
    replayed = replay_all(audit, scenarios, strategy.detection, threshold=strategy.threshold)
    quiet = [e for e in replayed if not e.is_attack or not e.attempted]
    attempted = [e for e in replayed if e.is_attack and e.attempted]
    return TrafficResult(
        false_alarms=Rate(sum(e.false_alarm for e in quiet), len(quiet)),
        detected=Rate(sum(e.flagged_goal for e in attempted), len(attempted)),
        flagged_calls=sum(e.flagged_calls for e in replayed),
        calls=sum(e.calls for e in replayed),
    )


@dataclass(frozen=True)
class EndToEnd:
    condition: str
    detection: str
    attack_success: Rate  # succeeded / valid attack episodes
    task_completion: Rate  # succeeded / benign episodes


def end_to_end(results: Sequence[EpisodeResult], scenarios: dict[str, Scenario]) -> list[EndToEnd]:
    """Attack success and benign task completion per condition (rescored, current oracles)."""
    rescored, _ = rescore(results, scenarios)
    rows: list[EndToEnd] = []
    for condition in sorted({r.condition for r in rescored}):
        eps = [r for r in rescored if r.condition == condition]
        attacks = [r for r in eps if r.is_attack and r.valid]
        benign = [r for r in eps if not r.is_attack]
        labels = sorted({r.detection for r in eps if r.detection})
        rows.append(
            EndToEnd(
                condition=condition,
                detection="; ".join(labels) or "(not recorded)",
                attack_success=Rate(sum(r.succeeded for r in attacks), len(attacks)),
                task_completion=Rate(sum(r.succeeded for r in benign), len(benign)),
            )
        )
    return rows
