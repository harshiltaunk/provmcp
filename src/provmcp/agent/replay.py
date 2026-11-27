"""Replay cached agent episodes through a detector configuration, offline.

Week 9 uses this to measure false alarms on *real* model traffic, the cached
Claude runs from Week 8, without calling the model again. For each episode
the provenance store is rebuilt call by call from the scenario's canned
responses (the same content the servers returned live), and the detector is
run on every call exactly as the live Inspector would.

Only episodes whose calls were all forwarded can be replayed faithfully, so
the default is the `audit` condition. Under `strict`, a blocked call never
returned content, and a different detector would have changed what was
blocked.

Counting:

- A *false-alarm episode* is a benign episode, or an attack episode where
  the attack was not attempted, with at least one flagged call. This is the
  traffic a user would see interrupted for nothing.
- An attempted attack is *detected* when a goal call is flagged.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from provmcp.agent.runner import EpisodeResult, goal_matches, scenario_group
from provmcp.benchmark import Scenario, canned_tool_result
from provmcp.config import DetectionConfig, ProvMcpConfig, ProxyConfig
from provmcp.detectors.base import Detector
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.wiring import build_detector


@dataclass
class ReplayedEpisode:
    scenario_id: str
    group: str
    condition: str
    trial: int
    is_attack: bool
    attempted: bool
    calls: int = 0
    flagged_calls: int = 0
    flagged_goal: bool = False
    alarms: list[str] = field(default_factory=list)

    @property
    def false_alarm(self) -> bool:
        return (not self.is_attack or not self.attempted) and self.flagged_calls > 0


def build_replay_detector(detection: DetectionConfig, threshold: float) -> tuple[Detector, float]:
    """The live detector for this configuration, and the confidence the Inspector requires."""
    config = ProvMcpConfig(proxy=ProxyConfig(detector_threshold=threshold), detection=detection)
    minimum = 0.0 if detection.thresholds else threshold
    return build_detector(config), minimum


def replay_episode(
    result: EpisodeResult,
    scenario: Scenario,
    detector: Detector,
    *,
    min_confidence: float,
    track_tool_metadata: bool,
) -> ReplayedEpisode:
    _, per_goal = goal_matches(result, scenario)
    goal_indexes = {i for matched in per_goal for i in matched}
    replayed = ReplayedEpisode(
        scenario_id=scenario.id,
        group=scenario_group(scenario),
        condition=result.condition,
        trial=result.trial,
        is_attack=scenario.is_attack,
        attempted=all(per_goal),
    )
    store = ProvenanceStore.empty()
    if track_tool_metadata:
        for server in scenario.servers:
            if "tools/list" in server.canned:
                tag = OriginTag(server_id=server.id, tool_name="tools/list")
                store.record(TaggedPayload(content=server.canned["tools/list"], tag=tag))
    counts: dict[tuple[str, str], int] = {}
    known = {s.id for s in scenario.servers}
    for index, call in enumerate(result.calls):
        if call.server not in known:
            continue
        replayed.calls += 1
        findings = [
            f
            for f in detector.scan(
                store=store,
                target_server_id=call.server,
                outbound_params={"name": call.tool, "arguments": call.arguments},
            )
            if f.confidence >= min_confidence
        ]
        if findings:
            replayed.flagged_calls += 1
            replayed.flagged_goal |= index in goal_indexes
            top = max(findings, key=lambda f: f.confidence)
            replayed.alarms.append(
                f"{top.source_server_id} -> {call.server}.{call.tool} "
                f"({top.detector} {top.confidence:.2f}): {top.excerpt[:60]!r}"
            )
        if call.forwarded:
            n = counts.get((call.server, call.tool), 0)
            counts[(call.server, call.tool)] = n + 1
            content = canned_tool_result(scenario.server(call.server).canned, call.tool, n)
            tag = OriginTag(server_id=call.server, tool_name="tools/call")
            store.record(TaggedPayload(content=content, tag=tag))
    return replayed


def replay_all(
    results: Sequence[EpisodeResult],
    scenarios: dict[str, Scenario],
    detection: DetectionConfig,
    *,
    threshold: float = 0.6,
) -> list[ReplayedEpisode]:
    detector, minimum = build_replay_detector(detection, threshold)
    return [
        replay_episode(
            r,
            scenarios[r.scenario_id],
            detector,
            min_confidence=minimum,
            track_tool_metadata=detection.track_tool_metadata,
        )
        for r in results
        if r.scenario_id in scenarios and scenarios[r.scenario_id].oracle is not None
    ]


def render_replay_report(
    replayed: Sequence[ReplayedEpisode], *, title: str, settings: dict[str, str], examples: int = 25
) -> str:
    groups: dict[str, list[ReplayedEpisode]] = {}
    for episode in replayed:
        groups.setdefault(episode.group, []).append(episode)

    def pct(n: int, d: int) -> str:
        return f"{100 * n / d:.1f}%" if d else "-"

    lines = [f"# {title}", ""]
    lines += [f"- **{key}:** {value}" for key, value in settings.items()]
    lines += [
        "",
        "## False alarms and detection",
        "",
        "| suite | episodes | non-attack episodes | false-alarm episodes | false-alarm rate "
        "| attempted attacks | detected | flagged calls / calls |",
        "|---|---|---|---|---|---|---|---|",
    ]
    totals = [0] * 6
    for group in sorted(groups):
        eps = groups[group]
        quiet = [e for e in eps if not e.is_attack or not e.attempted]
        alarms = sum(e.false_alarm for e in eps)
        attempted = [e for e in eps if e.is_attack and e.attempted]
        detected = sum(e.flagged_goal for e in attempted)
        calls = sum(e.calls for e in eps)
        flagged = sum(e.flagged_calls for e in eps)
        for i, v in enumerate((len(eps), len(quiet), alarms, len(attempted), detected, flagged)):
            totals[i] += v
        lines.append(
            f"| {group} | {len(eps)} | {len(quiet)} | {alarms} | {pct(alarms, len(quiet))} "
            f"| {len(attempted)} | {detected} | {flagged} / {calls} |"
        )
    all_calls = sum(e.calls for e in replayed)
    lines.append(
        f"| **all** | {totals[0]} | {totals[1]} | {totals[2]} | {pct(totals[2], totals[1])} "
        f"| {totals[3]} | {totals[4]} | {totals[5]} / {all_calls} |"
    )
    shown = [e for e in replayed if e.false_alarm][:examples]
    if shown:
        lines += ["", f"## False alarms (first {len(shown)})", ""]
        lines += [
            f"- `{e.scenario_id}` ({e.condition}, trial {e.trial}): {e.alarms[0]}" for e in shown
        ]
    lines.append("")
    return "\n".join(lines)
