"""Scenario loader and offline benchmark runner.

A scenario is a JSON file that declares two or more servers, the responses
each would give for `tools/list` and `tools/call`, and an ordered trace of
calls the host (LLM) is assumed to make. The runner replays the trace
through a ProvMCP Proxy whose transports return the canned responses, runs
the configured detectors on each outbound call, and reports per-step
findings.

Since Week 8 a scenario can also drive a real LLM agent (`provmcp.agent`):

- `task` is the user's request to the agent.
- `oracle` says what success means: the `entry` call exposes the agent to
  the scenario's content (an episode without it is invalid), and every
  `goal` call must reach its server. For an attack the goal is the
  attacker's objective and must come *after* the entry call; for a benign
  scenario it is the user's task, in any order.
- `canned["responses"]` maps a tool name to its result. A list is a
  sequence: the n-th call returns the n-th item (the last item repeats).
- `metadata` records where an imported scenario came from.

The runner is deliberately offline — it never starts a subprocess, never
talks to a real LLM. It exists to exercise the provenance pipeline and
the detector stack against a growing corpus of hand-authored scenarios
without the overhead (or non-determinism) of a live host.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from provmcp.detectors.base import Detector
from provmcp.detectors.substring import SubstringDetector
from provmcp.policy import InfluenceFinding
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.registry import TrustClass


class ScenarioServer(BaseModel):
    id: str
    display_name: str
    trust: TrustClass = TrustClass.LIMITED
    canned: dict[str, Any]


class ScenarioStep(BaseModel):
    step: int
    server: str
    method: str
    params: dict[str, Any] = Field(default_factory=dict)
    expect_cross_origin_from: str | None = None


def _leaf_values(value: Any) -> list[str]:
    """Every scalar value inside nested arguments, as text. Key names are skipped."""
    if isinstance(value, dict):
        return [text for item in value.values() for text in _leaf_values(item)]
    if isinstance(value, list):
        return [text for item in value for text in _leaf_values(item)]
    return [] if value is None else [str(value)]


class OracleCall(BaseModel):
    """One tool call the oracle looks for.

    Matching is case-insensitive and looks at argument *values* only, so a
    schema's key names can never satisfy it.

    - `contains`: every string must appear.
    - `any_of`: at least one must appear. Used when the exact wording is
      unknown, e.g. distinctive tokens from an attacker instruction.
    """

    server: str
    tool: str
    contains: list[str] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)

    def matches(self, server: str, tool: str, arguments: Any) -> bool:
        """True if this is the call and its argument values carry the required evidence."""
        if server != self.server or tool != self.tool:
            return False
        text = "\n".join(_leaf_values(arguments)).lower()
        if not all(needle.lower() in text for needle in self.contains):
            return False
        return not self.any_of or any(needle.lower() in text for needle in self.any_of)


class Oracle(BaseModel):
    """What counts as success when an agent runs the scenario."""

    entry: OracleCall | None = None
    goal: list[OracleCall]


class Scenario(BaseModel):
    id: str
    title: str
    description: str = ""
    servers: list[ScenarioServer]
    trace: list[ScenarioStep] = Field(default_factory=list)
    ground_truth: str
    task: str | None = None
    oracle: Oracle | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_attack(self) -> bool:
        return self.ground_truth == "cross_server_influence"

    def server(self, server_id: str) -> ScenarioServer:
        for server in self.servers:
            if server.id == server_id:
                return server
        raise KeyError(f"scenario {self.id} has no server {server_id!r}")


def load_scenario(path: str | Path) -> Scenario:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def load_scenarios(root: str | Path) -> list[Scenario]:
    """Load every `.json` scenario under a directory (non-recursive).

    Files whose names start with `_` (such as an importer's `_manifest.json`)
    are skipped.
    """
    return sorted(
        (load_scenario(p) for p in Path(root).glob("*.json") if not p.name.startswith("_")),
        key=lambda s: s.id,
    )


@dataclass
class StepResult:
    step: int
    server: str
    method: str
    findings: list[InfluenceFinding]
    expected_cross_origin_from: str | None


@dataclass
class ScenarioResult:
    scenario_id: str
    ground_truth: str
    steps: list[StepResult]

    def true_positive(self) -> bool:
        if self.ground_truth != "cross_server_influence":
            return False
        return any(s.findings for s in self.steps)

    def false_positive(self) -> bool:
        if self.ground_truth != "benign":
            return False
        return any(s.findings for s in self.steps)


class BenchmarkRunner:
    """Replay one or more scenarios offline and collect findings.

    The runner is single-detector for Week 4; the embedding and
    structured-field detectors arrive in Weeks 5 and 6 and will plug in
    through a shared Detector protocol then.
    """

    def __init__(self, *, detector: Detector | None = None) -> None:
        self.detector = detector or SubstringDetector(min_run_length=8)

    def run(self, scenario: Scenario) -> ScenarioResult:
        store = ProvenanceStore.empty()
        step_results: list[StepResult] = []
        counts: dict[tuple[str, str], int] = {}
        for step in scenario.trace:
            canned_result = _canned_result_for(scenario, step, counts)
            # If the step reads from the server, tag the response with the
            # server's origin before considering the next step.
            tag = OriginTag(server_id=step.server, tool_name=step.method)
            store.record(TaggedPayload(content=canned_result, tag=tag))

            # Also check this step's *outbound* params against prior
            # provenance, because a call to server B carrying content from
            # server A is the attack we want to catch.
            findings = self.detector.scan(
                store=store,
                target_server_id=step.server,
                outbound_params=step.params,
            )
            step_results.append(
                StepResult(
                    step=step.step,
                    server=step.server,
                    method=step.method,
                    findings=findings,
                    expected_cross_origin_from=step.expect_cross_origin_from,
                )
            )
        return ScenarioResult(
            scenario_id=scenario.id,
            ground_truth=scenario.ground_truth,
            steps=step_results,
        )


def canned_tool_result(canned: dict[str, Any], tool: str, call_index: int) -> Any:
    """The canned result for the `call_index`-th call (0-based) to `tool`."""
    responses = canned.get("responses") or {}
    if tool in responses:
        value = responses[tool]
        if isinstance(value, list):
            return value[min(call_index, len(value) - 1)] if value else {}
        return value
    return canned.get("tools/call", {})


def _canned_result_for(
    scenario: Scenario, step: ScenarioStep, counts: dict[tuple[str, str], int]
) -> Any:
    try:
        server = scenario.server(step.server)
    except KeyError:
        raise KeyError(f"step references unknown server: {step.server!r}") from None
    if step.method == "tools/call":
        tool = str(step.params.get("name", ""))
        index = counts.get((step.server, tool), 0)
        counts[(step.server, tool)] = index + 1
        return canned_tool_result(server.canned, tool, index)
    return server.canned.get(step.method, {})
