"""Scenario loader and offline benchmark runner.

A scenario is a JSON file that declares two or more servers, the responses
each would give for `tools/list` and `tools/call`, and an ordered trace of
calls the host (LLM) is assumed to make. The runner replays the trace
through a ProvMCP Proxy whose transports return the canned responses, runs
the configured detectors on each outbound call, and reports per-step
findings.

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


class Scenario(BaseModel):
    id: str
    title: str
    description: str = ""
    servers: list[ScenarioServer]
    trace: list[ScenarioStep]
    ground_truth: str


def load_scenario(path: str | Path) -> Scenario:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def load_scenarios(root: str | Path) -> list[Scenario]:
    """Load every `.json` scenario under a directory (non-recursive)."""
    return sorted(
        (load_scenario(p) for p in Path(root).glob("*.json")),
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

    def __init__(self, *, detector: SubstringDetector | None = None) -> None:
        self.detector = detector or SubstringDetector(min_run_length=8)

    def run(self, scenario: Scenario) -> ScenarioResult:
        store = ProvenanceStore.empty()
        step_results: list[StepResult] = []
        for step in scenario.trace:
            canned_result = _canned_result_for(scenario, step)
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


def _canned_result_for(scenario: Scenario, step: ScenarioStep) -> Any:
    for server in scenario.servers:
        if server.id == step.server:
            if step.method in server.canned:
                return server.canned[step.method]
            return {}
    raise KeyError(f"step references unknown server: {step.server!r}")
