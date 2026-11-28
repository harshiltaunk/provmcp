"""Declaration probe (Week 13): what scope does a model declare for a request?

One short conversation per scenario. The model is shown exactly the catalog a
full episode shows (every server's tools plus `declare_scope`) and the user's
task, and the probe stops as soon as a scope is accepted. No server is
started and no tool runs, so the declaration can only depend on the task and
the catalog, which is the situation `provmcp.scope` relies on.

If the model calls another tool first, it gets the same refusal the proxy
gives and one more turn, up to `max_turns`.

Results go to a JSONL cache keyed by (scenario, model, trial, wording of the
tool), so a run can be interrupted and resumed, and is never paid for twice.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from provmcp.agent.backends import Backend, BackendError, ToolResult
from provmcp.agent.experiment import run_order
from provmcp.agent.runner import SYSTEM_PROMPT, scenario_group, scenario_tool_specs
from provmcp.benchmark import Scenario
from provmcp.inspector import Decision, held_result
from provmcp.policy import PolicyAction, PolicyTemplate
from provmcp.scope import SCOPE_SERVER_ID, SCOPE_TOOL_VERSION, ScopeError, ScopeGuard


@dataclass
class ProbeResult:
    scenario_id: str
    group: str
    backend: str
    model: str
    trial: int
    declared: dict[str, Any] | None = None  # the accepted scope, or None
    declared_first: bool = False  # the first tool call was the declaration
    turns: int = 0
    nudged: int = 0  # other tools called before any declaration
    invalid: int = 0  # declarations refused as malformed
    first_calls: list[str] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None
    tool_version: str = SCOPE_TOOL_VERSION  # wording of `declare_scope` the model saw

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ProbeResult:
        return cls(**data)


def probe_key(
    scenario_id: str, model: str, trial: int, tool_version: str = SCOPE_TOOL_VERSION
) -> str:
    return f"{scenario_id}|{model}|{trial}|{tool_version}"


def _refusal(server: str, tool: str) -> str:
    decision = Decision(
        action=PolicyAction.BLOCK,
        template=PolicyTemplate.STRICT,
        target=server,
        tool=tool,
        scope="undeclared",
    )
    return str(held_result(decision)["content"][0]["text"])


async def probe_scenario(
    scenario: Scenario,
    backend: Backend,
    *,
    trial: int = 0,
    max_turns: int = 3,
    system_prompt: str = SYSTEM_PROMPT,
) -> ProbeResult:
    """Ask for the first turns of an episode and record the declared scope."""
    specs = scenario_tool_specs(scenario, declare=True)
    by_name = {spec.name: spec for spec in specs}
    guard = ScopeGuard(servers={s.id: s.display_name for s in scenario.servers})
    result = ProbeResult(
        scenario_id=scenario.id,
        group=scenario_group(scenario),
        backend=backend.name,
        model=backend.model,
        trial=trial,
    )
    backend.begin(system=system_prompt, task=scenario.task or scenario.title, tools=specs)
    for turn_number in range(1, max_turns + 1):
        turn = await backend.step()
        result.turns = turn_number
        result.input_tokens += turn.input_tokens
        result.output_tokens += turn.output_tokens
        if turn.truncated:
            result.error = "reply cut off at the output limit (raise --max-tokens)"
            break
        if turn_number == 1:
            result.first_calls = [call.name for call in turn.calls]
            first = by_name.get(turn.calls[0].name) if turn.calls else None
            result.declared_first = first is not None and first.server == SCOPE_SERVER_ID
        if not turn.calls:
            break
        replies: list[ToolResult] = []
        for call in turn.calls:
            spec = by_name.get(call.name)
            if spec is not None and spec.server == SCOPE_SERVER_ID:
                try:
                    scope = guard.declare(call.arguments)
                except ScopeError as exc:
                    replies.append(ToolResult(call, str(exc), is_error=True))
                else:
                    replies.append(ToolResult(call, f"Scope recorded ({scope.describe()})."))
            elif guard.scope is None:
                result.nudged += 1
                server, tool = (spec.server, spec.tool) if spec else ("?", call.name)
                replies.append(ToolResult(call, _refusal(server, tool), is_error=True))
            else:
                replies.append(ToolResult(call, "Not run: this probe stops at the declaration."))
        if guard.scope is not None:
            break
        backend.add_results(replies)
    result.declared = guard.scope.to_json() if guard.scope is not None else None
    result.invalid = guard.invalid
    return result


def load_probes(path: Path | None) -> dict[str, ProbeResult]:
    done: dict[str, ProbeResult] = {}
    if path is None or not path.is_file():
        return done
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            result = ProbeResult.from_json(json.loads(line))
            if result.error is None:
                key = probe_key(result.scenario_id, result.model, result.trial, result.tool_version)
                done[key] = result
    return done


def estimate_probe_tokens(scenario: Scenario) -> tuple[int, int]:
    """Rough input/output tokens for one probe (4 characters per token)."""
    chars = sum(
        len(t.description) + len(json.dumps(t.input_schema)) + len(t.name)
        for t in scenario_tool_specs(scenario, declare=True)
    )
    return 300 + (chars + len(scenario.task or "")) // 4, 150


async def run_probe(
    scenarios: Sequence[Scenario],
    make_backend: Callable[[Scenario], Backend],
    *,
    model: str,
    trials: int = 1,
    cache: Path | None = None,
    concurrency: int = 4,
    price_in: float = 0.0,
    price_out: float = 0.0,
    max_usd: float | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[ProbeResult]:
    """Probe every (scenario, trial) not already in the cache."""
    say = progress or (lambda _msg: None)
    done = load_probes(cache)
    jobs = [(scenario, trial) for scenario in scenarios for trial in range(trials)]
    wanted = {probe_key(s.id, model, t) for s, t in jobs}
    results = {k: v for k, v in done.items() if k in wanted}
    # Trial by trial, scenarios in a fixed pseudo-random order: a run that stops
    # early leaves a random sample, not the top of the list.
    pending = [
        (s, t) for s, t in run_order(scenarios, trials) if probe_key(s.id, model, t) not in results
    ]

    def cost(r: ProbeResult) -> float:
        return (r.input_tokens * price_in + r.output_tokens * price_out) / 1_000_000

    spent = sum(cost(r) for r in results.values())
    say(f"{len(jobs)} probe(s): {len(results)} cached, {len(pending)} to run")
    if cache is not None:
        cache.parent.mkdir(parents=True, exist_ok=True)
    gate = asyncio.Semaphore(max(1, concurrency))
    stop: list[str] = []
    finished = 0

    async def one(scenario: Scenario, trial: int) -> None:
        nonlocal spent, finished
        async with gate:
            if stop:
                return
            if max_usd is not None and spent >= max_usd:
                stop.append(f"budget of ${max_usd:.2f} reached (spent ${spent:.4f})")
                return
            backend = make_backend(scenario)
            try:
                result = await probe_scenario(scenario, backend, trial=trial)
            except Exception as exc:  # noqa: BLE001 — one bad probe must not end a long run
                if isinstance(exc, BackendError) and exc.fatal:
                    stop.append(f"stopped: {exc}")
                    return
                result = ProbeResult(
                    scenario_id=scenario.id,
                    group="error",
                    backend=backend.name,
                    model=backend.model,
                    trial=trial,
                    error=f"{type(exc).__name__}: {exc}",
                )
            spent += cost(result)
            finished += 1
            if cache is not None:
                with cache.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(result.to_json(), ensure_ascii=False) + "\n")
            if result.error is None:
                results[probe_key(scenario.id, model, trial)] = result
            if result.error:
                verdict = f"error ({result.error[:80]})"
            elif result.declared is None:
                verdict = "no declaration"
            else:
                flows = ", ".join(f"{f['from']}->{f['to']}" for f in result.declared["flows"])
                verdict = f"{', '.join(result.declared['servers'])}" + (
                    f"; {flows}" if flows else ""
                )
            say(f"[{finished}/{len(pending)}] {scenario.id}: {verdict}")

    await asyncio.gather(*(one(s, t) for s, t in pending))
    fatal = [m for m in stop if m.startswith("stopped")]
    if fatal:
        raise BackendError(fatal[0], fatal=True)
    for message in stop:
        say(message)
    return [
        results[probe_key(s.id, model, t)] for s, t in jobs if probe_key(s.id, model, t) in results
    ]
