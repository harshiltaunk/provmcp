"""Suite runs: selection, caching, budget, fatal errors, report."""

from __future__ import annotations

from pathlib import Path

import pytest

from provmcp.agent.backends import (
    Backend,
    BackendError,
    ScriptedBackend,
    ToolResult,
    ToolSpec,
    Turn,
)
from provmcp.agent.experiment import (
    KNOWN_PRICES,
    cost_usd,
    estimate_tokens,
    load_cache,
    render_report,
    run_suite,
    select_scenarios,
)
from provmcp.agent.runner import EpisodeResult
from provmcp.benchmark import Scenario, load_scenario
from provmcp.importers.injecagent import import_repo
from tests.test_live_enforcement import CD003, REPO

ATTACKS = REPO / "benchmarks" / "attacks"
FIXTURE = REPO / "tests" / "fixtures" / "injecagent_mini"


class CostlyBackend(Backend):
    """Answers at once, but reports a large token bill."""

    name = "costly"

    def __init__(self) -> None:
        super().__init__("costly-model")

    def begin(self, *, system: str, task: str, tools: list[ToolSpec]) -> None:
        pass

    async def step(self) -> Turn:
        return Turn(text="no", input_tokens=1_000_000, output_tokens=0)

    def add_results(self, results: list[ToolResult]) -> None:
        pass


class BrokenKeyBackend(CostlyBackend):
    async def step(self) -> Turn:
        raise BackendError("HTTP 401: invalid x-api-key", fatal=True)


def test_select_scenarios_samples_and_drops_same_server(tmp_path: Path) -> None:
    import_repo(FIXTURE, tmp_path, settings=["base"])
    chosen, notes = select_scenarios([tmp_path])
    assert [s.id for s in chosen] == ["ia-base-dh-0000", "ia-base-ds-0000"]
    assert any("same-server" in n for n in notes)

    with_same, _ = select_scenarios([tmp_path], include_same_server=True)
    assert len(with_same) == 3

    sampled, notes = select_scenarios([ATTACKS], limit=2, seed=7)
    again, _ = select_scenarios([ATTACKS], limit=2, seed=7)
    assert len(sampled) == 2 and [s.id for s in sampled] == [s.id for s in again]
    assert any("sampled 2" in n for n in notes)


async def test_cache_makes_reruns_free(tmp_path: Path) -> None:
    scenarios = [load_scenario(CD003)]
    cache = tmp_path / "cache.jsonl"
    messages: list[str] = []

    async def run(progress: list[str] | None = None) -> list[EpisodeResult]:
        return await run_suite(
            scenarios,
            ScriptedBackend.from_scenario,
            model="scripted",
            conditions=["audit", "strict"],
            workroot=tmp_path / "runs",
            cache=cache,
            progress=progress.append if progress is not None else None,
        )

    first = await run()
    second = await run(messages)
    assert len(first) == len(second) == 2
    assert "2 cached, 0 to run" in messages[0]
    assert len(load_cache(cache)) == 2
    assert [r.condition for r in second] == ["audit", "strict"]


async def test_budget_stops_the_run(tmp_path: Path) -> None:
    scenarios = [load_scenario(p) for p in sorted(ATTACKS.glob("*.json"))]
    messages: list[str] = []
    results = await run_suite(
        scenarios,
        lambda _s: CostlyBackend(),
        model="costly-model",
        conditions=["none"],
        workroot=tmp_path,
        concurrency=1,
        price_in=1.0,
        max_usd=1.5,
        progress=messages.append,
    )
    assert len(results) == 2  # $1 + $1 crosses the $1.50 cap; the third never starts
    assert any("budget" in m for m in messages)


async def test_fatal_backend_error_stops_everything(tmp_path: Path) -> None:
    with pytest.raises(BackendError):
        await run_suite(
            [load_scenario(CD003)],
            lambda _s: BrokenKeyBackend(),
            model="costly-model",
            conditions=["none"],
            workroot=tmp_path,
        )


def test_costs_and_prices() -> None:
    result = EpisodeResult(
        "x", "g", "none", "b", "m", 0, True, input_tokens=2_000_000, output_tokens=1_000_000
    )
    assert cost_usd(result, 0.10, 0.50) == pytest.approx(0.70)
    assert KNOWN_PRICES["claude-haiku-5-5"] == (0.10, 0.50)
    tokens_in, tokens_out = estimate_tokens(load_scenario(CD003), max_steps=8)
    assert tokens_in > 0 and tokens_out > 0


def test_report_has_attack_and_benign_tables() -> None:
    def ep(sid: str, group: str, cond: str, attack: bool, **kw: bool) -> EpisodeResult:
        return EpisodeResult(sid, group, cond, "scripted", "scripted", 0, attack, **kw)

    results = [
        ep(
            "cd-003",
            "provmcp-attacks",
            "audit",
            True,
            valid=True,
            attempted=True,
            succeeded=True,
            flagged_goal=True,
        ),
        ep(
            "cd-003",
            "provmcp-attacks",
            "strict",
            True,
            valid=True,
            attempted=True,
            flagged_goal=True,
            blocked_goal=True,
        ),
        ep(
            "bn-004",
            "provmcp-benign",
            "strict",
            False,
            valid=True,
            attempted=True,
            flagged_any=True,
            blocked_goal=True,
        ),
    ]
    report = render_report(results, title="Test", settings={"model": "scripted"})
    assert "| provmcp-attacks | audit | 1 | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% | 0.0% |" in report
    assert "| provmcp-attacks | strict | 1 | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |" in report
    assert "| provmcp-benign | strict | 1 | 0.0% | 100.0% | 100.0% |" in report
    assert "## Published baselines for reference" in report


def test_scenario_without_task_is_skipped(tmp_path: Path) -> None:
    bare = Scenario(id="x-1", title="t", servers=[], ground_truth="benign")
    (tmp_path / "x.json").write_text(bare.model_dump_json(), encoding="utf-8")
    chosen, notes = select_scenarios([tmp_path])
    assert chosen == [] and "without task/oracle" in notes[0]
