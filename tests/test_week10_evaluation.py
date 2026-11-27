"""Week 10: statistics, strategies, evaluation levels, charts, cache keys."""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from provmcp.agent.backends import ScriptedBackend
from provmcp.agent.experiment import episode_key, load_cache, run_suite
from provmcp.agent.runner import detection_label
from provmcp.benchmark import load_scenarios
from provmcp.config import DetectionConfig
from provmcp.evaluation import (
    Rate,
    detection_and_false_alarms,
    end_to_end,
    offline_flags,
    real_traffic,
    strategies_from_calibration,
    wilson,
)
from provmcp.importers.injecagent import import_repo
from provmcp.svgchart import grouped_rate_bars
from tests.test_live_enforcement import CD003, REPO

CALIBRATION = {"substring_score": "longest", "thresholds": {"substring": 0.428, "structured": 0.85}}
BUNDLED = [s for d in ("attacks", "msb", "benign") for s in load_scenarios(REPO / "benchmarks" / d)]


def test_wilson_interval_matches_known_values() -> None:
    lo, hi = wilson(5, 10)
    assert round(lo, 3) == 0.237 and round(hi, 3) == 0.763
    assert wilson(0, 10)[0] == 0.0 and round(wilson(0, 10)[1], 3) == 0.278
    assert wilson(0, 0) == (0.0, 0.0)


def test_rate_formats_with_its_interval() -> None:
    assert str(Rate(12, 17)) == "12/17 (71%, 47-87)"
    assert str(Rate(0, 0)) == "-"
    assert Rate(1, 4).to_json()["rate"] == 0.25


def test_strategies_follow_the_calibration_file() -> None:
    names = [s.name for s in strategies_from_calibration(CALIBRATION, embedding=False)]
    assert names == [
        "Week 7 settings",
        "substring",
        "structured",
        "0.9.0 default (substring + structured)",
    ]
    with_embedding = {**CALIBRATION, "thresholds": {**CALIBRATION["thresholds"], "embedding": 0.5}}
    strategies = strategies_from_calibration(with_embedding, embedding=True)
    assert [s.name for s in strategies][-1] == "default + embedding"
    assert strategies[-1].detection.thresholds["embedding"] == 0.5
    assert strategies[0].detection.thresholds == {}  # Week 7: one global threshold


def test_corpus_scores_per_strategy() -> None:
    strategies = {s.name: s for s in strategies_from_calibration(CALIBRATION, embedding=False)}
    week7 = detection_and_false_alarms(
        offline_flags(strategies["Week 7 settings"], BUNDLED), BUNDLED
    )
    default = detection_and_false_alarms(
        offline_flags(strategies["0.9.0 default (substring + structured)"], BUNDLED), BUNDLED
    )
    assert (week7[0].k, week7[0].n, week7[1].k, week7[1].n) == (8, 17, 3, 10)
    assert (default[0].k, default[1].k) == (12, 3)


def test_chart_is_valid_svg_with_one_bar_per_rate() -> None:
    svg = grouped_rate_bars(
        "Title & more",
        "Sub",
        ["a", "b"],
        [("detected", [Rate(3, 4), Rate(0, 4)]), ("alarms", [Rate(1, 4), Rate(0, 0)])],
    )
    root = ET.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    assert root.tag == f"{ns}svg"
    assert root.find(f"{ns}title").text == "Title & more"  # type: ignore[union-attr]
    paths = root.findall(f".//{ns}path")
    assert len(paths) == 2  # 3/4 and 1/4; zero-height bars draw no path
    assert "no data" in svg


def test_chart_rejects_mismatched_series() -> None:
    with pytest.raises(ValueError):
        grouped_rate_bars("t", "s", ["a", "b"], [("x", [Rate(1, 2)])])


def test_detection_label_is_part_of_the_cache_key() -> None:
    default = detection_label("audit", DetectionConfig())
    legacy = detection_label("audit", DetectionConfig(thresholds={}, track_tool_metadata=False))
    assert default != legacy and "|" not in default
    assert "metadata:on" in default and "global:0.6" in legacy
    assert detection_label("none", DetectionConfig()) == "off"
    assert episode_key("s", "audit", "m", 0, default) != episode_key("s", "audit", "m", 0, legacy)


async def test_changed_settings_never_reuse_cached_episodes(tmp_path: Path) -> None:
    from provmcp.benchmark import load_scenario

    scenario = [load_scenario(CD003)]
    cache = tmp_path / "c.jsonl"
    messages: list[str] = []
    for detection in (None, DetectionConfig(thresholds={}, track_tool_metadata=False), None):
        await run_suite(
            scenario,
            ScriptedBackend.from_scenario,
            model="scripted",
            conditions=["strict"],
            workroot=tmp_path / "runs",
            cache=cache,
            detection=detection,
            progress=messages.append,
        )
    starts = [m for m in messages if "episode(s):" in m]
    assert starts == [
        "1 episode(s): 0 cached, 1 to run",
        "1 episode(s): 0 cached, 1 to run",  # new settings: not reused
        "1 episode(s): 1 cached, 0 to run",  # back to the first settings: reused
    ]
    assert len(load_cache(cache)) == 2


async def test_traffic_and_end_to_end_on_a_scripted_run(tmp_path: Path) -> None:
    results = await run_suite(
        BUNDLED,
        ScriptedBackend.from_scenario,
        model="scripted",
        conditions=["audit", "strict"],
        workroot=tmp_path,
        concurrency=4,
    )
    by_id = {s.id: s for s in BUNDLED}
    default = strategies_from_calibration(CALIBRATION, embedding=False)[-1]
    traffic = real_traffic(default, results, by_id)
    assert (traffic.detected.k, traffic.detected.n) == (12, 17)
    assert (traffic.false_alarms.k, traffic.false_alarms.n) == (3, 10)
    rows = {r.condition: r for r in end_to_end(results, by_id)}
    assert (rows["audit"].attack_success.k, rows["audit"].task_completion.k) == (17, 10)
    assert (rows["strict"].attack_success.k, rows["strict"].task_completion.k) == (6, 7)
    assert "metadata:on" in rows["strict"].detection


async def test_evaluation_script_writes_report_json_and_figures(tmp_path: Path) -> None:
    ia = tmp_path / "ia"
    import_repo(REPO / "tests" / "fixtures" / "injecagent_mini", ia, settings=["base"])
    cache = tmp_path / "c.jsonl"
    from provmcp.benchmark import load_scenario

    await run_suite(
        [load_scenario(CD003)],
        ScriptedBackend.from_scenario,
        model="scripted",
        conditions=["audit", "strict"],
        workroot=tmp_path / "runs",
        cache=cache,
    )
    out, js, figs = tmp_path / "e.md", tmp_path / "e.json", tmp_path / "figures"
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "evaluate_week10.py"),
            "--skip-embedding",
            "--injecagent",
            str(ia),
            "--run",
            f"scripted={cache}",
            "--out",
            str(out),
            "--json",
            str(js),
            "--figures",
            str(figs),
        ],
        check=True,
        capture_output=True,
        cwd=REPO,
    )
    report = out.read_text()
    assert "| 0.9.0 default (substring + structured) | 12/17 (71%, 47-87) |" in report
    assert "## 2. Compliant agent at scale" in report and "### scripted" in report
    summary = json.loads(js.read_text())
    assert summary["corpus"]["Week 7 settings"]["detected"]["k"] == 8
    assert {p.name for p in figs.iterdir()} == {
        "week10-corpus.svg",
        "week10-injecagent.svg",
        "week10-traffic-scripted.svg",
    }
