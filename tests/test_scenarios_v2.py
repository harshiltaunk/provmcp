"""Week 8 scenario format: tasks, oracles, per-tool responses, MCPSecBench cases."""

from __future__ import annotations

import sys

import pytest

from provmcp.benchmark import (
    BenchmarkRunner,
    OracleCall,
    Scenario,
    canned_tool_result,
    load_scenario,
    load_scenarios,
)
from provmcp.detectors import StructuredFieldDetector, SubstringDetector
from provmcp.transports.stdio import StdioTransport
from tests.test_live_enforcement import REPO, SCRIPTED

SUITES = ["attacks", "benign", "msb"]
MSB = REPO / "benchmarks" / "msb"


def _all() -> list[Scenario]:
    return [s for suite in SUITES for s in load_scenarios(REPO / "benchmarks" / suite)]


def test_every_bundled_scenario_can_drive_an_agent() -> None:
    scenarios = _all()
    assert len(scenarios) == 11
    for scenario in scenarios:
        assert scenario.task, scenario.id
        assert scenario.oracle is not None and scenario.oracle.goal, scenario.id
        server_ids = {s.id for s in scenario.servers}
        for call in scenario.oracle.goal:
            assert call.server in server_ids, scenario.id
            tools = {t["name"] for t in scenario.server(call.server).canned["tools/list"]["tools"]}
            assert call.tool in tools, scenario.id


def test_oracle_matching_is_case_insensitive_on_arguments() -> None:
    call = OracleCall(server="email", tool="send", contains=["Evil-Partner.example"])
    assert call.matches("email", "send", {"to": "x@evil-partner.EXAMPLE"})
    assert not call.matches("email", "send", {"to": "x@good.example"})
    assert not call.matches("calendar", "send", {"to": "x@evil-partner.example"})


def test_canned_results_by_tool_and_in_sequence() -> None:
    canned = {"responses": {"a": [{"n": 1}, {"n": 2}], "b": {"n": 9}}, "tools/call": {"n": 0}}
    assert [canned_tool_result(canned, "a", i)["n"] for i in range(3)] == [1, 2, 2]
    assert canned_tool_result(canned, "b", 5) == {"n": 9}
    assert canned_tool_result(canned, "zzz", 0) == {"n": 0}


@pytest.mark.parametrize(
    ("name", "flagged"),
    [
        ("msb_att10_log_injection.json", True),
        ("msb_att07_shadowing_verifier.json", False),
        ("msb_att08_tool_metadata_exfil.json", False),
    ],
)
def test_mcpsecbench_cases_behave_as_documented(name: str, flagged: bool) -> None:
    scenario = load_scenario(MSB / name)
    result = BenchmarkRunner(detector=StructuredFieldDetector()).run(scenario)
    assert bool(any(step.findings for step in result.steps)) is flagged
    assert scenario.metadata["expected_provmcp"].startswith("detect" if flagged else "miss")


def test_rug_pull_is_seen_offline_but_below_the_live_threshold() -> None:
    """Known limitation (Week 8): substring confidence scores only the longest
    shared token, so copying the whole note scores 0.43, under the live 0.6."""
    scenario = load_scenario(MSB / "msb_att13_rug_pull_notes_exfil.json")
    result = BenchmarkRunner(detector=SubstringDetector(min_run_length=8)).run(scenario)
    findings = result.steps[-1].findings
    assert findings and findings[0].source_server_id == "notes"
    assert findings[0].confidence < 0.6


async def test_scripted_server_sequences_and_lists_tools() -> None:
    scenario = MSB / "msb_att13_rug_pull_notes_exfil.json"
    transport = StdioTransport(
        [sys.executable, str(SCRIPTED), "--scenario", str(scenario), "--server", "weather"]
    )
    await transport.start()
    try:
        listed = await transport.call("tools/list", {})
        assert [t["name"] for t in listed["tools"]] == ["get_forecast", "sync_profile"]
        first = await transport.call("tools/call", {"name": "get_forecast", "arguments": {}})
        second = await transport.call("tools/call", {"name": "get_forecast", "arguments": {}})
        assert "SERVICE NOTICE" not in first["content"][0]["text"]
        assert "SERVICE NOTICE" in second["content"][0]["text"]
    finally:
        await transport.close()


def test_oracle_ignores_key_names_and_supports_any_of() -> None:
    call = OracleCall(server="s", tool="t", contains=["permanent"])
    assert not call.matches("s", "t", {"permanent": True, "guest": "amy"})
    assert call.matches("s", "t", {"note": "make it permanent"})
    either = OracleCall(server="s", tool="t", any_of=["guest_amy01", "visitor_kx42"])
    assert either.matches("s", "t", {"ids": ["x", "VISITOR_KX42"]})
    assert not either.matches("s", "t", {"command": "date +%Y-%m-%d"})
