"""Tests for the scenario loader and the benchmark runner."""

from __future__ import annotations

from pathlib import Path

from provmcp.benchmark import BenchmarkRunner, load_scenario, load_scenarios

REPO_ROOT = Path(__file__).parent.parent
ATTACK_DIR = REPO_ROOT / "benchmarks" / "attacks"
BENIGN_DIR = REPO_ROOT / "benchmarks" / "benign"


def test_load_authored_attack_scenario() -> None:
    scenario = load_scenario(ATTACK_DIR / "cd_001_calendar_to_email.json")
    assert scenario.id == "cd-001-calendar-to-email"
    assert scenario.ground_truth == "cross_server_influence"
    assert {s.id for s in scenario.servers} == {"calendar", "email"}
    assert len(scenario.trace) == 2


def test_load_authored_benign_scenario() -> None:
    scenario = load_scenario(BENIGN_DIR / "bn_001_independent_calls.json")
    assert scenario.ground_truth == "benign"


def test_load_scenarios_sorts_by_id() -> None:
    attacks = load_scenarios(ATTACK_DIR)
    assert all(s.ground_truth == "cross_server_influence" for s in attacks)
    assert attacks == sorted(attacks, key=lambda s: s.id)


def test_runner_flags_authored_attack() -> None:
    runner = BenchmarkRunner()
    scenario = load_scenario(ATTACK_DIR / "cd_001_calendar_to_email.json")
    result = runner.run(scenario)
    assert result.true_positive() is True
    assert result.false_positive() is False
    # The flagging step must be step 2 (email send carrying calendar content).
    flagged_steps = [s for s in result.steps if s.findings]
    assert any(s.step == 2 for s in flagged_steps)
    assert all(f.source_server_id == "calendar" for step in flagged_steps for f in step.findings)


def test_runner_does_not_flag_benign_scenario() -> None:
    runner = BenchmarkRunner()
    scenario = load_scenario(BENIGN_DIR / "bn_001_independent_calls.json")
    result = runner.run(scenario)
    assert result.true_positive() is False
    assert result.false_positive() is False
