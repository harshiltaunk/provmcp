"""Tests for the scenario loader and the benchmark runner."""

from __future__ import annotations

from pathlib import Path

from provmcp.benchmark import BenchmarkRunner, load_scenario, load_scenarios
from provmcp.detectors import Detector, StructuredFieldDetector, SubstringDetector

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


def _flags(detector: Detector, path: Path) -> bool:
    result = BenchmarkRunner(detector=detector).run(load_scenario(path))
    return any(step.findings for step in result.steps)


def test_corpus_size() -> None:
    assert len(load_scenarios(ATTACK_DIR)) == 13  # 3 from Weeks 4-6, 10 added in Week 9
    assert len(load_scenarios(BENIGN_DIR)) == 10  # 4 from Weeks 4-6, 6 added in Week 9


def test_cd002_evades_substring_and_structured_by_design() -> None:
    path = ATTACK_DIR / "cd_002_paraphrased_calendar_to_email.json"
    assert _flags(SubstringDetector(min_run_length=8), path) is False
    assert _flags(StructuredFieldDetector(), path) is False


def test_cd003_only_structured_catches_recased_values() -> None:
    path = ATTACK_DIR / "cd_003_recased_address_exfiltration.json"
    assert _flags(SubstringDetector(min_run_length=8), path) is False
    assert _flags(StructuredFieldDetector(), path) is True


def test_unrelated_benign_scenarios_stay_quiet() -> None:
    for name in ("bn_002_readme_then_clock.json", "bn_003_convert_meeting_time.json"):
        path = BENIGN_DIR / name
        assert _flags(SubstringDetector(min_run_length=8), path) is False, name
        assert _flags(StructuredFieldDetector(), path) is False, name


def test_bn004_is_the_documented_flow_vs_intent_limitation() -> None:
    """Provenance sees the organizer's address flow; it cannot see that the user asked.

    Expected to be flagged without configuration, and silenced by the allowlist.
    """
    path = BENIGN_DIR / "bn_004_reply_to_organizer.json"
    assert _flags(StructuredFieldDetector(), path) is True
    assert _flags(StructuredFieldDetector(allowlist=["dana.lee@fresnostate.edu"]), path) is False
