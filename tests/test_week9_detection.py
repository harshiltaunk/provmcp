"""Week 9 detection options: coverage scoring, value-only matching, gates, tool metadata."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from provmcp.benchmark import BenchmarkRunner, load_scenario, load_scenarios
from provmcp.config import DetectionConfig, ProvMcpConfig, ProxyConfig, ServerConfig
from provmcp.detectors import (
    CompositeDetector,
    GatedDetector,
    StructuredFieldDetector,
    SubstringDetector,
)
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.wiring import build_detector, build_inspector, build_proxy
from tests.test_live_enforcement import REPO
from tests.test_proxy_enforcement import _proxy, _req

MSB = REPO / "benchmarks" / "msb"
SPLITS = REPO / "benchmarks" / "splits"


def _store(server: str, content: Any) -> ProvenanceStore:
    store = ProvenanceStore.empty()
    store.record(TaggedPayload(content=content, tag=OriginTag(server_id=server)))
    return store


def test_coverage_scores_a_long_copy_higher_than_longest() -> None:
    note = "Destination Lisbon-Portugal confirmation HX-55120-LIS token tk_live_9QmZ4vR2xL7p"
    store = _store("notes", note)
    params = {"name": "sync", "arguments": {"text": note}}
    longest = SubstringDetector(score_mode="longest").scan(
        store=store, target_server_id="weather", outbound_params=params
    )
    coverage = SubstringDetector(score_mode="coverage").scan(
        store=store, target_server_id="weather", outbound_params=params
    )
    assert coverage[0].confidence > longest[0].confidence
    assert longest[0].excerpt == coverage[0].excerpt == "tk_live_9QmZ4vR2xL7p"


def test_key_names_never_count_as_copied_content() -> None:
    store = _store("inbox", "Please add the payment reference and the properties list")
    params = {"name": "pay", "arguments": {"reference": "X1", "properties": "none"}}
    assert (
        SubstringDetector().scan(store=store, target_server_id="pay", outbound_params=params) == []
    )


def test_unknown_score_mode_is_rejected() -> None:
    with pytest.raises(ValueError):
        SubstringDetector(score_mode="median")  # type: ignore[arg-type]


def test_gate_drops_findings_below_its_threshold() -> None:
    store = _store("calendar", "mail Exfil@Evil.Example now")
    params = {"name": "send", "arguments": {"to": "exfil@evil.example"}}
    structured = StructuredFieldDetector()
    assert GatedDetector(structured, 0.5).scan(
        store=store, target_server_id="email", outbound_params=params
    )
    assert not GatedDetector(structured, 0.99).scan(
        store=store, target_server_id="email", outbound_params=params
    )
    with pytest.raises(ValueError):
        GatedDetector(structured, 1.5)


def test_gates_apply_per_detector_before_the_composite_merges() -> None:
    store = _store("calendar", "mail Exfil@Evil.Example now")
    params = {"name": "send", "arguments": {"to": "exfil@evil.example"}}
    composite = CompositeDetector(
        [GatedDetector(SubstringDetector(), 0.99), GatedDetector(StructuredFieldDetector(), 0.5)]
    )
    findings = composite.scan(store=store, target_server_id="email", outbound_params=params)
    assert [f.detector for f in findings] == ["structured"]


def test_defaults_are_the_week9_calibration() -> None:
    detection = DetectionConfig()
    saved = json.loads((REPO / "docs" / "results" / "calibration-week9.json").read_text())
    assert detection.thresholds == {
        "substring": saved["thresholds"]["substring"],
        "structured": saved["thresholds"]["structured"],
    }
    assert detection.substring_score == saved["substring_score"] == "longest"
    assert detection.track_tool_metadata is True
    assert detection.detectors == ["substring", "structured"]  # embedding stays opt-in


def test_thresholds_are_validated() -> None:
    with pytest.raises(ValueError):
        DetectionConfig(thresholds={"substring": 1.4})
    with pytest.raises(ValueError):
        DetectionConfig.model_validate({"thresholds": {"telepathy": 0.5}})


def _config(detection: DetectionConfig) -> ProvMcpConfig:
    server = ServerConfig(id="a", display_name="A", command=[sys.executable, "-c", "pass"])
    return ProvMcpConfig(
        proxy=ProxyConfig(detector_threshold=0.6), detection=detection, servers=[server]
    )


def test_wiring_gates_each_detector_and_lets_the_gates_decide() -> None:
    config = _config(DetectionConfig(thresholds={"substring": 0.43}, substring_score="coverage"))
    detector = build_detector(config)
    assert isinstance(detector, CompositeDetector)
    gates = detector.detectors
    assert all(isinstance(g, GatedDetector) for g in gates)
    assert [g.threshold for g in gates] == [0.43, 0.6]  # structured falls back to [proxy]
    assert gates[0].detector.score_mode == "coverage"  # type: ignore[attr-defined]
    inspector = build_inspector(config)
    assert inspector is not None and inspector.threshold == 0.0


def test_empty_thresholds_restore_the_week7_global_threshold() -> None:
    legacy = DetectionConfig(thresholds={}, track_tool_metadata=False)
    inspector = build_inspector(_config(legacy))
    assert inspector is not None and inspector.threshold == 0.6
    assert not any(isinstance(d, GatedDetector) for d in inspector.detector.detectors)  # type: ignore[attr-defined]
    assert build_proxy(_config(legacy)).track_tool_metadata is False
    assert build_proxy(_config(DetectionConfig())).track_tool_metadata is True


async def test_proxy_records_tools_list_only_when_tracking() -> None:
    for track in (False, True):
        proxy, _, _ = _proxy()
        proxy.track_tool_metadata = track
        await proxy.handle(_req("calendar", "tools/list", {}))
        assert len(proxy.store) == (1 if track else 0)


def test_tool_metadata_tracking_catches_att08_offline() -> None:
    scenario = load_scenario(MSB / "msb_att08_tool_metadata_exfil.json")
    structured = StructuredFieldDetector()
    plain = BenchmarkRunner(detector=structured).run(scenario)
    tracked = BenchmarkRunner(detector=structured, track_tool_metadata=True).run(scenario)
    assert not any(step.findings for step in plain.steps)
    finding = tracked.steps[-1].findings[0]
    assert finding.source_server_id == "bank" and finding.confidence >= 0.85


def test_calibrated_gate_catches_the_rug_pull() -> None:
    scenario = load_scenario(MSB / "msb_att13_rug_pull_notes_exfil.json")
    gated = GatedDetector(SubstringDetector(), 0.428)
    result = BenchmarkRunner(detector=gated, track_tool_metadata=True).run(scenario)
    assert result.steps[-1].findings


def test_metadata_tracking_adds_no_alarm_to_clean_benign_scenarios() -> None:
    detector = CompositeDetector([SubstringDetector(), StructuredFieldDetector()])
    for scenario in load_scenarios(REPO / "benchmarks" / "benign"):
        if scenario.metadata.get("expected_provmcp") != "clean":
            continue
        result = BenchmarkRunner(detector=detector, track_tool_metadata=True).run(scenario)
        assert not any(step.findings for step in result.steps), scenario.id


def test_week9_split_covers_every_scenario_once() -> None:
    split = json.loads((SPLITS / "week9.json").read_text())
    ids = {
        s.id for d in ("attacks", "msb", "benign") for s in load_scenarios(REPO / "benchmarks" / d)
    }
    cal, held = set(split["calibration"]), set(split["held_out"])
    assert cal.isdisjoint(held) and cal | held == ids
    week6 = json.loads((SPLITS / "week6.json").read_text())["all"]
    assert len(week6) == 7 and set(week6) <= ids


def test_new_scenarios_document_technique_and_expectation() -> None:
    added = [
        s
        for d in ("attacks", "benign")
        for s in load_scenarios(REPO / "benchmarks" / d)
        if s.metadata.get("added") == "week 9"
    ]
    assert len(added) == 16
    attacks = [s for s in added if s.is_attack]
    assert len(attacks) == 10
    assert len({s.metadata["technique"] for s in attacks}) == 10
    assert all("expected_provmcp" in s.metadata for s in added)


def test_scenario_files_are_valid_json_with_traces() -> None:
    for d in ("attacks", "benign"):
        for path in sorted((REPO / "benchmarks" / d).glob("*.json")):
            data = json.loads(path.read_text())
            assert data["trace"], path.name


def test_embedding_keeps_its_week5_text_flattening() -> None:
    """Week 6 results must reproduce: embedding inputs may not follow substring's changes."""
    from provmcp.detectors import embedding, substring

    content = {"to": "a@b.example", "body": "hello there"}
    assert embedding._flatten_to_text(content) == json.dumps(content, sort_keys=True)
    assert substring._flatten_to_text(content) == "a@b.example\nhello there"
    assert embedding._flatten_to_text is not substring._flatten_to_text
