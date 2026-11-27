"""Tests for the substring detector."""

from __future__ import annotations

from provmcp.detectors.substring import SubstringDetector
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload


def _seed_store(items: list[tuple[str, object]]) -> ProvenanceStore:
    store = ProvenanceStore.empty()
    for server_id, content in items:
        store.record(TaggedPayload(content=content, tag=OriginTag(server_id=server_id)))
    return store


def test_detects_direct_propagation_across_servers() -> None:
    store = _seed_store([
        ("calendar", {"text": "Lunch at Blueberry-Cafe-1138 with team"}),
    ])
    det = SubstringDetector(min_run_length=8)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params={"body": "please book a table at Blueberry-Cafe-1138 for us"},
    )
    assert len(findings) == 1
    assert findings[0].source_server_id == "calendar"
    assert findings[0].target_server_id == "email"
    assert "Blueberry" in findings[0].excerpt
    assert 0.0 < findings[0].confidence < 1.0


def test_ignores_same_server_echo() -> None:
    store = _seed_store([
        ("email", {"text": "previously sent: urgent-reminder-xyz"}),
    ])
    det = SubstringDetector(min_run_length=6)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params={"body": "follow-up on urgent-reminder-xyz"},
    )
    assert findings == []


def test_ignores_short_runs() -> None:
    store = _seed_store([
        ("calendar", {"text": "The quick brown fox"}),
    ])
    det = SubstringDetector(min_run_length=10)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params={"body": "a quick note"},
    )
    assert findings == []


def test_longer_match_yields_higher_confidence() -> None:
    marker_short = "token-ABC-12345"
    marker_long = "token-ABC-12345-with-a-much-longer-tail-67890-end"
    det = SubstringDetector(min_run_length=8)

    store_short = _seed_store([("calendar", {"text": marker_short})])
    short_finding = det.scan(
        store=store_short,
        target_server_id="email",
        outbound_params={"body": marker_short},
    )[0]

    store_long = _seed_store([("calendar", {"text": marker_long})])
    long_finding = det.scan(
        store=store_long,
        target_server_id="email",
        outbound_params={"body": marker_long},
    )[0]

    assert long_finding.confidence > short_finding.confidence


def test_reports_once_per_source_server() -> None:
    store = _seed_store([
        ("calendar", {"text": "distinct-marker-ONE and distinct-marker-TWO"}),
    ])
    det = SubstringDetector(min_run_length=8)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params={"body": "see distinct-marker-ONE and also distinct-marker-TWO"},
    )
    assert len(findings) == 1
    assert findings[0].source_server_id == "calendar"
