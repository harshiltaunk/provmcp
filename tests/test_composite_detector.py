"""Tests for the composite detector's merge logic."""

from __future__ import annotations

from typing import Any

from provmcp.detectors.composite import CompositeDetector
from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore


class StubDetector:
    def __init__(self, name: str, findings: list[InfluenceFinding]) -> None:
        self.name = name
        self._findings = findings

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        return [
            InfluenceFinding(
                source_server_id=f.source_server_id,
                target_server_id=f.target_server_id,
                confidence=f.confidence,
                detector=self.name,
                excerpt=f.excerpt,
            )
            for f in self._findings
        ]


def _finding(src: str, dst: str, confidence: float) -> InfluenceFinding:
    return InfluenceFinding(
        source_server_id=src,
        target_server_id=dst,
        confidence=confidence,
        detector="stub",
    )


def test_merges_same_source_keeping_highest_confidence() -> None:
    comp = CompositeDetector(
        [
            StubDetector("substring", [_finding("calendar", "email", 0.55)]),
            StubDetector("embedding", [_finding("calendar", "email", 0.85)]),
        ]
    )
    out = comp.scan(store=ProvenanceStore.empty(), target_server_id="email", outbound_params={})
    assert len(out) == 1
    assert out[0].confidence == 0.85
    assert out[0].detector == "embedding+substring"


def test_distinct_sources_produce_distinct_findings() -> None:
    comp = CompositeDetector(
        [
            StubDetector("substring", [_finding("calendar", "email", 0.90)]),
            StubDetector("embedding", [_finding("filesystem", "email", 0.80)]),
        ]
    )
    out = comp.scan(store=ProvenanceStore.empty(), target_server_id="email", outbound_params={})
    sources = sorted(f.source_server_id for f in out)
    assert sources == ["calendar", "filesystem"]


def test_rejects_empty_detector_list() -> None:
    import pytest

    with pytest.raises(ValueError):
        CompositeDetector([])


def test_detector_order_does_not_affect_result() -> None:
    a = StubDetector("substring", [_finding("x", "y", 0.70)])
    b = StubDetector("embedding", [_finding("x", "y", 0.80)])
    ab = CompositeDetector([a, b]).scan(
        store=ProvenanceStore.empty(), target_server_id="y", outbound_params={}
    )
    ba = CompositeDetector([b, a]).scan(
        store=ProvenanceStore.empty(), target_server_id="y", outbound_params={}
    )
    assert ab[0].confidence == ba[0].confidence
    assert ab[0].detector == ba[0].detector
