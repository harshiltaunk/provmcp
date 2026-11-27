"""Per-detector decision thresholds.

Detectors score on different scales: a 0.6 from the substring detector does
not mean what a 0.6 from the structured detector means. `GatedDetector`
drops a detector's findings below that detector's own threshold *before*
the composite merges them, so each detector can be calibrated separately
(Week 9). The Inspector then acts on whatever passes a gate.
"""

from __future__ import annotations

from typing import Any

from provmcp.detectors.base import Detector
from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore


class GatedDetector:
    """Pass through only the findings of `detector` that reach `threshold`."""

    def __init__(self, detector: Detector, threshold: float) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        self.detector = detector
        self.threshold = threshold
        self.name = detector.name

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        return [
            finding
            for finding in self.detector.scan(
                store=store, target_server_id=target_server_id, outbound_params=outbound_params
            )
            if finding.confidence >= self.threshold
        ]
