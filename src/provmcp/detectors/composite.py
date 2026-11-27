"""Composite detector — run several detectors and merge findings.

Per-source deduplication: if substring and embedding both flag the same
source → target pair, the composite keeps the finding with the highest
confidence and tags it with the detector names that agreed. This keeps
the per-alert report short while preserving which detectors fired.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from provmcp.detectors.base import Detector
from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore


class CompositeDetector:
    name = "composite"

    def __init__(self, detectors: Sequence[Detector]) -> None:
        if not detectors:
            raise ValueError("composite needs at least one detector")
        self.detectors = list(detectors)

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        best: dict[tuple[str, str], InfluenceFinding] = {}
        agreeing: dict[tuple[str, str], list[str]] = {}

        for detector in self.detectors:
            for finding in detector.scan(
                store=store,
                target_server_id=target_server_id,
                outbound_params=outbound_params,
            ):
                key = (finding.source_server_id, finding.target_server_id)
                agreeing.setdefault(key, []).append(finding.detector)
                prior = best.get(key)
                if prior is None or finding.confidence > prior.confidence:
                    best[key] = finding

        merged: list[InfluenceFinding] = []
        for key, finding in best.items():
            detectors_hit = sorted(set(agreeing[key]))
            merged.append(
                InfluenceFinding(
                    source_server_id=finding.source_server_id,
                    target_server_id=finding.target_server_id,
                    confidence=finding.confidence,
                    detector="+".join(detectors_hit),
                    excerpt=finding.excerpt,
                )
            )
        return merged
