"""Common detector protocol.

Every detector takes a ProvenanceStore, a target server, and an outbound
parameter object, and returns a list of InfluenceFinding. Implementations
differ only in how they decide whether the outbound content "came from"
another server. The runner picks one or more detectors and aggregates
their findings.
"""

from __future__ import annotations

from typing import Any, Protocol

from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore


class Detector(Protocol):
    """Shape every detector in `provmcp.detectors` is expected to satisfy."""

    name: str

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]: ...
