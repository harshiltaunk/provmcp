"""Substring-based cross-origin propagation detector.

The simplest of the three detectors: look for distinctive runs of characters
from a prior server response inside an outgoing tool call. Short tokens
(single words, common punctuation) are filtered out because they produce
false positives from coincidence. The gate is `min_run_length`.

This detector catches direct, unparaphrased propagation. Paraphrased or
restructured content is the job of the embedding detector in Week 5.
"""

from __future__ import annotations

import json
import re
from typing import Any

from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore, TaggedPayload


def _flatten_to_text(obj: Any) -> str:
    """Render arbitrary JSON-RPC content as a single searchable string."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (int, float, bool)) or obj is None:
        return str(obj)
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return repr(obj)


def _extract_runs(text: str, min_len: int) -> list[str]:
    """Split a payload into word-like runs long enough to be distinctive."""
    runs = re.findall(r"[A-Za-z0-9_.@:/\-]{" + str(min_len) + r",}", text)
    return [r for r in runs if len(r) >= min_len]


class SubstringDetector:
    """Flag outbound call parameters that reuse content from another server.

    Parameters
    ----------
    min_run_length:
        Minimum character run length to consider "distinctive". Short runs
        (e.g. "the", "GET") match too often to be useful.
    confidence_scale:
        Longer matched runs yield higher confidence. This caps the mapping
        so a very long match does not peg the score at 1.0 immediately.
    """

    name = "substring"

    def __init__(self, min_run_length: int = 8, confidence_scale: int = 32) -> None:
        if min_run_length < 2:
            raise ValueError("min_run_length must be >= 2")
        self.min_run_length = min_run_length
        self.confidence_scale = confidence_scale

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        """Return a finding per source server whose content shows up here."""
        target_text = _flatten_to_text(outbound_params)
        findings: list[InfluenceFinding] = []
        seen_by_source: dict[str, str] = {}

        for payload in self._iter_other_server_payloads(store, target_server_id):
            match = self._longest_shared_run(payload, target_text)
            if match is None:
                continue
            source = payload.tag.server_id
            # Keep the strongest match per source to avoid duplicate findings.
            if source not in seen_by_source or len(match) > len(seen_by_source[source]):
                seen_by_source[source] = match

        for source, match in seen_by_source.items():
            findings.append(
                InfluenceFinding(
                    source_server_id=source,
                    target_server_id=target_server_id,
                    confidence=self._score(match),
                    detector=self.name,
                    excerpt=match[:120],
                )
            )
        return findings

    def _iter_other_server_payloads(
        self,
        store: ProvenanceStore,
        target_server_id: str,
    ):
        for payload in store._payloads.values():  # noqa: SLF001 (internal collab)
            if payload.tag.server_id != target_server_id:
                yield payload

    def _longest_shared_run(self, payload: TaggedPayload, target_text: str) -> str | None:
        source_text = _flatten_to_text(payload.content)
        runs = _extract_runs(source_text, self.min_run_length)
        best: str | None = None
        for run in runs:
            if run in target_text and (best is None or len(run) > len(best)):
                best = run
        return best

    def _score(self, match: str) -> float:
        # Smooth linear-to-asymptote mapping from match length to [0, 1).
        length = len(match)
        return min(0.99, length / (length + self.confidence_scale))
