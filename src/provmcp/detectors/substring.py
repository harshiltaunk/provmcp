"""Substring-based cross-origin propagation detector.

The simplest of the three detectors: look for distinctive runs of characters
from a prior server response inside an outgoing tool call. Short tokens
(single words, common punctuation) are filtered out because they produce
false positives from coincidence. The gate is `min_run_length`.

This detector catches direct, unparaphrased propagation. Paraphrased or
restructured content is the job of the embedding detector in Week 5.

Scoring (`score_mode`):

- `longest` (Weeks 4-8): only the longest shared run counts,
  `len / (len + scale)`. A whole paragraph copied word for word scores no
  higher than its longest word, so verbatim copies of prose stay below a
  0.6 threshold.
- `coverage` (Week 9): the total length of all distinct shared runs from one
  source server counts, `covered / (covered + scale)`. Copying more distinctive
  content from a server raises the score.

With `canonicalize=True` (Week 12, opt-in) both sides are compared in their
canonical views (`provmcp.detectors.canonical`): case-insensitive, with
encodings decoded, look-alike and invisible characters normalized, and, on
the outbound side, separators squashed out.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any, Literal

from provmcp.detectors import canonical
from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore, TaggedPayload

ScoreMode = Literal["longest", "coverage"]


def _flatten_to_text(obj: Any) -> str:
    """Render JSON-RPC content as one searchable string of its *values*.

    Key names are left out (Week 9): a schema key such as `reference` or
    `properties` must not count as content copied from another server.
    Strings, numbers and booleans are joined with newlines, so runs never
    span two values.
    """
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return "\n".join(_flatten_to_text(value) for value in obj.values())
    if isinstance(obj, (list, tuple)):
        return "\n".join(_flatten_to_text(item) for item in obj)
    if isinstance(obj, (int, float, bool)) or obj is None:
        return "" if obj is None else str(obj)
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
    canonicalize:
        Compare canonical views of both sides instead of the raw text.
    """

    name = "substring"

    def __init__(
        self,
        min_run_length: int = 8,
        confidence_scale: int = 32,
        score_mode: ScoreMode = "longest",
        *,
        canonicalize: bool = False,
    ) -> None:
        if min_run_length < 2:
            raise ValueError("min_run_length must be >= 2")
        if score_mode not in ("longest", "coverage"):
            raise ValueError(f"unknown score_mode {score_mode!r}")
        self.min_run_length = min_run_length
        self.confidence_scale = confidence_scale
        self.score_mode: ScoreMode = score_mode
        self.canonicalize = canonicalize

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        """Return a finding per source server whose content shows up here."""
        target_text = _flatten_to_text(outbound_params)
        if self.canonicalize:
            target_text = "\n".join(canonical.views(target_text, squashed=True))
        findings: list[InfluenceFinding] = []
        runs_by_source: dict[str, set[str]] = {}

        for payload in self._iter_other_server_payloads(store, target_server_id):
            shared = self._shared_runs(payload, target_text, store)
            if shared:
                runs_by_source.setdefault(payload.tag.server_id, set()).update(shared)

        for source, runs in runs_by_source.items():
            longest = max(runs, key=lambda r: (len(r), r))
            if self.score_mode == "coverage":
                confidence = self._score_length(sum(len(r) for r in runs))
            else:
                confidence = self._score_length(len(longest))
            findings.append(
                InfluenceFinding(
                    source_server_id=source,
                    target_server_id=target_server_id,
                    confidence=confidence,
                    detector=self.name,
                    excerpt=longest[:120],
                )
            )
        return findings

    def _iter_other_server_payloads(
        self,
        store: ProvenanceStore,
        target_server_id: str,
    ) -> Iterator[TaggedPayload]:
        for payload in store.payloads():
            if payload.tag.server_id != target_server_id:
                yield payload

    def _shared_runs(
        self, payload: TaggedPayload, target_text: str, store: ProvenanceStore | None = None
    ) -> set[str]:
        def runs() -> frozenset[str]:
            text = _flatten_to_text(payload.content)
            if self.canonicalize:
                text = "\n".join(canonical.views(text))
            return frozenset(_extract_runs(text, self.min_run_length))

        key = f"substring:{'canon-' if self.canonicalize else ''}runs:{self.min_run_length}"
        source_runs = store.derived(payload.tag.tag_id, key, runs) if store is not None else runs()
        return {run for run in source_runs if run in target_text}

    def _longest_shared_run(self, payload: TaggedPayload, target_text: str) -> str | None:
        shared = self._shared_runs(payload, target_text)
        return max(shared, key=lambda r: (len(r), r)) if shared else None

    def _score_length(self, length: int) -> float:
        # Smooth linear-to-asymptote mapping from matched length to [0, 1).
        return min(0.99, length / (length + self.confidence_scale))

    def _score(self, match: str) -> float:
        return self._score_length(len(match))
