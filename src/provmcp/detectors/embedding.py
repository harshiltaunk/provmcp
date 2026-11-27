"""Embedding-based cross-origin propagation detector.

Catches the paraphrased case the substring detector misses: an LLM
rewords content it reads from server A before passing it to server B.
Byte-level matching does not fire; semantic similarity does.

Implementation: encode distinctive sentences from each source server's
responses and from the outbound parameters, then flag outbound sentences
whose cosine similarity to any source sentence exceeds `threshold`.

Model: `sentence-transformers/all-MiniLM-L6-v2` by default — 22 MB
(fits a $100 budget), runs on CPU in sub-second latency for short text,
MIT-licensed. The model is lazy-loaded so that importing this module
does not pull PyTorch into every ProvMCP command.

The detector degrades gracefully when the optional `sentence-transformers`
dependency is not installed: it emits a one-line warning and returns no
findings. The substring detector carries the suite in that case.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from provmcp.detectors.substring import _flatten_to_text
from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore, TaggedPayload

log = logging.getLogger(__name__)

# One module-level cache so repeated detector instances do not reload the
# model from disk. Access is keyed by model name.
_MODEL_CACHE: dict[str, Any] = {}


def _split_sentences(text: str, *, min_chars: int = 15) -> list[str]:
    """Rough sentence splitter.

    A dependency-free `re.split` on sentence terminators. Not perfect, but
    good enough for flow-metadata-style content. Sentences shorter than
    `min_chars` are dropped because they are usually noise (field labels,
    one-word values) that drive up false positives.
    """
    pieces = re.split(r"(?<=[.!?\n])\s+|\n+", text)
    cleaned: list[str] = []
    for piece in pieces:
        trimmed = piece.strip()
        if len(trimmed) >= min_chars:
            cleaned.append(trimmed)
    return cleaned


class EmbeddingDetector:
    """Flag outbound content that semantically matches another server's data."""

    name = "embedding"

    def __init__(
        self,
        *,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        threshold: float = 0.72,
        min_sentence_chars: int = 15,
    ) -> None:
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be in (0, 1]")
        self.model_name = model_name
        self.threshold = threshold
        self.min_sentence_chars = min_sentence_chars

    def _get_model(self) -> Any | None:
        """Load the sentence-transformers model once, cache it, or None."""
        if self.model_name in _MODEL_CACHE:
            return _MODEL_CACHE[self.model_name]
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            log.warning(
                "sentence-transformers not installed; "
                "embedding detector will return no findings. "
                "Install with: pip install 'provmcp[embed]'"
            )
            _MODEL_CACHE[self.model_name] = None
            return None
        model = SentenceTransformer(self.model_name)
        _MODEL_CACHE[self.model_name] = model
        return model

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        model = self._get_model()
        if model is None:
            return []

        outbound_text = _flatten_to_text(outbound_params)
        outbound_sentences = _split_sentences(outbound_text, min_chars=self.min_sentence_chars)
        if not outbound_sentences:
            return []

        other_payloads = [
            p
            for p in store._payloads.values()  # noqa: SLF001
            if p.tag.server_id != target_server_id
        ]
        if not other_payloads:
            return []

        # Encode outbound sentences once.
        outbound_embeds = model.encode(outbound_sentences, normalize_embeddings=True)

        # For each other server, find the best cross-origin similarity.
        best_by_source: dict[str, tuple[float, str, str]] = {}
        for payload in other_payloads:
            source_sentences = self._payload_sentences(payload)
            if not source_sentences:
                continue
            source_embeds = model.encode(source_sentences, normalize_embeddings=True)
            # Cosine similarity via dot product on unit vectors.
            sims = source_embeds @ outbound_embeds.T
            # Argmax across (source, outbound) pairs for the strongest link.
            i, j = self._argmax_2d(sims)
            score = float(sims[i][j])
            if score < self.threshold:
                continue
            source_id = payload.tag.server_id
            prior = best_by_source.get(source_id)
            if prior is None or score > prior[0]:
                best_by_source[source_id] = (
                    score,
                    source_sentences[i],
                    outbound_sentences[j],
                )

        findings: list[InfluenceFinding] = []
        for source_id, (score, source_sentence, outbound_sentence) in best_by_source.items():
            findings.append(
                InfluenceFinding(
                    source_server_id=source_id,
                    target_server_id=target_server_id,
                    confidence=min(0.99, score),
                    detector=self.name,
                    excerpt=f"source: {source_sentence[:60]} ↔ outbound: {outbound_sentence[:60]}",
                )
            )
        return findings

    def _payload_sentences(self, payload: TaggedPayload) -> list[str]:
        return _split_sentences(
            _flatten_to_text(payload.content),
            min_chars=self.min_sentence_chars,
        )

    @staticmethod
    def _argmax_2d(matrix: Any) -> tuple[int, int]:
        flat_idx = int(matrix.argmax())
        rows = matrix.shape[1]
        return flat_idx // rows, flat_idx % rows
