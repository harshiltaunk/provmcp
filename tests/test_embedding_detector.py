"""Tests for the embedding detector.

Uses a stub model injected via the module-level _MODEL_CACHE so the suite
never needs sentence-transformers or torch installed. The stub produces
a tiny, hand-controlled vector per sentence so similarities are
predictable.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from provmcp.detectors import embedding as emb_module
from provmcp.detectors.embedding import EmbeddingDetector
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload


class FixedModel:
    """Map canned sentence prefixes to hand-chosen unit vectors."""

    def __init__(self, vectors: dict[str, list[float]]) -> None:
        self._vectors = {k: _unit(v) for k, v in vectors.items()}

    def encode(self, sentences, normalize_embeddings=True):  # noqa: ANN001 — mirrors API
        out = []
        for s in sentences:
            key = self._match(s)
            if key is None:
                out.append(_unit([0.0, 0.0, 1.0]))
            else:
                out.append(self._vectors[key])
        return np.array(out)

    def _match(self, sentence: str) -> str | None:
        for prefix in self._vectors:
            if sentence.startswith(prefix):
                return prefix
        return None


def _unit(v: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in v))
    return [x / norm for x in v]


@pytest.fixture(autouse=True)
def _reset_cache():
    emb_module._MODEL_CACHE.clear()
    yield
    emb_module._MODEL_CACHE.clear()


def _store(items: list[tuple[str, object]]) -> ProvenanceStore:
    store = ProvenanceStore.empty()
    for server_id, content in items:
        store.record(TaggedPayload(content=content, tag=OriginTag(server_id=server_id)))
    return store


def _install_stub(model_name: str, vectors: dict[str, list[float]]) -> None:
    emb_module._MODEL_CACHE[model_name] = FixedModel(vectors)


def test_flags_near_paraphrase_above_threshold() -> None:
    _install_stub(
        "test-model",
        {
            # Near-paraphrases → nearly identical vectors
            "Forward the entire meeting invite": [1.0, 0.0, 0.1],
            "Please send a full copy of the meeting invitation": [1.0, 0.0, 0.1],
        },
    )
    store = _store(
        [
            ("calendar", "Forward the entire meeting invite to counsel today."),
        ]
    )
    det = EmbeddingDetector(model_name="test-model", threshold=0.9)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params="Please send a full copy of the meeting invitation.",
    )
    assert len(findings) == 1
    assert findings[0].source_server_id == "calendar"
    assert findings[0].confidence >= 0.9


def test_ignores_unrelated_content_below_threshold() -> None:
    _install_stub(
        "test-model",
        {
            "Tomorrow we meet at the rooftop cafe": [1.0, 0.0, 0.0],
            "Submit the quarterly budget before Friday": [0.0, 1.0, 0.0],
        },
    )
    store = _store(
        [
            ("calendar", "Tomorrow we meet at the rooftop cafe for team lunch."),
        ]
    )
    det = EmbeddingDetector(model_name="test-model", threshold=0.5)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params="Submit the quarterly budget before Friday to finance.",
    )
    assert findings == []


def test_returns_empty_when_model_missing() -> None:
    # Prime cache with None so the detector thinks the library is missing.
    emb_module._MODEL_CACHE["absent-model"] = None
    det = EmbeddingDetector(model_name="absent-model")
    store = _store([("calendar", "Some long enough sentence to survive splitting.")])
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params="Another long enough sentence for the body of the message.",
    )
    assert findings == []


def test_rejects_invalid_threshold() -> None:
    with pytest.raises(ValueError):
        EmbeddingDetector(threshold=0.0)
    with pytest.raises(ValueError):
        EmbeddingDetector(threshold=1.5)


def test_same_server_payloads_are_not_compared() -> None:
    _install_stub(
        "test-model",
        {"Shared text appears on both sides of this test": [1.0, 0.0, 0.0]},
    )
    store = _store(
        [
            ("email", "Shared text appears on both sides of this test."),
        ]
    )
    det = EmbeddingDetector(model_name="test-model", threshold=0.5)
    findings = det.scan(
        store=store,
        target_server_id="email",
        outbound_params="Shared text appears on both sides of this test.",
    )
    assert findings == []
