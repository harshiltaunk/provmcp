"""Structured-field cross-origin detector.

Catches the case the other two detectors handle poorly: a short, typed value
(an email address, a URL, a file path, an identifier) is read from server A
and reused as a parameter in a call to server B, possibly re-cased or
re-formatted on the way.

- The substring detector is case-sensitive and byte-exact, so
  `Exfil@Evil.Example` read from a calendar and written as
  `exfil@evil.example` in an email call slips through.
- The embedding detector compares sentence meaning, and a bare address
  carries almost no meaning, so it scores low.

This detector extracts typed values from every string leaf in a payload,
normalizes each value according to its type, and flags any normalized value
that appears in both a prior response from another server and the outbound
parameters.

Normalization rules:

    email    lowercase
    url      lowercase scheme and host, drop trailing slash, keep path case and query
    uuid     lowercase
    path     drop trailing slash
    ipv4     unchanged
    long_id  unchanged (six or more digits)

Each type carries a fixed confidence reflecting how unlikely a coincidental
match is. A UUID shared across servers is almost certainly a real flow; a
six-digit number might be a coincidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

from provmcp.policy import InfluenceFinding
from provmcp.provenance import ProvenanceStore

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>\\]+")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH = re.compile(r"(?<![A-Za-z0-9:/.])(?:~/|/)(?:[A-Za-z0-9._\-]+/)+[A-Za-z0-9._\-]+/?")
_LONG_ID = re.compile(r"\b\d{6,}\b")

_TRAILING_PUNCT = ".,;:!?)]}'\""

CONFIDENCE_BY_KIND: dict[str, float] = {
    "uuid": 0.95,
    "email": 0.90,
    "url": 0.85,
    "path": 0.80,
    "ipv4": 0.70,
    "long_id": 0.60,
}

Field = tuple[str, str]  # (kind, normalized value)


def iter_strings(obj: Any) -> Iterator[str]:
    """Yield every string leaf in a JSON-like structure (values only, not keys)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from iter_strings(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from iter_strings(item)


def _normalize_url(raw: str) -> str | None:
    cleaned = raw.rstrip(_TRAILING_PUNCT)
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    normalized = f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path.rstrip('/')}"
    if parts.query:
        normalized += f"?{parts.query}"
    return normalized


def extract_fields(obj: Any) -> set[Field]:
    """Return every typed, normalized value found anywhere in `obj`."""
    fields: set[Field] = set()
    for text in iter_strings(obj):
        for match in _URL.findall(text):
            url = _normalize_url(match)
            if url is not None:
                fields.add(("url", url))
        for match in _EMAIL.findall(text):
            fields.add(("email", match.lower()))
        for match in _UUID.findall(text):
            fields.add(("uuid", match.lower()))
        for match in _IPV4.findall(text):
            fields.add(("ipv4", match))
        for match in _PATH.findall(text):
            path = match.rstrip("/")
            if path not in ("", "~"):
                fields.add(("path", path))
        for match in _LONG_ID.findall(text):
            fields.add(("long_id", match))
    return fields


class StructuredFieldDetector:
    """Flag typed values that travel from one server into a call to another.

    Parameters
    ----------
    allowlist:
        Values that may cross servers freely, compared after normalization
        (lowercase emails and URLs). Typical entries are the user's own
        address and organization domain. This is the main lever for cutting
        false positives on legitimate, user-directed flows.
    kinds:
        Restrict detection to these field kinds. Defaults to every kind in
        `CONFIDENCE_BY_KIND`.
    """

    name = "structured"

    def __init__(
        self,
        *,
        allowlist: Iterable[str] = (),
        kinds: Iterable[str] | None = None,
    ) -> None:
        self.allowlist = {value.lower() for value in allowlist}
        selected = set(kinds) if kinds is not None else set(CONFIDENCE_BY_KIND)
        unknown = selected - set(CONFIDENCE_BY_KIND)
        if unknown:
            raise ValueError(f"unknown field kinds: {sorted(unknown)}")
        self.kinds = selected

    def scan(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        outbound_params: Any,
    ) -> list[InfluenceFinding]:
        outbound = self._filter(extract_fields(outbound_params))
        if not outbound:
            return []

        best_by_source: dict[str, Field] = {}
        for payload in store._payloads.values():  # noqa: SLF001
            source_id = payload.tag.server_id
            if source_id == target_server_id:
                continue
            shared = outbound & self._filter(extract_fields(payload.content))
            for field in shared:
                prior = best_by_source.get(source_id)
                if prior is None or _rank(field) > _rank(prior):
                    best_by_source[source_id] = field

        return [
            InfluenceFinding(
                source_server_id=source_id,
                target_server_id=target_server_id,
                confidence=CONFIDENCE_BY_KIND[kind],
                detector=self.name,
                excerpt=f"{kind}: {value}"[:120],
            )
            for source_id, (kind, value) in best_by_source.items()
        ]

    def _filter(self, fields: set[Field]) -> set[Field]:
        return {
            (kind, value)
            for kind, value in fields
            if kind in self.kinds and value.lower() not in self.allowlist
        }


def _rank(field: Field) -> tuple[float, int]:
    kind, value = field
    return CONFIDENCE_BY_KIND[kind], len(value)
