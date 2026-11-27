"""Tests for the provenance primitives."""

from __future__ import annotations

import pytest

from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload


def test_origin_tag_requires_server_id() -> None:
    with pytest.raises(ValueError):
        OriginTag(server_id="")


def test_origin_tag_assigns_unique_ids() -> None:
    a = OriginTag(server_id="calendar")
    b = OriginTag(server_id="calendar")
    assert a.tag_id != b.tag_id
    assert len(a.tag_id) == 16


def test_derive_links_parent_and_child() -> None:
    parent = OriginTag(server_id="email", tool_name="list_messages")
    child = parent.derive(tool_name="get_message")
    assert child.server_id == parent.server_id
    assert child.parent_tag_id == parent.tag_id
    assert child.tool_name == "get_message"


def test_tagged_payload_is_from() -> None:
    tag = OriginTag(server_id="calendar")
    payload = TaggedPayload(content={"event": "coffee"}, tag=tag)
    assert payload.is_from("calendar") is True
    assert payload.is_from("email") is False


def test_store_records_and_retrieves() -> None:
    store = ProvenanceStore.empty()
    tag = OriginTag(server_id="calendar")
    payload = TaggedPayload(content="hello", tag=tag)
    store.record(payload)
    assert len(store) == 1
    assert store.get(tag.tag_id) is payload


def test_store_filters_by_server() -> None:
    store = ProvenanceStore.empty()
    store.record(TaggedPayload(content="a", tag=OriginTag(server_id="calendar")))
    store.record(TaggedPayload(content="b", tag=OriginTag(server_id="email")))
    store.record(TaggedPayload(content="c", tag=OriginTag(server_id="calendar")))
    calendar_only = store.from_server("calendar")
    assert len(calendar_only) == 2
    assert all(p.is_from("calendar") for p in calendar_only)


def test_store_clear() -> None:
    store = ProvenanceStore.empty()
    store.record(TaggedPayload(content="x", tag=OriginTag(server_id="s")))
    store.clear()
    assert len(store) == 0
