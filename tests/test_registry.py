"""Tests for the server registry."""

from __future__ import annotations

import pytest

from provmcp.registry import ServerRecord, ServerRegistry, TrustClass


def _record(server_id: str, trust: TrustClass = TrustClass.LIMITED) -> ServerRecord:
    return ServerRecord(
        server_id=server_id,
        display_name=server_id.title(),
        endpoint=f"http://127.0.0.1/{server_id}",
        trust=trust,
    )


def test_registry_add_and_get() -> None:
    reg = ServerRegistry([_record("calendar"), _record("email")])
    assert len(reg) == 2
    assert reg.get("calendar").display_name == "Calendar"
    assert "email" in reg


def test_registry_rejects_duplicates() -> None:
    reg = ServerRegistry([_record("calendar")])
    with pytest.raises(ValueError):
        reg.add(_record("calendar"))


def test_registry_unknown_server_raises() -> None:
    reg = ServerRegistry()
    with pytest.raises(KeyError):
        reg.get("missing")


def test_trust_class_default_is_limited() -> None:
    record = _record("calendar")
    assert record.trust is TrustClass.LIMITED


def test_contains_rejects_non_string() -> None:
    reg = ServerRegistry([_record("calendar")])
    assert ("calendar" in reg) is True
    assert (42 in reg) is False  # type: ignore[operator]
