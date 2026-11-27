"""Tests for the file-backed approval store and the JSONL audit log."""

from __future__ import annotations

from pathlib import Path

import pytest

from provmcp.approvals import ApprovalStore, fingerprint_call
from provmcp.audit import AuditLog


def _request(store: ApprovalStore, fp: str = "fp-1") -> str:
    return store.request(fingerprint=fp, target="email", tool="send", summary="test").id


def test_fingerprint_is_stable_and_argument_sensitive() -> None:
    a = fingerprint_call("email", {"name": "send", "arguments": {"to": "x", "cc": "y"}})
    b = fingerprint_call("email", {"name": "send", "arguments": {"cc": "y", "to": "x"}})
    c = fingerprint_call("email", {"name": "send", "arguments": {"to": "z"}})
    d = fingerprint_call("calendar", {"name": "send", "arguments": {"to": "x", "cc": "y"}})
    assert a == b
    assert len({a, c, d}) == 3


def test_file_store_is_shared_between_instances(tmp_path: Path) -> None:
    path = tmp_path / "approvals.json"
    proxy_side = ApprovalStore(path)
    user_side = ApprovalStore(path)
    approval_id = _request(proxy_side)
    assert [a.id for a in user_side.entries()] == [approval_id]
    user_side.decide(approval_id, approve=True)
    assert proxy_side.consume("fp-1") is True
    assert proxy_side.consume("fp-1") is False


def test_decide_rejects_unknown_and_already_decided(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "a.json")
    with pytest.raises(KeyError):
        store.decide("nope", approve=True)
    approval_id = _request(store)
    store.decide(approval_id, approve=False)
    with pytest.raises(ValueError):
        store.decide(approval_id, approve=True)


def test_denied_is_reported(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "a.json")
    store.decide(_request(store), approve=False)
    assert store.is_denied("fp-1") is True
    assert store.consume("fp-1") is False


def test_pending_and_approved_expire_after_ttl(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "a.json", ttl_seconds=0.000001)
    approval_id = _request(store)
    item = store.get(approval_id)
    assert item is not None and item.status == "expired"
    assert store.entries() == []
    assert [a.status for a in store.entries(include_decided=True)] == ["expired"]


def test_missing_file_means_empty(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "does-not-exist.json")
    assert store.entries() == []
    assert store.consume("anything") is False


def test_audit_log_appends_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    log = AuditLog(path)
    log.record({"event": "decision", "action": "warn"})
    log.record({"event": "decision", "action": "block"})
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    events = log.read()
    assert [e["action"] for e in events] == ["warn", "block"]
    assert all("ts" in e for e in events)
    assert [e["action"] for e in log.read(last=1)] == ["block"]


def test_audit_log_in_memory_when_no_path() -> None:
    log = AuditLog()
    log.record({"event": "x"})
    assert log.path is None
    assert len(log.read()) == 1
