"""Tests for the live Inspector: findings + policy + approvals -> decision."""

from __future__ import annotations

from typing import Any

from provmcp.approvals import ApprovalStore
from provmcp.audit import AuditLog
from provmcp.inspector import Inspector, held_result
from provmcp.policy import InfluenceFinding, PolicyAction, PolicyTemplate
from provmcp.provenance import ProvenanceStore

PARAMS = {"name": "send", "arguments": {"to": "x@evil.example"}}


class StubDetector:
    name = "stub"

    def __init__(self, findings: list[tuple[str, float]]) -> None:
        self._findings = findings

    def scan(
        self, *, store: ProvenanceStore, target_server_id: str, outbound_params: Any
    ) -> list[InfluenceFinding]:
        return [
            InfluenceFinding(
                source_server_id=source,
                target_server_id=target_server_id,
                confidence=confidence,
                detector="stub",
                excerpt=f"email: x@evil.example (from {source})",
            )
            for source, confidence in self._findings
        ]


def _inspect(inspector: Inspector, params: dict[str, Any] = PARAMS) -> Any:
    return inspector.inspect(store=ProvenanceStore.empty(), target_server_id="email", params=params)


def test_no_findings_passes_and_is_not_audited() -> None:
    audit = AuditLog()
    decision = _inspect(Inspector(detector=StubDetector([]), audit=audit))
    assert decision.action is PolicyAction.PASS
    assert decision.findings == []
    assert audit.read() == []


def test_findings_below_threshold_are_ignored() -> None:
    decision = _inspect(Inspector(detector=StubDetector([("calendar", 0.4)]), threshold=0.6))
    assert decision.action is PolicyAction.PASS
    assert decision.findings == []


def test_strict_blocks() -> None:
    decision = _inspect(
        Inspector(detector=StubDetector([("calendar", 0.9)]), template=PolicyTemplate.STRICT)
    )
    assert decision.action is PolicyAction.BLOCK
    assert decision.template is PolicyTemplate.STRICT


def test_audit_policy_passes_but_logs() -> None:
    audit = AuditLog()
    decision = _inspect(
        Inspector(
            detector=StubDetector([("calendar", 0.9)]), template=PolicyTemplate.AUDIT, audit=audit
        )
    )
    assert decision.action is PolicyAction.PASS
    assert decision.template is PolicyTemplate.AUDIT
    events = audit.read()
    assert len(events) == 1
    assert events[0]["template"] == "audit"


def test_warn_creates_pending_approval() -> None:
    approvals = ApprovalStore()
    decision = _inspect(Inspector(detector=StubDetector([("calendar", 0.9)]), approvals=approvals))
    assert decision.action is PolicyAction.WARN
    assert decision.approval_id is not None
    pending = approvals.entries()
    assert [a.id for a in pending] == [decision.approval_id]
    assert pending[0].target == "email"
    assert pending[0].tool == "send"


def test_repeated_held_call_reuses_one_pending_approval() -> None:
    approvals = ApprovalStore()
    inspector = Inspector(detector=StubDetector([("calendar", 0.9)]), approvals=approvals)
    first = _inspect(inspector)
    second = _inspect(inspector)
    assert first.approval_id == second.approval_id
    assert len(approvals.entries()) == 1


def test_approved_call_passes_exactly_once() -> None:
    approvals = ApprovalStore()
    inspector = Inspector(detector=StubDetector([("calendar", 0.9)]), approvals=approvals)
    held = _inspect(inspector)
    approvals.decide(held.approval_id, approve=True)
    assert _inspect(inspector).action is PolicyAction.PASS
    again = _inspect(inspector)
    assert again.action is PolicyAction.WARN
    assert again.approval_id != held.approval_id


def test_approval_is_bound_to_the_exact_arguments() -> None:
    approvals = ApprovalStore()
    inspector = Inspector(detector=StubDetector([("calendar", 0.9)]), approvals=approvals)
    held = _inspect(inspector)
    approvals.decide(held.approval_id, approve=True)
    other = {"name": "send", "arguments": {"to": "x@evil.example", "bcc": "y@evil.example"}}
    assert _inspect(inspector, other).action is PolicyAction.WARN


def test_denied_call_is_blocked() -> None:
    approvals = ApprovalStore()
    inspector = Inspector(detector=StubDetector([("calendar", 0.9)]), approvals=approvals)
    held = _inspect(inspector)
    approvals.decide(held.approval_id, approve=False)
    decision = _inspect(inspector)
    assert decision.action is PolicyAction.BLOCK
    assert "denied" in decision.reason


def test_pair_policy_overrides_default() -> None:
    inspector = Inspector(
        detector=StubDetector([("calendar", 0.9)]),
        template=PolicyTemplate.AUDIT,
        pair_policies={("calendar", "email"): PolicyTemplate.STRICT},
    )
    assert _inspect(inspector).action is PolicyAction.BLOCK


def test_most_severe_finding_wins() -> None:
    inspector = Inspector(
        detector=StubDetector([("filesystem", 0.9), ("calendar", 0.9)]),
        template=PolicyTemplate.AUDIT,
        pair_policies={("calendar", "email"): PolicyTemplate.WARN_AND_CONFIRM},
    )
    decision = _inspect(inspector)
    assert decision.action is PolicyAction.WARN
    assert decision.template is PolicyTemplate.WARN_AND_CONFIRM


def test_held_result_is_an_mcp_tool_error() -> None:
    decision = _inspect(Inspector(detector=StubDetector([("calendar", 0.9)])))
    result = held_result(decision)
    assert result["isError"] is True
    assert result["content"][0]["type"] == "text"
    assert decision.approval_id in result["content"][0]["text"]
    assert result["_meta"]["provmcp"]["action"] == "warn"
