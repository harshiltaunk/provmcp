"""Live inspection of outbound tool calls.

The Inspector is what turns ProvMCP from an offline benchmark into a defense.
For every `tools/call` the host sends, it:

1. runs the configured detector over the call's parameters against the
   provenance of everything other servers have returned so far;
2. keeps findings at or above the decision threshold;
3. chooses a policy per finding (the default, or a per-pair override) and
   maps each to an action with `policy.decide`;
4. takes the most severe action across findings (block > warn > pass);
5. for warn-and-confirm, consults the approval store: an approved identical
   call passes once, a denied one is blocked, anything else is held and a
   pending approval is created;
6. writes an audit event.

With a declared scope (Week 13, `provmcp.scope`) two checks come first: a
call to a server outside the scope is a violation of its own, handled by the
default policy; and a finding on a flow the scope declares is dropped, because
the request asked for that flow.

The Inspector is synchronous and does no I/O beyond the audit log and the
approval file, so it can be tested without any transport.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from provmcp.approvals import ApprovalStore, fingerprint_call
from provmcp.audit import AuditLog
from provmcp.detectors.base import Detector
from provmcp.policy import InfluenceFinding, PolicyAction, PolicyTemplate, decide
from provmcp.provenance import ProvenanceStore
from provmcp.scope import SCOPE_TOOL, Scope

SEVERITY: dict[PolicyAction, int] = {
    PolicyAction.PASS: 0,
    PolicyAction.WARN: 1,
    PolicyAction.BLOCK: 2,
}


class Decision(BaseModel):
    """What the proxy should do with one outbound call, and why."""

    action: PolicyAction
    template: PolicyTemplate
    target: str
    tool: str | None = None
    findings: list[InfluenceFinding] = Field(default_factory=list)
    reason: str = ""
    approval_id: str | None = None
    # Week 13. `scope` is "undeclared" (nothing declared yet) or "out_of_scope"
    # (the server is not in the declared scope). `suppressed` counts findings
    # dropped because the scope declares their flow.
    scope: str | None = None
    suppressed: int = 0


class Inspector:
    def __init__(
        self,
        *,
        detector: Detector,
        template: PolicyTemplate = PolicyTemplate.WARN_AND_CONFIRM,
        threshold: float = 0.6,
        pair_policies: dict[tuple[str, str], PolicyTemplate] | None = None,
        approvals: ApprovalStore | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.detector = detector
        self.template = template
        self.threshold = threshold
        self.pair_policies = dict(pair_policies or {})
        self.approvals = approvals if approvals is not None else ApprovalStore()
        self.audit = audit if audit is not None else AuditLog()

    def policy_for(self, source: str, target: str) -> PolicyTemplate:
        return self.pair_policies.get((source, target), self.template)

    def inspect(
        self,
        *,
        store: ProvenanceStore,
        target_server_id: str,
        params: dict[str, Any],
        scope: Scope | None = None,
    ) -> Decision:
        tool = params.get("name") if isinstance(params.get("name"), str) else None
        if scope is not None and not scope.allows_server(target_server_id):
            return self._out_of_scope(target_server_id, tool, params)
        findings = [
            f
            for f in self.detector.scan(
                store=store, target_server_id=target_server_id, outbound_params=params
            )
            if f.confidence >= self.threshold
        ]
        suppressed = 0
        if scope is not None and findings:
            kept = [
                f for f in findings if not scope.allows_flow(f.source_server_id, target_server_id)
            ]
            suppressed = len(findings) - len(kept)
            findings = kept

        if not findings:
            decision = Decision(
                action=PolicyAction.PASS,
                template=self.template,
                target=target_server_id,
                tool=tool,
                reason=(
                    "the declared scope allows this flow"
                    if suppressed
                    else "no cross-server influence detected"
                ),
                suppressed=suppressed,
            )
            if suppressed:
                self.audit.record({"event": "decision", **decision.model_dump(mode="json")})
            return decision

        action = PolicyAction.PASS
        template = self.template
        for finding in findings:
            pair_template = self.policy_for(finding.source_server_id, target_server_id)
            pair_action = decide(finding, pair_template, threshold=self.threshold)
            if SEVERITY[pair_action] > SEVERITY[action] or (
                SEVERITY[pair_action] == SEVERITY[action] and action is PolicyAction.PASS
            ):
                action, template = pair_action, pair_template

        decision = Decision(
            action=action,
            template=template,
            target=target_server_id,
            tool=tool,
            findings=findings,
            suppressed=suppressed,
        )

        if action is PolicyAction.BLOCK:
            decision.reason = "strict policy blocks cross-server influence"
        elif action is PolicyAction.WARN:
            self._resolve_warning(decision, params)
        else:
            decision.reason = "audit policy: logged, not enforced"

        self.audit.record({"event": "decision", **decision.model_dump(mode="json")})
        return decision

    def undeclared(self, target_server_id: str, params: dict[str, Any]) -> Decision:
        """The call arrived before any scope was declared: refuse it, whatever the policy.

        This is a protocol step, not a detection, so it is not written to the
        audit log as a decision.
        """
        tool = params.get("name") if isinstance(params.get("name"), str) else None
        return Decision(
            action=PolicyAction.BLOCK,
            template=self.template,
            target=target_server_id,
            tool=tool,
            reason="no scope declared yet",
            scope="undeclared",
        )

    def _out_of_scope(self, target: str, tool: str | None, params: dict[str, Any]) -> Decision:
        decision = Decision(
            action=PolicyAction.PASS,
            template=self.template,
            target=target,
            tool=tool,
            scope="out_of_scope",
        )
        if self.template is PolicyTemplate.STRICT:
            decision.action = PolicyAction.BLOCK
            decision.reason = "strict policy blocks a call outside the declared scope"
        elif self.template is PolicyTemplate.WARN_AND_CONFIRM:
            decision.action = PolicyAction.WARN
            self._resolve_warning(decision, params)
        else:
            decision.reason = "audit policy: out-of-scope call logged, not enforced"
        self.audit.record({"event": "decision", **decision.model_dump(mode="json")})
        return decision

    def _resolve_warning(self, decision: Decision, params: dict[str, Any]) -> None:
        fingerprint = fingerprint_call(decision.target, params)
        if self.approvals.consume(fingerprint):
            decision.action = PolicyAction.PASS
            decision.reason = "approved by the user for one use"
            return
        if self.approvals.is_denied(fingerprint):
            decision.action = PolicyAction.BLOCK
            decision.reason = "the user denied this exact call"
            return
        if decision.scope == "out_of_scope":
            summary = f"call to {decision.target} is outside the declared scope"
        else:
            sources = ", ".join(sorted({f.source_server_id for f in decision.findings}))
            summary = f"data from {sources} -> {decision.target}: {decision.findings[0].excerpt}"
        approval = self.approvals.request(
            fingerprint=fingerprint,
            target=decision.target,
            tool=decision.tool or "?",
            summary=summary[:200],
        )
        decision.approval_id = approval.id
        decision.reason = "held for user approval"


def held_result(decision: Decision) -> dict[str, Any]:
    """MCP tool result returned to the host instead of forwarding the call.

    Returned as a normal `tools/call` result with `isError: true`, which is how
    MCP reports tool-level failures, so the LLM reads the message and can relay
    it to the user. Decision details ride along under `_meta`.
    """
    sources = ", ".join(sorted({f.source_server_id for f in decision.findings})) or "another server"
    excerpt = decision.findings[0].excerpt if decision.findings else ""
    if decision.scope == "undeclared":
        text = (
            f"ProvMCP needs the scope of this request before any other tool. Call "
            f"`{SCOPE_TOOL}` with the servers the user's request needs and any data that "
            "must move between them, then make this call again. The call was not sent."
        )
    elif decision.scope == "out_of_scope" and decision.action is PolicyAction.BLOCK:
        text = (
            f"ProvMCP blocked this call to '{decision.target}': that server is outside the "
            "scope declared for this request. The call was not sent."
        )
    elif decision.scope == "out_of_scope":
        text = (
            f"ProvMCP is holding this call to '{decision.target}' for the user's approval: "
            "that server is outside the scope declared for this request. "
            f"Tell the user that approval {decision.approval_id} is waiting in ProvMCP. "
            "If they approve it there, the same call can be retried once."
        )
    elif decision.action is PolicyAction.BLOCK:
        text = (
            f"ProvMCP blocked this call to '{decision.target}'. Its arguments contain data "
            f"that came from '{sources}' ({excerpt}). Reason: {decision.reason}. "
            "The call was not sent."
        )
    else:
        text = (
            f"ProvMCP is holding this call to '{decision.target}' for the user's approval. "
            f"Its arguments contain data that came from '{sources}' ({excerpt}). "
            f"Tell the user that approval {decision.approval_id} is waiting in ProvMCP. "
            "If they approve it there, the same call can be retried once."
        )
    return {
        "content": [{"type": "text", "text": text}],
        "isError": True,
        "_meta": {"provmcp": decision.model_dump(mode="json")},
    }
