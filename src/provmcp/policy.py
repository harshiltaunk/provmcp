"""Policy engine: what to do when cross-origin influence is detected.

Three templates, matching the three deployment modes described in the proposal.
The engine is intentionally pure — no side effects — so it can be unit-tested
without spinning up the proxy.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class PolicyAction(StrEnum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


class PolicyTemplate(StrEnum):
    STRICT = "strict"
    WARN_AND_CONFIRM = "warn_and_confirm"
    AUDIT = "audit"


class InfluenceFinding(BaseModel):
    """What a detector reports when it sees cross-origin content."""

    source_server_id: str
    target_server_id: str
    confidence: float
    detector: str
    excerpt: str = ""


def decide(
    finding: InfluenceFinding,
    template: PolicyTemplate,
    *,
    threshold: float = 0.6,
) -> PolicyAction:
    """Map a finding plus template to an action.

    Below the confidence threshold every template treats the finding as noise
    and lets the call pass. At or above threshold, STRICT blocks,
    WARN_AND_CONFIRM asks the user, and AUDIT logs and lets the call through.
    """
    if finding.confidence < threshold:
        return PolicyAction.PASS
    if template is PolicyTemplate.STRICT:
        return PolicyAction.BLOCK
    if template is PolicyTemplate.WARN_AND_CONFIRM:
        return PolicyAction.WARN
    return PolicyAction.PASS  # AUDIT
