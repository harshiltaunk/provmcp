"""Tests for the policy engine."""

from __future__ import annotations

import pytest

from provmcp.policy import InfluenceFinding, PolicyAction, PolicyTemplate, decide


def _finding(confidence: float) -> InfluenceFinding:
    return InfluenceFinding(
        source_server_id="calendar",
        target_server_id="email",
        confidence=confidence,
        detector="substring",
    )


@pytest.mark.parametrize("template", list(PolicyTemplate))
def test_below_threshold_always_passes(template: PolicyTemplate) -> None:
    assert decide(_finding(0.2), template) is PolicyAction.PASS


def test_strict_blocks_above_threshold() -> None:
    assert decide(_finding(0.9), PolicyTemplate.STRICT) is PolicyAction.BLOCK


def test_warn_and_confirm_warns_above_threshold() -> None:
    assert decide(_finding(0.9), PolicyTemplate.WARN_AND_CONFIRM) is PolicyAction.WARN


def test_audit_passes_but_is_the_signal_to_log() -> None:
    assert decide(_finding(0.9), PolicyTemplate.AUDIT) is PolicyAction.PASS


def test_threshold_is_configurable() -> None:
    f = _finding(0.5)
    assert decide(f, PolicyTemplate.STRICT, threshold=0.4) is PolicyAction.BLOCK
    assert decide(f, PolicyTemplate.STRICT, threshold=0.6) is PolicyAction.PASS
