"""End-to-end: real subprocess MCP servers, real config, real wiring.

Each test writes a config pointing at `scripted_server.py` replaying a
benchmark scenario, builds the proxy exactly as `provmcp run` does, and drives
the scenario's trace through `Proxy.handle`. The email server records every
call it actually receives, so the tests can assert that a held or blocked
call never reached it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from provmcp.approvals import ApprovalStore
from provmcp.config import load_config
from provmcp.policy import PolicyAction
from provmcp.proxy import Proxy, RpcRequest
from provmcp.wiring import build_proxy

REPO = Path(__file__).parent.parent
SCRIPTED = REPO / "examples" / "dummy_server" / "scripted_server.py"
CD003 = REPO / "benchmarks" / "attacks" / "cd_003_recased_address_exfiltration.json"
BN001 = REPO / "benchmarks" / "benign" / "bn_001_independent_calls.json"


def _config(tmp: Path, scenario: Path, *, policy: str, pair: str = "") -> Path:
    def server(sid: str, extra: list[str]) -> str:
        cmd = [sys.executable, str(SCRIPTED), "--scenario", str(scenario), "--server", sid, *extra]
        return (
            f'[[servers]]\nid = "{sid}"\ndisplay_name = "{sid}"\n'
            f'transport = "stdio"\ncommand = {json.dumps(cmd)}\n'
        )

    body = (
        f'[proxy]\npolicy = "{policy}"\n'
        'audit_log = "audit.jsonl"\napprovals_file = "approvals.json"\n'
        f"{pair}\n"
        '[detection]\ndetectors = ["substring", "structured"]\n\n'
        + server("calendar", [])
        + server("email", ["--record", str(tmp / "email-received.jsonl")])
    )
    path = tmp / "provmcp.toml"
    path.write_text(body, encoding="utf-8")
    return path


def _received(tmp: Path) -> int:
    path = tmp / "email-received.jsonl"
    return len(path.read_text().splitlines()) if path.exists() else 0


async def _handshake(proxy: Proxy) -> None:
    for sid in ("calendar", "email"):
        await proxy.handle(
            RpcRequest(
                method="initialize",
                params={"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {}},
                request_id=0,
                target_server_id=sid,
            )
        )
        await proxy.handle(
            RpcRequest(
                method="notifications/initialized",
                params={},
                request_id=None,
                target_server_id=sid,
            )
        )


async def _replay(proxy: Proxy, scenario: Path) -> list[Any]:
    trace = json.loads(scenario.read_text())["trace"]
    responses = []
    for step in trace:
        responses.append(
            await proxy.handle(
                RpcRequest(
                    method=step["method"],
                    params=step["params"],
                    request_id=step["step"],
                    target_server_id=step["server"],
                )
            )
        )
    return responses


async def test_attack_is_held_and_never_reaches_email(tmp_path: Path) -> None:
    proxy = build_proxy(load_config(_config(tmp_path, CD003, policy="warn_and_confirm")))
    await proxy.router.start_all()
    try:
        await _handshake(proxy)
        _, email_step = await _replay(proxy, CD003)
    finally:
        await proxy.router.close_all()
    assert email_step.decision.action is PolicyAction.WARN
    assert email_step.result["isError"] is True
    assert _received(tmp_path) == 0
    audit = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert audit[-1]["action"] == "warn"
    assert audit[-1]["findings"][0]["source_server_id"] == "calendar"


async def test_out_of_band_approval_lets_the_call_through_once(tmp_path: Path) -> None:
    proxy = build_proxy(load_config(_config(tmp_path, CD003, policy="warn_and_confirm")))
    trace = json.loads(CD003.read_text())["trace"]
    send = RpcRequest(
        method="tools/call", params=trace[1]["params"], request_id=9, target_server_id="email"
    )
    await proxy.router.start_all()
    try:
        await _handshake(proxy)
        _, held = await _replay(proxy, CD003)
        # The user approves from a separate process: a fresh store on the same file.
        ApprovalStore(tmp_path / "approvals.json").decide(held.decision.approval_id, approve=True)
        allowed = await proxy.handle(send)
        held_again = await proxy.handle(send)
    finally:
        await proxy.router.close_all()
    assert allowed.result == {"status": "queued"}
    assert held_again.decision.action is PolicyAction.WARN
    assert _received(tmp_path) == 1


async def test_strict_pair_policy_blocks(tmp_path: Path) -> None:
    pair = '[[proxy.pair_policies]]\nsource = "calendar"\ntarget = "email"\npolicy = "strict"\n'
    proxy = build_proxy(load_config(_config(tmp_path, CD003, policy="audit", pair=pair)))
    await proxy.router.start_all()
    try:
        await _handshake(proxy)
        _, email_step = await _replay(proxy, CD003)
    finally:
        await proxy.router.close_all()
    assert email_step.decision.action is PolicyAction.BLOCK
    assert _received(tmp_path) == 0


async def test_benign_session_passes_untouched(tmp_path: Path) -> None:
    proxy = build_proxy(load_config(_config(tmp_path, BN001, policy="strict")))
    await proxy.router.start_all()
    try:
        await _handshake(proxy)
        _, email_step = await _replay(proxy, BN001)
    finally:
        await proxy.router.close_all()
    assert email_step.decision.action is PolicyAction.PASS
    assert email_step.result == {"status": "queued"}
    assert _received(tmp_path) == 1
