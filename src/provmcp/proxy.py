"""Transparent JSON-RPC proxy with live inspection.

Request flow for one host message:

1. Notifications (method `notifications/...`, no id) are forwarded with
   `Transport.notify` and produce no response.
2. If an Inspector is attached and the method is `tools/call`, the call is
   inspected first. A held or blocked call is never forwarded. The host
   receives an MCP tool result with `isError: true` explaining why.
3. Otherwise the request is forwarded to the backing server.
4. Results of content-bearing methods (`tools/call`, `resources/read`,
   `prompts/get`) are tagged with their origin and recorded in the provenance
   store, which later inspections compare against. With
   `track_tool_metadata`, `tools/list` results (tool names, descriptions and
   schemas) are recorded too, because a server can plant instructions in its
   tool descriptions, and another server can try to collect them (Week 9).

With a `ScopeGuard` (Week 13) the proxy also answers for one virtual server,
`provmcp`, whose only tool is `declare_scope`. Tool calls to real servers are
refused until a scope is declared, the declared scope is passed to the
Inspector, and the scope locks when the first result is delivered.

The Router owns one Transport per connected server, keyed by server_id.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from provmcp.approvals import fingerprint_call
from provmcp.inspector import Decision, Inspector, held_result
from provmcp.policy import PolicyAction, PolicyTemplate
from provmcp.provenance import OriginTag, ProvenanceStore, TaggedPayload
from provmcp.registry import ServerRegistry
from provmcp.scope import (
    SCOPE_SERVER_ID,
    SCOPE_TOOL,
    Scope,
    ScopeError,
    ScopeGuard,
    ScopeLockedError,
)
from provmcp.transports import Transport

log = logging.getLogger(__name__)

# Methods whose results carry server-provided content worth tracking.
RECORDED_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})


@dataclass
class RpcRequest:
    """A minimal JSON-RPC 2.0 request envelope the host gives us."""

    method: str
    params: dict[str, Any]
    request_id: str | int | None
    target_server_id: str

    @property
    def is_notification(self) -> bool:
        return self.request_id is None and self.method.startswith("notifications/")


@dataclass
class RpcResponse:
    """A minimal JSON-RPC 2.0 response envelope we return to the host."""

    result: Any
    request_id: str | int | None
    decision: Decision | None = None


class Router:
    """Owns one Transport per server_id and dispatches calls."""

    def __init__(self) -> None:
        self._transports: dict[str, Transport] = {}

    def register(self, server_id: str, transport: Transport) -> None:
        if server_id in self._transports:
            raise ValueError(f"transport already registered for {server_id!r}")
        self._transports[server_id] = transport

    def get(self, server_id: str) -> Transport:
        if server_id not in self._transports:
            raise KeyError(f"no transport for {server_id!r}")
        return self._transports[server_id]

    async def start_all(self) -> None:
        if not self._transports:
            return
        await asyncio.gather(*(t.start() for t in self._transports.values()))

    async def close_all(self) -> None:
        for transport in self._transports.values():
            try:
                await transport.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                log.exception("transport close failed")

    def server_ids(self) -> list[str]:
        return list(self._transports.keys())


class Proxy:
    """Routes host calls, inspects tool calls, tags responses, records provenance."""

    def __init__(
        self,
        *,
        registry: ServerRegistry,
        store: ProvenanceStore,
        router: Router,
        inspector: Inspector | None = None,
        track_tool_metadata: bool = False,
        scope: ScopeGuard | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        self.router = router
        self.inspector = inspector
        self.track_tool_metadata = track_tool_metadata
        # Scope is enforced through the Inspector, so it needs one.
        self.scope = scope if inspector is not None else None

    def serves(self, server_id: str) -> bool:
        """True for a connected server, and for the virtual scope server when scope is on."""
        return server_id in self.registry or (
            self.scope is not None and server_id == SCOPE_SERVER_ID
        )

    def _handle_scope_server(self, request: RpcRequest) -> RpcResponse:
        """Answer for the virtual `provmcp` server. Nothing is forwarded."""
        assert self.scope is not None
        if request.is_notification:
            return RpcResponse(result=None, request_id=None)
        result: Any
        if request.method == "initialize":
            self.scope.reset()  # a new host session starts with no scope
            result = {
                "protocolVersion": request.params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "provmcp-scope", "version": "0"},
            }
        elif request.method == "tools/list":
            result = {"tools": [self.scope.tool()]}
        elif request.method == "tools/call":
            result = self._declare(request.params)
        else:
            result = {}
        return RpcResponse(result=result, request_id=request.request_id)

    def _declare(self, params: dict[str, Any]) -> dict[str, Any]:
        assert self.scope is not None and self.inspector is not None
        if params.get("name") != SCOPE_TOOL:
            text = f"Unknown tool {params.get('name')!r}. This server only has `{SCOPE_TOOL}`."
            return {"content": [{"type": "text", "text": text}], "isError": True}
        approved = False
        try:
            scope = self.scope.declare(params.get("arguments") or {})
        except ScopeLockedError as exc:
            # A different scope after content was read. Under warn-and-confirm the user
            # can allow that exact change out of band; otherwise it is refused.
            held = self._confirm_change(exc.wanted)
            if held is not None:
                return {"content": [{"type": "text", "text": held}], "isError": True}
            scope = self.scope.declare(exc.wanted.to_json(), approved=True)
            approved = True
        except ScopeError as exc:
            self.inspector.audit.record({"event": "scope_rejected", "reason": str(exc)})
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        self.inspector.audit.record(
            {
                "event": "scope_declared",
                "source": self.scope.source,
                "after_content": self.scope.early_content or self.scope.locked,
                "approved_by_user": approved,
                **scope.to_json(),
            }
        )
        text = f"Scope recorded ({scope.describe()}). Calls outside it will be refused."
        return {
            "content": [{"type": "text", "text": text}],
            "isError": False,
            "_meta": {"provmcp": {"scope": scope.to_json()}},
        }

    def _confirm_change(self, wanted: Scope) -> str | None:
        """Decide a declaration that would change a locked scope.

        Returns the refusal shown to the agent, or None if the user approved
        this exact scope (the approval is then used up).
        """
        assert self.scope is not None and self.inspector is not None
        current = self.scope.scope.describe() if self.scope.scope is not None else "none"
        refusal = (
            "The scope cannot be changed after a tool result has been read. "
            f"It stays as declared ({current})."
        )
        event: dict[str, Any] = {"event": "scope_rejected", "wanted": wanted.to_json()}
        if self.inspector.template is not PolicyTemplate.WARN_AND_CONFIRM:
            text = f"{refusal} If the user's request needs more, tell the user."
            self.inspector.audit.record({**event, "reason": "locked"})
            return text
        approvals = self.inspector.approvals
        call = {"name": SCOPE_TOOL, "arguments": wanted.to_json()}
        fingerprint = fingerprint_call(SCOPE_SERVER_ID, call)
        if approvals.consume(fingerprint):
            return None
        if approvals.is_denied(fingerprint):
            self.inspector.audit.record({**event, "reason": "denied by the user"})
            return f"{refusal} The user denied this change."
        approval = approvals.request(
            fingerprint=fingerprint,
            target=SCOPE_SERVER_ID,
            tool=SCOPE_TOOL,
            summary=f"change the scope to {wanted.describe()}"[:200],
        )
        self.inspector.audit.record(
            {**event, "reason": "held for user approval", "approval_id": approval.id}
        )
        return (
            f"{refusal} Changing it needs the user's approval. Tell the user that approval "
            f"{approval.id} is waiting in ProvMCP. If they approve it there, call "
            f"`{SCOPE_TOOL}` again with the same arguments."
        )

    async def handle(self, request: RpcRequest) -> RpcResponse:
        if self.scope is not None and request.target_server_id == SCOPE_SERVER_ID:
            return self._handle_scope_server(request)
        record = self.registry.get(request.target_server_id)
        transport = self.router.get(request.target_server_id)

        if request.is_notification:
            await transport.notify(request.method, request.params)
            return RpcResponse(result=None, request_id=None)

        decision: Decision | None = None
        if self.inspector is not None and request.method == "tools/call":
            if self.scope is not None and self.scope.scope is None:
                self.scope.nudges += 1
                decision = self.inspector.undeclared(record.server_id, request.params)
            else:
                decision = self.inspector.inspect(
                    store=self.store,
                    target_server_id=record.server_id,
                    params=request.params,
                    scope=self.scope.effective() if self.scope is not None else None,
                )
            if decision.action is not PolicyAction.PASS:
                # A call before any declaration is a protocol step, not an alarm.
                level = logging.INFO if decision.scope == "undeclared" else logging.WARNING
                log.log(
                    level,
                    "%s call to %s: %s",
                    decision.action.value,
                    record.server_id,
                    decision.reason,
                )
                return RpcResponse(
                    result=held_result(decision),
                    request_id=request.request_id,
                    decision=decision,
                )

        log.debug("forwarding %s to %s", request.method, record.server_id)
        raw_result = await transport.call(request.method, request.params)

        if request.method in RECORDED_METHODS or (
            self.track_tool_metadata and request.method == "tools/list"
        ):
            tag = OriginTag(server_id=record.server_id, tool_name=request.method)
            self.store.record(TaggedPayload(content=raw_result, tag=tag))
        if self.scope is not None and request.method in RECORDED_METHODS:
            self.scope.lock()  # content has reached the host: the scope is now fixed

        return RpcResponse(result=raw_result, request_id=request.request_id, decision=decision)
