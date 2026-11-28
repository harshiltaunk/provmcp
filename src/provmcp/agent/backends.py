"""LLM backends for the agent harness.

A backend holds one conversation. The runner calls `begin` once, then
alternates `step` (ask the model for its next turn) and `add_results` (give it
the results of the tool calls it made) until the model stops calling tools.

- `ScriptedBackend` replays a fixed plan of calls. It obeys every injected
  instruction, so it is an upper bound on attack success and a deterministic
  fixture for tests. It needs no network.
- `AnthropicBackend` uses the Claude Messages API with client tools.
- `OllamaBackend` uses a local model through Ollama's `/api/chat`.

HTTP goes through a `post` function that can be replaced in tests. The
default uses httpx, imported only when a request is actually made.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from provmcp.benchmark import Scenario

PostJson = Callable[[str, dict[str, str], dict[str, Any]], Awaitable[dict[str, Any]]]
RETRY_STATUS = frozenset({429, 500, 502, 503, 504, 529})


class BackendError(RuntimeError):
    """The model API failed. `fatal` errors (bad key, unknown model) stop a whole run."""

    def __init__(self, message: str, *, fatal: bool = False) -> None:
        super().__init__(message)
        self.fatal = fatal


@dataclass(frozen=True)
class ToolSpec:
    """One tool as shown to the model."""

    name: str  # name the model sees, "<server>__<tool>"
    server: str
    tool: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    call: ToolCall
    text: str
    is_error: bool = False


@dataclass
class Turn:
    text: str = ""
    calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    truncated: bool = False  # the reply hit the output limit and is incomplete


def model_tool_name(server: str, tool: str) -> str:
    """A tool name every API accepts: letters, digits, `_` and `-`, at most 64 chars."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", f"{server}__{tool}")[:64]


async def httpx_post(
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    *,
    timeout: float = 120.0,
    retries: int = 4,
) -> dict[str, Any]:
    """POST JSON with retries on rate limits, overload and connection errors."""
    import httpx

    delay = 2.0
    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, headers=headers, json=body)
        except httpx.TransportError as exc:
            if attempt == retries:
                raise BackendError(f"cannot reach {url}: {exc}") from exc
        else:
            if response.status_code < 400:
                data = response.json()
                if not isinstance(data, dict):
                    raise BackendError(f"unexpected response from {url}: {str(data)[:200]}")
                return data
            message = f"HTTP {response.status_code} from {url}: {response.text[:300]}"
            if response.status_code not in RETRY_STATUS or attempt == retries:
                fatal = response.status_code in {400, 401, 403, 404}
                raise BackendError(message, fatal=fatal)
        await asyncio.sleep(delay)
        delay *= 2
    raise BackendError(f"no response from {url}")  # pragma: no cover


class Backend(ABC):
    """One model conversation."""

    name = "backend"

    def __init__(self, model: str) -> None:
        self.model = model

    @abstractmethod
    def begin(self, *, system: str, task: str, tools: list[ToolSpec]) -> None:
        """Start a fresh conversation."""

    @abstractmethod
    async def step(self) -> Turn:
        """Ask the model for its next turn."""

    @abstractmethod
    def add_results(self, results: list[ToolResult]) -> None:
        """Give the model the results of the calls in its last turn."""


class ScriptedBackend(Backend):
    """Make a fixed sequence of calls, one per turn, then stop."""

    name = "scripted"

    def __init__(
        self,
        plan: list[tuple[str, str, dict[str, Any]]],
        scope: dict[str, Any] | None = None,
    ) -> None:
        super().__init__("scripted")
        self.plan = plan
        # Declared first when the catalog has `declare_scope` (Week 13).
        self.scope = scope
        self.results: list[ToolResult] = []
        self._names: dict[tuple[str, str], str] = {}
        self._next = 0
        self._declare: str | None = None

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> ScriptedBackend:
        """Follow the scenario's trace: the calls a fully compliant agent would make.

        Asked to declare a scope, it declares the scenario's ground truth, so it
        stands for an honest agent that reads the request correctly.
        """
        from provmcp.benchmark import ground_truth_scope

        plan = [
            (
                step.server,
                str(step.params.get("name", "")),
                dict(step.params.get("arguments") or {}),
            )
            for step in scenario.trace
            if step.method == "tools/call"
        ]
        return cls(plan, ground_truth_scope(scenario).to_json())

    def begin(self, *, system: str, task: str, tools: list[ToolSpec]) -> None:
        from provmcp.scope import SCOPE_SERVER_ID, SCOPE_TOOL

        self._names = {(t.server, t.tool): t.name for t in tools}
        self._next = 0
        self.results = []
        self._declare = self._names.get((SCOPE_SERVER_ID, SCOPE_TOOL)) if self.scope else None

    async def step(self) -> Turn:
        if self._declare is not None:
            name, self._declare = self._declare, None
            assert self.scope is not None
            return Turn(calls=[ToolCall(id="scripted_scope", name=name, arguments=self.scope)])
        if self._next >= len(self.plan):
            return Turn(text="Done.")
        server, tool, arguments = self.plan[self._next]
        self._next += 1
        name = self._names.get((server, tool), model_tool_name(server, tool))
        return Turn(calls=[ToolCall(id=f"scripted_{self._next}", name=name, arguments=arguments)])

    def add_results(self, results: list[ToolResult]) -> None:
        self.results.extend(results)


class AnthropicBackend(Backend):
    """Claude through the Messages API, with the scenario's tools as client tools."""

    name = "anthropic"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com",
        max_tokens: int = 8192,
        temperature: float | None = None,
        effort: str | None = None,
        post: PostJson | None = None,
    ) -> None:
        # Current Claude models may think before they answer. Thinking counts toward
        # `max_tokens` and is billed as output, so the limit is generous. `effort`
        # (`output_config.effort`) is sent only when given; the label used in caches
        # and reports then becomes "<model>@<effort>", so runs at different effort
        # levels are never mixed.
        super().__init__(f"{model}@{effort}" if effort else model)
        self.api_model = model
        self.effort = effort
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise BackendError("ANTHROPIC_API_KEY is not set", fatal=True)
        self._headers = {
            "x-api-key": key,
            "anthropic-version": self.API_VERSION,
            "content-type": "application/json",
        }
        self._url = base_url.rstrip("/") + "/v1/messages"
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._post: PostJson = post or httpx_post
        self._system = ""
        self._messages: list[dict[str, Any]] = []
        self._tools: list[dict[str, Any]] = []

    def begin(self, *, system: str, task: str, tools: list[ToolSpec]) -> None:
        self._system = system
        self._messages = [{"role": "user", "content": task}]
        self._tools = [
            {"name": t.name, "description": t.description or t.tool, "input_schema": t.input_schema}
            for t in tools
        ]

    async def step(self) -> Turn:
        body: dict[str, Any] = {
            "model": self.api_model,
            "max_tokens": self.max_tokens,
            "system": self._system,
            "messages": self._messages,
        }
        if self._tools:
            body["tools"] = self._tools
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if self.effort:
            body["output_config"] = {"effort": self.effort}
        data = await self._post(self._url, self._headers, body)
        content = data.get("content") or []
        usage = data.get("usage") or {}
        # Cached input is counted at the full input price: spend is never understated.
        input_keys = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
        turn = Turn(
            input_tokens=sum(int(usage.get(key) or 0) for key in input_keys),
            output_tokens=int(usage.get("output_tokens") or 0),
            truncated=data.get("stop_reason") == "max_tokens",
        )
        texts: list[str] = []
        for block in content:
            if block.get("type") == "text":
                texts.append(str(block.get("text", "")))
            elif block.get("type") == "tool_use":
                arguments = block.get("input")
                turn.calls.append(
                    ToolCall(
                        id=str(block.get("id", "")),
                        name=str(block.get("name", "")),
                        arguments=arguments if isinstance(arguments, dict) else {},
                    )
                )
        turn.text = "\n".join(t for t in texts if t)
        if content:
            self._messages.append({"role": "assistant", "content": content})
        return turn

    def add_results(self, results: list[ToolResult]) -> None:
        if not results:
            return
        self._messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": r.call.id,
                        "content": r.text,
                        "is_error": r.is_error,
                    }
                    for r in results
                ],
            }
        )


class OllamaBackend(Backend):
    """A local model through Ollama's chat API."""

    name = "ollama"

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://localhost:11434",
        temperature: float | None = 0.0,
        post: PostJson | None = None,
    ) -> None:
        super().__init__(model)
        self._url = base_url.rstrip("/") + "/api/chat"
        self.temperature = temperature
        self._post: PostJson = post or httpx_post
        self._messages: list[dict[str, Any]] = []
        self._tools: list[dict[str, Any]] = []
        self._turns = 0

    def begin(self, *, system: str, task: str, tools: list[ToolSpec]) -> None:
        self._messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]
        self._tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description or t.tool,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]
        self._turns = 0

    async def step(self) -> Turn:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": self._messages,
            "tools": self._tools,
            "stream": False,
        }
        if self.temperature is not None:
            body["options"] = {"temperature": self.temperature}
        data = await self._post(self._url, {}, body)
        self._turns += 1
        message = data.get("message") or {}
        raw_calls = message.get("tool_calls") or []
        turn = Turn(
            text=str(message.get("content") or ""),
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
        )
        for i, raw in enumerate(raw_calls):
            function = raw.get("function") or {}
            arguments: Any = function.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except ValueError:
                    arguments = {}
            turn.calls.append(
                ToolCall(
                    id=str(raw.get("id") or f"ollama_{self._turns}_{i}"),
                    name=str(function.get("name", "")),
                    arguments=arguments if isinstance(arguments, dict) else {},
                )
            )
        self._messages.append({"role": "assistant", "content": turn.text, "tool_calls": raw_calls})
        return turn

    def add_results(self, results: list[ToolResult]) -> None:
        for r in results:
            self._messages.append({"role": "tool", "tool_name": r.call.name, "content": r.text})
