"""LLM backends, with the HTTP layer replaced by a recording fake."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from provmcp.agent.backends import (
    AnthropicBackend,
    BackendError,
    OllamaBackend,
    ScriptedBackend,
    ToolCall,
    ToolResult,
    ToolSpec,
    model_tool_name,
)
from provmcp.benchmark import load_scenario
from tests.test_live_enforcement import CD003

SPEC = ToolSpec(
    name="email__send",
    server="email",
    tool="send",
    description="Send an email.",
    input_schema={"type": "object", "properties": {"to": {"type": "string"}}},
)


class FakePost:
    """Returns queued responses and keeps a deep copy of every request."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    async def __call__(
        self, url: str, headers: dict[str, str], body: dict[str, Any]
    ) -> dict[str, Any]:
        self.requests.append((url, dict(headers), copy.deepcopy(body)))
        return self.responses.pop(0)


def test_model_tool_name_is_api_safe() -> None:
    assert model_tool_name("google-calendar", "Get Events") == "google-calendar__Get_Events"
    assert len(model_tool_name("s" * 40, "t" * 40)) == 64


async def test_anthropic_round_trip_with_tool_use() -> None:
    post = FakePost(
        [
            {
                "content": [
                    {"type": "text", "text": "Sending now."},
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "email__send",
                        "input": {"to": "a@b.example"},
                    },
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 120, "output_tokens": 30},
            },
            {
                "content": [{"type": "text", "text": "Done."}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 160, "output_tokens": 5},
            },
        ]
    )
    backend = AnthropicBackend("claude-haiku-5-5", api_key="sk-test", post=post)
    backend.begin(system="sys", task="email a@b", tools=[SPEC])

    first = await backend.step()
    assert first.text == "Sending now."
    assert first.calls == [ToolCall("toolu_1", "email__send", {"to": "a@b.example"})]
    assert (first.input_tokens, first.output_tokens) == (120, 30)

    backend.add_results([ToolResult(first.calls[0], "queued")])
    second = await backend.step()
    assert second.text == "Done." and second.calls == []

    url, headers, body = post.requests[0]
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "sk-test"
    assert headers["anthropic-version"] == "2023-06-01"
    assert body["model"] == "claude-haiku-5-5"
    assert body["system"] == "sys"
    assert body["tools"][0]["input_schema"]["type"] == "object"
    assert "temperature" not in body

    messages = post.requests[1][2]["messages"]
    assert [m["role"] for m in messages] == ["user", "assistant", "user"]
    assert messages[2]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "toolu_1",
        "content": "queued",
        "is_error": False,
    }


def test_anthropic_needs_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(BackendError) as info:
        AnthropicBackend("claude-haiku-5-5")
    assert info.value.fatal


async def test_ollama_parses_tool_calls_and_returns_results() -> None:
    post = FakePost(
        [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": "email__send", "arguments": {"to": "x@y.example"}}},
                        {"function": {"name": "email__send", "arguments": '{"to": "z@y.example"}'}},
                    ],
                },
                "prompt_eval_count": 90,
                "eval_count": 12,
            },
            {"message": {"role": "assistant", "content": "All sent."}},
        ]
    )
    backend = OllamaBackend("llama3.1:8b", post=post)
    backend.begin(system="sys", task="send", tools=[SPEC])
    turn = await backend.step()
    assert [c.arguments for c in turn.calls] == [{"to": "x@y.example"}, {"to": "z@y.example"}]
    assert len({c.id for c in turn.calls}) == 2
    assert (turn.input_tokens, turn.output_tokens) == (90, 12)

    backend.add_results([ToolResult(c, "ok") for c in turn.calls])
    final = await backend.step()
    assert final.text == "All sent."

    url, _, body = post.requests[0]
    assert url == "http://localhost:11434/api/chat"
    assert body["stream"] is False
    assert body["tools"][0]["function"]["parameters"]["type"] == "object"
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    follow_up = post.requests[1][2]["messages"]
    assert follow_up[-1] == {"role": "tool", "tool_name": "email__send", "content": "ok"}


async def test_scripted_backend_follows_the_trace() -> None:
    backend = ScriptedBackend.from_scenario(load_scenario(CD003))
    backend.begin(system="", task="", tools=[SPEC])
    first = await backend.step()
    second = await backend.step()
    third = await backend.step()
    assert first.calls[0].name == "calendar__get_next_event"
    assert second.calls[0].name == "email__send"
    assert second.calls[0].arguments["to"] == "exfil.team@evil-partner.example"
    assert third.calls == []
