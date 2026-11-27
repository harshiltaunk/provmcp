"""A stdio MCP server that replays canned responses from a benchmark scenario.

Lets the live proxy be exercised end to end with real subprocesses but
deterministic content: the calendar server returns the poisoned event from
`cd-003`, the email server accepts sends, and so on.

    python scripted_server.py --scenario benchmarks/attacks/cd_003_....json --server calendar
    python scripted_server.py ... --server email --record /tmp/email-calls.jsonl

`--record` appends every `tools/call` the server actually receives to a JSONL
file. Tests use it to prove that a blocked call never reached the server.

Per-tool results come from `canned["responses"][tool]`; a list there is a
sequence (the n-th call gets the n-th item, the last one repeats). Without a
`tools/list` entry, the tool list is built from the `responses` keys.

The file is standalone on purpose (no provmcp import), so it runs under any
Python that a config names.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_canned(scenario_path: str, server_id: str) -> dict[str, Any]:
    scenario = json.loads(Path(scenario_path).read_text(encoding="utf-8"))
    for server in scenario["servers"]:
        if server["id"] == server_id:
            return dict(server.get("canned", {}))
    raise SystemExit(f"server {server_id!r} not in scenario {scenario_path}")


def tool_result(canned: dict[str, Any], tool: str, call_index: int) -> Any:
    responses = canned.get("responses") or {}
    if tool in responses:
        value = responses[tool]
        if isinstance(value, list):
            return value[min(call_index, len(value) - 1)] if value else {}
        return value
    return canned.get("tools/call", {"content": [], "isError": False})


def tool_list(canned: dict[str, Any]) -> Any:
    if "tools/list" in canned:
        return canned["tools/list"]
    schema = {"type": "object", "additionalProperties": True}
    return {
        "tools": [
            {"name": name, "description": name, "inputSchema": schema}
            for name in (canned.get("responses") or {})
        ]
    }


def reply(request_id: Any, result: Any = None, error: dict[str, Any] | None = None) -> None:
    envelope: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        envelope["error"] = error
    else:
        envelope["result"] = result
    sys.stdout.write(json.dumps(envelope) + "\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    canned = load_canned(args.scenario, args.server)
    calls: dict[str, int] = {}

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        message = json.loads(raw)
        if "id" not in message:
            continue  # notification
        method = message.get("method")
        if method == "initialize":
            reply(
                message["id"],
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": f"scripted-{args.server}", "version": "0"},
                },
            )
        elif method == "tools/list":
            reply(message["id"], tool_list(canned))
        elif method == "tools/call":
            params = message.get("params") or {}
            if args.record:
                Path(args.record).parent.mkdir(parents=True, exist_ok=True)
                with open(args.record, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(params) + "\n")
            tool = str(params.get("name", ""))
            index = calls.get(tool, 0)
            calls[tool] = index + 1
            reply(message["id"], tool_result(canned, tool, index))
        else:
            reply(message["id"], error={"code": -32601, "message": f"no method {method}"})


if __name__ == "__main__":
    main()
