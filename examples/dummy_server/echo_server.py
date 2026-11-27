"""A toy JSON-RPC echo server used by the stdio transport tests.

Reads one JSON object per line from stdin, returns an envelope whose
`result` field echoes the method and params. Not an MCP server — just
enough to exercise the transport end-to-end without pulling in a real
backing server.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }
        else:
            if "id" not in request:
                continue  # JSON-RPC notifications get no reply
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "echoed_method": request.get("method"),
                    "echoed_params": request.get("params"),
                },
            }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
