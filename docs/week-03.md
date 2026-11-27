# Week 3 log — Sep 7 to 11

## Done

- `provmcp/server.py` — FastAPI app around the Proxy.
  - `POST /mcp/{server_id}` forwards JSON-RPC to the named backing server.
  - `GET /health` reports readiness, configured servers, and provenance store size.
  - Lifespan hook owns transport start-up and shutdown so uvicorn Ctrl-C closes subprocesses cleanly.
- `provmcp run` CLI subcommand starts the server loop.
- `provmcp export-claude-config` CLI subcommand prints a ready-to-paste
  Claude Desktop stanza that routes MCP calls through ProvMCP.
- `tests/test_server.py` — six new ASGI tests using `asgi-lifespan` and
  `httpx.ASGITransport`. No real sockets, no uvicorn — the lifespan
  hooks still fire so we get real start/close coverage.

## Test counts

- **47 tests, all passing** (was 41 at end of Week 2).

## Not done yet

- Claude Desktop currently only supports stdio transport by default. The
  `export-claude-config` stanza emits an HTTP transport block that works
  with any HTTP-capable MCP client (Cursor, custom test harnesses) but
  not vanilla Claude Desktop. Week 4 adds a stdio bridge so ProvMCP can
  sit inline for Claude Desktop too.
- No TLS yet — the server binds to `127.0.0.1` only. Good enough for a
  local research tool; add TLS in Week 11 if we expose remotely.

## Try it

```bash
# shell 1 — start ProvMCP
provmcp run -c configs/dev.toml

# shell 2 — hit it
curl -s http://127.0.0.1:7337/health | jq
curl -s -X POST http://127.0.0.1:7337/mcp/time \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' | jq
curl -s -X POST http://127.0.0.1:7337/mcp/time \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | jq
```

The third curl should return the time server's three tools.

## Next up (Week 4)

- Stdio bridge so Claude Desktop (which only speaks stdio) can talk to
  ProvMCP as if it were a backing server.
- Concurrent `Router.start_all()` — right now transports start serially
  which adds up with several servers.
- First multi-server attack scenario authored by hand to drive the
  Week 5 embedding detector design.
