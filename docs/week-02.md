# Week 2 log — Aug 31 to Sep 4

## Done

- Async `Transport` abstraction (`transports/base.py`).
- `StdioTransport` — launches subprocess, JSON-RPC over stdin/stdout, one request at a time.
- `HttpTransport` — JSON-RPC over HTTP POST with `httpx.AsyncClient`.
- `Router` owns one transport per `server_id`.
- `Proxy` rewritten to be async, go through the router, keep tagging.
- `config.py` — strict Pydantic TOML loader for proxy + servers.
- `wiring.py` — one-call `build_proxy(config)` used by tests and the CLI.
- CLI subcommands: `list-servers`, `ping` (end-to-end sanity check against one server).
- Toy echo server under `examples/dummy_server/echo_server.py` for the stdio integration test.
- `configs/dev.toml` — sample config pointing at the echo server; placeholders for Anthropic reference servers.
- Test suite now at **42 tests, all passing**.

## Not done yet

- No HTTP server loop yet — the proxy exposes `handle()` but does not listen on a port. Week 3 adds the FastAPI loop so Claude Desktop can point at it.
- `Router.start_all()` starts transports sequentially; Week 4 makes it concurrent once we have more than two servers.
- Config does not yet hot-reload. Not a priority.

## Notes to self

- `StdioTransport` holds an `asyncio.Lock` so sequential callers do not interleave reads. Real MCP clients multiplex; revisit in Week 4.
- `HttpTransport` imports httpx lazily so stdio-only installs do not have to pay for it at import time.
- The toy echo server is **not** an MCP server. It is just enough to make the stdio test real (actual subprocess, actual bytes) without depending on a network install.

## Try it

```bash
provmcp list-servers -c configs/dev.toml
provmcp ping -c configs/dev.toml -s echo -m tools/call
```

The `ping` output should show the echo server's response, shaped like
`{"echoed_method": "tools/call", "echoed_params": {}}`.

## Next up (Week 3)

- FastAPI server loop — the proxy listens on `127.0.0.1:7337` and serves JSON-RPC to Claude Desktop.
- Set up Claude Desktop's `claude_desktop_config.json` to point at ProvMCP.
- Hands-on verification: list tools from `mcp-server-time` through the proxy from inside Claude Desktop.
