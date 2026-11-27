# ProvMCP

Runtime detection of cross-server confused-deputy attacks in multi-server Model Context Protocol configurations.

ProvMCP is a transparent JSON-RPC proxy that sits between an MCP host (Claude Desktop, Cursor) and the MCP servers connected to it. It tags every server response with its origin, propagates those tags through the LLM context, and raises a flag when a tool call to one server carries content that originated at another server.

**Status:** Week 1 scaffold. Proxy skeleton, server registry, provenance tag schema.

## Why

When several MCP servers run under the same host, they share one LLM context window. The protocol does not let a server mark its output as untrusted with respect to other servers. A malicious server can plant instructions in its reply; the LLM reads them; the LLM then issues a tool call against a different server. That second server's privileges have been abused through the LLM acting as a confused deputy.

This project is a CSCI 298 research project at CSU Fresno, Fall 2026. See `docs/proposal.md` for the full proposal.

## Quick start on macOS

Requires macOS 13+ and Python 3.11 or newer.

```bash
# clone and enter
git clone <your-repo-url> provmcp
cd provmcp

# virtualenv (keeps system python clean)
python3.11 -m venv .venv
source .venv/bin/activate

# install in editable mode with dev deps
pip install -U pip
pip install -e ".[dev]"

# run the tests — should all pass
pytest -v

# run the proxy against the sample echo server
python -m provmcp.proxy --config configs/dev.toml
```

If `python3.11` is not on your system, install it with:

```bash
brew install python@3.11
```

## Project layout

```
provmcp/
  src/provmcp/
    __init__.py
    proxy.py           JSON-RPC pass-through proxy
    registry.py        Connected-server identity and trust class
    provenance.py      Origin tags, propagation rules
    policy.py          Strict / warn-and-confirm / audit templates
    detectors/
      substring.py     Byte-level propagation check
      embedding.py     Paraphrase check (sentence-transformers)
      structured.py    Typed-field re-use check
  tests/               pytest suite
  benchmarks/          attack scenarios, benign traces
  scripts/             one-off tools (wiring Claude Desktop, etc.)
  docs/                proposal, design notes, weekly logs
```

## Development workflow

```bash
# format + lint before every commit
ruff format src tests
ruff check src tests

# run the type checker
mypy src

# run the test suite
pytest -v

# run with coverage
pytest --cov=provmcp --cov-report=term-missing
```

## License

Apache-2.0. See `LICENSE`.
