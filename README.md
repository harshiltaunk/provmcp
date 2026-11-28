# ProvMCP

Runtime detection of cross-server confused-deputy attacks in multi-server Model Context Protocol configurations.

ProvMCP is a JSON-RPC proxy that sits between an MCP host (Claude Desktop, Cursor) and the MCP servers connected to it. It records which server every piece of returned content came from. Before forwarding a tool call, it checks whether the call's arguments carry content that originated at a different server, and then blocks it, holds it for the user's approval, or logs it, depending on policy.

**Status:** Week 12 of 16. Live enforcement with strict / warn-and-confirm / audit policies and out-of-band approvals (Week 7); an LLM agent harness with MCPSecBench-derived and InjecAgent cases (Week 8); 27 bundled scenarios, tool-metadata provenance and calibrated per-detector thresholds (Week 9); a four-level evaluation with confidence intervals (Week 10); a bounded, cached provenance store and a performance benchmark against the 50 ms / 100 MB targets (Week 11); an adaptive-adversary evaluation and opt-in canonical views that defeat encoding and reformatting evasions (Week 12). 266 tests.

## Why

When several MCP servers run under the same host, they share one LLM context window. The protocol gives a server no way to mark its output as untrusted with respect to other servers. A malicious server can plant instructions in its reply; the LLM reads them and then issues a tool call against a different server. That second server's privileges are abused through the LLM acting as a confused deputy.

This is a CSCI 298 research project at CSU Fresno, Fall 2026. Weekly progress is in `docs/week-*.md`.

## Quick start on macOS

Requires macOS 13+ and Python 3.11 or newer (`brew install python@3.11`).

```bash
git clone https://github.com/harshiltaunk/provmcp.git
cd provmcp
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev,embed]"      # drop ",embed" to skip sentence-transformers

pytest -q                           # 231 passed
bash scripts/demo_live_attack.sh    # watch ProvMCP stop a live exfiltration attempt
```

## How it runs

```
Claude Desktop ──stdio──> provmcp bridge --via URL --server calendar ─┐
               ──stdio──> provmcp bridge --via URL --server email ────┤ HTTP
                                                                       v
                          provmcp run -c config.toml   (one daemon, one shared provenance store)
                            ├── calendar MCP server
                            └── email MCP server
```

The daemon must hold the only provenance store. If each server had its own proxy process, content from the calendar server would never be visible when inspecting a call to the email server.

```bash
provmcp run -c configs/dev.toml                         # 1. start the daemon
provmcp export-claude-config -c configs/dev.toml        # 2. paste into claude_desktop_config.json
provmcp approvals list -c configs/dev.toml              # 3. review held calls
provmcp approvals approve <id> -c configs/dev.toml      #    (interactive terminal only)
provmcp audit -c configs/dev.toml                       # 4. see every decision
```

## Policies

| policy | when a cross-server flow is found |
|---|---|
| `strict` | Block. The assistant receives an error result; the target server never sees the call. |
| `warn_and_confirm` (default) | Hold. An approval is created; the user approves or denies it from a terminal. An approval allows the identical call once. |
| `audit` | Forward and log. |

The provenance store keeps at most 1,000 records per source server (`[proxy] provenance_max_per_server`), so memory stays bounded and one server cannot flush another's records; `provenance_ttl_seconds` adds expiry by age.

Policies can be overridden per (source, target) server pair, and trusted values (for example your own contacts) can be allowlisted. See `configs/dev.toml`.

Detection defaults (since 0.9.0) are calibrated on a held-out split and checked on real Claude traffic: substring 0.428 and structured 0.85, each with its own threshold, and tool descriptions (`tools/list`) tracked as a provenance source. `thresholds = {}` and `track_tool_metadata = false` restore the Week 7 behaviour. The embedding detector is calibrated (see `docs/results/calibration-week9.md`) but opt-in. See `docs/week-09.md`.

`canonicalize = true` (opt-in since 0.12) compares both sides after decoding base64, hex, percent-encoding and HTML references, Unicode normalization, case folding, defanging and despacing, so an encoded or reformatted copy is still tied to its source. See `docs/week-12.md`.

## Measuring attack success with an LLM

```bash
# free: a scripted agent that obeys every injection (upper bound)
provmcp agent-run -s benchmarks/attacks -s benchmarks/benign -s benchmarks/msb

# Claude (needs ANTHROPIC_API_KEY); --dry-run prints a cost estimate first
provmcp agent-run -s benchmarks/attacks -s benchmarks/msb \
  --backend anthropic --model claude-haiku-5-5 --trials 5 --dry-run

# a local model through Ollama
provmcp agent-run -s benchmarks/attacks --backend ollama --model llama3.1:8b

# InjecAgent cases as multi-server scenarios (MIT; clone it first)
python scripts/import_injecagent.py --repo ~/Projects/InjecAgent

# replay cached runs through other detector settings to count false alarms (no model calls)
provmcp agent-replay --cache logs/agent-cache-anthropic-claude-haiku-5-5.jsonl \
  -s benchmarks/attacks -s benchmarks/benign -s benchmarks/msb \
  --thresholds none --no-track-tool-metadata     # Week 7 settings; drop for the defaults

# performance: per-detector latency, proxy overhead, daemon memory (no model calls)
python scripts/bench_week11.py --quick

# the full evaluation: every strategy, four levels, intervals, figures (no model calls)
python scripts/evaluate_week10.py --run haiku=logs/agent-cache-haiku-week10.jsonl

# adaptive adversary: evasion scenarios, sweeps, and the cost of canonical views
python scripts/evaluate_week12.py --run haiku=logs/agent-cache-haiku-week10.jsonl

# rescore a cache with the current oracles and rebuild a report (no model calls)
provmcp agent-report --cache logs/agent-cache-anthropic-claude-haiku-5-5.jsonl \
  -s benchmarks/external/injecagent --out docs/results/baseline-week8-haiku-injecagent.md
```

`audit` gives the no-defense baseline and ProvMCP's detection rate from one
run; `strict` measures protection end to end. Success is judged by what the
target server actually received. See `docs/week-08.md` and
`docs/benchmarks/threat-model-mapping.md`.

## Project layout

```
src/provmcp/
  proxy.py            routing, recording, enforcement hook
  inspector.py        detectors + policy -> pass / block / hold
  approvals.py        single-use, out-of-band approvals
  audit.py            JSONL decision log
  provenance.py       origin tags and the shared store
  registry.py         server identity and trust class
  policy.py           strict / warn_and_confirm / audit
  detectors/          substring, structured, embedding, composite, canonical views
  server.py           HTTP daemon (FastAPI)
  bridge.py           stdio bridges (daemon and direct mode)
  evaluation.py       Week 10 strategies, levels and Wilson intervals
  adaptive.py         Week 12 adaptive-adversary scoring and sweeps
  perf.py             Week 11 latency and memory benchmarks
  svgchart.py         dependency-free SVG charts for the reports
  agent/              LLM agent harness: backends, episode runner, suite + report
  importers/          InjecAgent -> multi-server scenarios
  transports/         stdio and HTTP clients for backing servers
  config.py, wiring.py, cli.py, benchmark.py
benchmarks/           attack (cd-*), benign (bn-*) and MCPSecBench-derived (msb-*) scenarios;
                      adaptive/ holds the Week 12 evasion scenarios (ad-*, bn-ad-*);
                      splits/ holds the frozen Week 6 corpus and the Week 9 calibration split
examples/             echo and scripted test servers
configs/              dev.toml, demo-attack.toml
scripts/              evaluation, demo and verification scripts
docs/                 weekly logs and saved results
```

## Development workflow

```bash
ruff format src tests scripts examples
ruff check src tests scripts examples
mypy src
pytest -q
bash scripts/verify_week12.sh
```

## Known limitations

See `docs/week-07.md` to `docs/week-09.md` and `docs/week-12.md`. In short: approvals are protected only by a terminal check and file permissions; provenance has no per-session scope (it is bounded per server since 0.11); only `tools/call` is inspected; paraphrased data, values split across calls or transformed outside the decoder set (Week 12), self-flushing of a server's own quota, and pure control-flow hijacks are not detected; encoded and reformatted data is detected only with `canonicalize = true`; and provenance sees data flow, not user intent, so flows the user asked for are flagged too.

## License

Apache-2.0. See `LICENSE`.
