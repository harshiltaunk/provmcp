# Week 4 log — Sep 14 to 18

## Done

- `provmcp/bridge.py` — stdio bridge class. Reads JSON-RPC lines from stdin,
  routes through the Proxy, writes responses to stdout. Notifications are
  not replied to. Bad JSON yields a `-32700` parse error.
- `provmcp bridge -c <config> -s <server>` CLI subcommand.
- `provmcp export-claude-config` now emits two modes:
  - `--mode bridge` (default) — stdio bridge command per server, works with
    vanilla Claude Desktop.
  - `--mode http` — HTTP endpoint per server, for HTTP-capable clients.
- `Router.start_all()` now runs transport starts concurrently via
  `asyncio.gather`. Tested: four 100 ms starts finish in < 300 ms.
- First authored multi-server attack scenario:
  `benchmarks/attacks/cd_001_calendar_to_email.json` — a poisoned
  calendar event's description shares a distinctive marker
  (`ACMEWarehouse-Dock-42B`) that the LLM's email call reproduces.
- First authored benign scenario:
  `benchmarks/benign/bn_001_independent_calls.json` — calendar and email
  calls with no shared content.
- `provmcp/benchmark.py` — scenario loader (Pydantic) plus offline
  `BenchmarkRunner` that replays scenarios through the current detector
  stack.
- `provmcp run-benchmark --scenarios <dir>` CLI subcommand with a
  per-scenario verdict and TP / FP / TN / FN summary.

## Test counts

- **59 tests, all passing** (was 47 at end of Week 3).

## Try it

```bash
# wire Claude Desktop to ProvMCP via the stdio bridge
provmcp export-claude-config -c configs/dev.toml --mode bridge > /tmp/claude_stanza.json
cat /tmp/claude_stanza.json
# paste the "mcpServers" block into ~/Library/Application Support/Claude/claude_desktop_config.json
# then restart Claude Desktop

# offline benchmark of the authored scenarios
provmcp run-benchmark --scenarios benchmarks/attacks
provmcp run-benchmark --scenarios benchmarks/benign
```

For the benchmark you should see `cd-001-calendar-to-email: true positive`
and `bn-001-independent-calls: true negative` with 1 TP / 0 FP / 1 TN / 0 FN
each.

## Not done yet

- Only the substring detector is wired. Embedding + structured-field
  detectors land in Weeks 5 and 6; the benchmark runner is already
  shaped to accept multiple detectors.
- `StdioBridge._serve` uses `run_in_executor` for stdin reads. Fine for
  one bridge per subprocess but inefficient at scale; refactor to the
  streams API in Week 11 when overhead becomes measurable.

## Next up (Week 5)

- Embedding detector (sentence-transformers/all-MiniLM-L6-v2 on CPU) for
  paraphrased propagation that substring matching misses.
- Second attack scenario: calendar note paraphrased into an email body.
- Threshold-sweep script to pick embedding cutoffs on the benign corpus.
