# Week 1 log — Aug 24 to 28

## Done

- Repo scaffold under Apache-2.0, `pyproject.toml` with strict Ruff and mypy.
- Server registry with trust classes (trusted / limited / untrusted).
- Provenance primitives: `OriginTag`, `TaggedPayload`, `ProvenanceStore`.
- Transparent proxy skeleton with injected transport for unit tests.
- Substring detector — the first of three. Catches direct propagation with no paraphrase.
- Policy engine — strict, warn-and-confirm, audit templates.
- Test suite: 27 tests, 100 percent passing.

## Not done yet

- HTTP transport for the proxy (Week 2 work).
- Config loader for `.toml` files — currently the registry is built in code.
- The embedding and structured-field detectors (Weeks 5 and 6).

## Notes to self

- The substring detector's `min_run_length=8` default is a guess. Tune it on
  benign traces in Week 10 before the accuracy run.
- Keep `ProvenanceStore` in memory for now. Decide in Week 3 whether to add a
  SQLite backing store or stay in-memory for the life of one host session.
- The proxy's `TransportCall` type alias is `Any` for now so Week 2 can pick
  between sync and async without breaking the public surface.

## Next up (Week 2)

- Wire the proxy to a real HTTP transport using `httpx.AsyncClient`.
- Point Claude Desktop at the proxy and verify pass-through with the
  `filesystem` and `time` reference servers from Anthropic.
- Add a `provmcp run` CLI subcommand.
