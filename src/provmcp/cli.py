"""Command-line entry point."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from provmcp import __version__
from provmcp.config import DetectionConfig, load_config
from provmcp.detectors.base import Detector
from provmcp.proxy import RpcRequest
from provmcp.server import build_app
from provmcp.wiring import build_approvals, build_audit, build_proxy

app = typer.Typer(no_args_is_help=True, add_completion=False)
approvals_app = typer.Typer(no_args_is_help=True, help="Review calls held for approval.")
app.add_typer(approvals_app, name="approvals")
console = Console()


@app.command()
def version() -> None:
    """Print the ProvMCP version."""
    console.print(f"provmcp [bold]{__version__}[/bold]")


@app.command()
def doctor() -> None:
    """Report Python version and import health."""
    console.print(f"python: [bold]{sys.version.split()[0]}[/bold]")
    ok = True
    for module in ("pydantic", "fastapi", "httpx", "typer", "uvicorn"):
        try:
            __import__(module)
            console.print(f"  {module}: [green]ok[/green]")
        except ImportError as exc:
            console.print(f"  {module}: [red]missing[/red] ({exc})")
            ok = False
    if not ok:
        raise typer.Exit(code=1)


@app.command(name="list-servers")
def list_servers(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
) -> None:
    """Show the servers declared in a config file."""
    cfg = load_config(config)
    table = Table(title="Configured servers")
    table.add_column("id", style="bold")
    table.add_column("display name")
    table.add_column("trust")
    table.add_column("transport")
    table.add_column("endpoint")
    for s in cfg.servers:
        endpoint = " ".join(s.command) if s.transport == "stdio" else (s.url or "-")
        table.add_row(s.id, s.display_name, s.trust.value, s.transport, endpoint)
    console.print(table)


@app.command()
def ping(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    server: Annotated[str, typer.Option("--server", "-s")],
    method: Annotated[str, typer.Option("--method", "-m")] = "tools/list",
    params: Annotated[str, typer.Option("--params", "-p", help="JSON object")] = "{}",
) -> None:
    """Send one JSON-RPC call to a server through the proxy and print the result.

    Performs the MCP initialize handshake first so real servers accept the
    subsequent call. Inspection applies, so a `tools/call` can be held.
    """
    cfg = load_config(config)
    proxy = build_proxy(cfg)
    call_params = json.loads(params)

    async def go() -> None:
        await proxy.router.start_all()
        try:
            await proxy.handle(
                RpcRequest(
                    method="initialize",
                    params={
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "provmcp-ping", "version": __version__},
                    },
                    request_id=1,
                    target_server_id=server,
                )
            )
            await proxy.handle(
                RpcRequest(
                    method="notifications/initialized",
                    params={},
                    request_id=None,
                    target_server_id=server,
                )
            )
            response = await proxy.handle(
                RpcRequest(
                    method=method,
                    params=call_params,
                    request_id=2,
                    target_server_id=server,
                )
            )
            console.print_json(data=response.result)
        finally:
            await proxy.router.close_all()

    asyncio.run(go())


@app.command()
def run(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    host: Annotated[str | None, typer.Option("--host")] = None,
    port: Annotated[int | None, typer.Option("--port")] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
) -> None:
    """Start the ProvMCP HTTP server loop.

    Loads the config, wires a Proxy, and serves JSON-RPC over HTTP so MCP
    clients can connect at `/mcp/<server_id>`.
    """
    cfg = load_config(config)
    bind_host = host or cfg.proxy.host
    bind_port = port or cfg.proxy.port
    fastapi_app = build_app(build_proxy(cfg))
    console.print(
        f"ProvMCP serving {len(cfg.servers)} server(s) on "
        f"[bold]http://{bind_host}:{bind_port}[/bold]"
    )
    if cfg.detection.enabled:
        console.print(
            f"  inspection: {', '.join(cfg.detection.detectors)}  "
            f"policy={cfg.proxy.policy.value}  threshold={cfg.proxy.detector_threshold}"
        )
        for pair in cfg.proxy.pair_policies:
            console.print(f"  pair policy: {pair.source} -> {pair.target} = {pair.policy.value}")
        console.print(f"  audit log: {cfg.resolve_path(cfg.proxy.audit_log) or 'memory only'}")
        console.print(f"  approvals: {cfg.resolve_path(cfg.proxy.approvals_file) or 'memory only'}")
    else:
        console.print("  inspection: [yellow]disabled[/yellow]")
    uvicorn.run(fastapi_app, host=bind_host, port=bind_port, log_level=log_level)


@app.command()
def bridge(
    server: Annotated[str, typer.Option("--server", "-s")],
    via: Annotated[
        str | None, typer.Option("--via", help="URL of a running `provmcp run` daemon")
    ] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c", exists=True)] = None,
) -> None:
    """Run a stdio bridge for one backing server (what Claude Desktop launches).

    --via URL      daemon mode (recommended): relay to a running `provmcp run`,
                   which holds the one provenance store shared by every server.
    --config PATH  direct mode: an in-process proxy for this server only. No
                   cross-server detection, because nothing is shared.
    """
    from provmcp.bridge import DaemonBridge, StdioBridge

    if via is not None:
        asyncio.run(DaemonBridge(daemon_url=via, server_id=server).run())
        return
    if config is None:
        raise typer.BadParameter("pass --via <daemon url> or --config <path>")
    proxy = build_proxy(load_config(config))
    asyncio.run(StdioBridge(proxy=proxy, server_id=server).run())


@app.command(name="run-benchmark")
def run_benchmark(
    scenarios: Annotated[Path, typer.Option("--scenarios", exists=True)],
    detector: Annotated[str, typer.Option("--detector", "-d")] = "substring",
    embedding_threshold: Annotated[float, typer.Option("--embedding-threshold")] = 0.72,
) -> None:
    """Replay every JSON scenario under a directory through the detector.

    --detector substring    byte-level matching only (default)
    --detector structured   typed values (emails, URLs, paths, IDs), normalized
    --detector embedding    sentence-transformers semantic similarity
    --detector composite    all three, deduplicated per source server
    """
    from provmcp.benchmark import BenchmarkRunner, load_scenarios
    from provmcp.detectors import (
        CompositeDetector,
        EmbeddingDetector,
        StructuredFieldDetector,
        SubstringDetector,
    )

    selected: Detector
    if detector == "substring":
        selected = SubstringDetector(min_run_length=8)
    elif detector == "structured":
        selected = StructuredFieldDetector()
    elif detector == "embedding":
        selected = EmbeddingDetector(threshold=embedding_threshold)
    elif detector == "composite":
        selected = CompositeDetector(
            [
                SubstringDetector(min_run_length=8),
                StructuredFieldDetector(),
                EmbeddingDetector(threshold=embedding_threshold),
            ]
        )
    else:
        raise typer.BadParameter(f"unknown detector: {detector!r}")

    runner = BenchmarkRunner(detector=selected)
    corpus = load_scenarios(scenarios)
    tp = fp = tn = fn = 0
    for scenario in corpus:
        result = runner.run(scenario)
        gt = result.ground_truth
        flagged = any(step.findings for step in result.steps)
        if gt == "cross_server_influence":
            if flagged:
                tp += 1
                verdict = "[green]true positive[/green]"
            else:
                fn += 1
                verdict = "[red]false negative[/red]"
        else:
            if flagged:
                fp += 1
                verdict = "[red]false positive[/red]"
            else:
                tn += 1
                verdict = "[green]true negative[/green]"
        console.print(f"{result.scenario_id}: {verdict}")
        for step in result.steps:
            if step.findings:
                for f in step.findings:
                    console.print(
                        f"  step {step.step} → {f.source_server_id} → "
                        f"{f.target_server_id} conf={f.confidence:.2f} "
                        f"excerpt={f.excerpt[:60]!r}"
                    )
    total = tp + fp + tn + fn
    console.print()
    console.print(f"[bold]Summary[/bold]: {total} scenarios  TP={tp} FP={fp} TN={tn} FN={fn}")


@app.command(name="export-claude-config")
def export_claude_config(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    mode: Annotated[str, typer.Option("--mode")] = "daemon",
    host: Annotated[str | None, typer.Option("--host")] = None,
    port: Annotated[int | None, typer.Option("--port")] = None,
) -> None:
    """Print a Claude Desktop config stanza that routes MCP traffic through ProvMCP.

    Paste the output into:

        ~/Library/Application Support/Claude/claude_desktop_config.json

    --mode daemon (default): one thin bridge per server relaying to the
      `provmcp run` daemon. Cross-server detection works. Start the daemon first.
    --mode bridge: one self-contained bridge per server. No cross-server
      detection; for single-server testing only.
    --mode http: HTTP endpoints, for clients with HTTP transport support.
    """
    cfg = load_config(config)
    abs_config = str(Path(config).resolve())
    daemon = f"http://{host or cfg.proxy.host}:{port or cfg.proxy.port}"
    provmcp_bin = str(Path(sys.executable).parent / "provmcp")
    servers: dict[str, Any]
    if mode == "daemon":
        servers = {
            s.id: {"command": provmcp_bin, "args": ["bridge", "--via", daemon, "--server", s.id]}
            for s in cfg.servers
        }
    elif mode == "bridge":
        servers = {
            s.id: {
                "command": provmcp_bin,
                "args": ["bridge", "--config", abs_config, "--server", s.id],
            }
            for s in cfg.servers
        }
    elif mode == "http":
        servers = {s.id: {"url": f"{daemon}/mcp/{s.id}", "transport": "http"} for s in cfg.servers}
    else:
        raise typer.BadParameter(f"unknown mode: {mode!r} (use daemon, bridge or http)")
    print(json.dumps({"mcpServers": servers}, indent=2))


@app.command()
def audit(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    last: Annotated[int, typer.Option("--last", "-n")] = 20,
) -> None:
    """Show the most recent inspection decisions from the audit log."""
    cfg = load_config(config)
    log = build_audit(cfg)
    if log.path is None:
        console.print("No audit_log configured in [proxy]; nothing is persisted.")
        raise typer.Exit(code=1)
    events = log.read(last=last)
    if not events:
        console.print(f"No events yet in {log.path}")
        return
    table = Table(title=f"Last {len(events)} decision(s) — {log.path}")
    for column in ("time", "action", "policy", "target", "tool", "from", "evidence", "approval"):
        table.add_column(column)
    for e in events:
        findings = e.get("findings") or []
        sources = ",".join(sorted({f.get("source_server_id", "?") for f in findings}))
        evidence = findings[0].get("excerpt", "")[:48] if findings else ""
        table.add_row(
            str(e.get("ts", "")),
            str(e.get("action", "")),
            str(e.get("template", "")),
            str(e.get("target", "")),
            str(e.get("tool", "")),
            sources,
            evidence,
            str(e.get("approval_id") or ""),
        )
    console.print(table)


@approvals_app.command("list")
def approvals_list(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    show_all: Annotated[bool, typer.Option("--all", help="include decided ones")] = False,
) -> None:
    """List calls waiting for approval."""
    store = build_approvals(load_config(config))
    items = store.entries(include_decided=show_all)
    if not items:
        console.print("No pending approvals." if not show_all else "No approvals recorded.")
        return
    table = Table(title="Approvals")
    for column in ("id", "status", "target", "tool", "what was found"):
        table.add_column(column)
    for item in items:
        table.add_row(item.id, item.status, item.target, item.tool, item.summary)
    console.print(table)


def _decide(config: Path, approval_id: str, *, approve: bool) -> None:
    if not sys.stdin.isatty():
        console.print(
            "[red]Refusing:[/red] approvals must be confirmed in an interactive terminal, "
            "so an LLM tool cannot approve its own held call."
        )
        raise typer.Exit(code=2)
    store = build_approvals(load_config(config))
    item = store.get(approval_id)
    if item is None:
        console.print(f"[red]No approval with id {approval_id}[/red]")
        raise typer.Exit(code=1)
    console.print(f"[bold]{item.tool}[/bold] on [bold]{item.target}[/bold]: {item.summary}")
    verb = "Approve" if approve else "Deny"
    if not typer.confirm(f"{verb} this call?"):
        raise typer.Exit(code=1)
    try:
        decided = store.decide(approval_id, approve=approve)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"{approval_id}: [bold]{decided.status}[/bold]")
    if approve:
        console.print("The identical call will be allowed once if it is retried.")


@approvals_app.command("approve")
def approvals_approve(
    approval_id: str,
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
) -> None:
    """Approve one held call (interactive confirmation required)."""
    _decide(config, approval_id, approve=True)


@approvals_app.command("deny")
def approvals_deny(
    approval_id: str,
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
) -> None:
    """Deny one held call; identical retries are then blocked."""
    _decide(config, approval_id, approve=False)


def _detection_options(
    detectors: str, thresholds: str, substring_score: str, track_tool_metadata: bool | None
) -> DetectionConfig:
    """Build a [detection] section from CLI options; unset options keep the defaults.

    `thresholds`: '' keeps the calibrated defaults, 'none' means one global
    threshold (Week 7 behaviour), otherwise 'substring=0.43,structured=0.85'.
    """
    data: dict[str, object] = {"detectors": [d.strip() for d in detectors.split(",") if d.strip()]}
    if thresholds.strip().lower() == "none":
        data["thresholds"] = {}
    elif thresholds.strip():
        parsed: dict[str, float] = {}
        for item in (t.strip() for t in thresholds.split(",")):
            if not item:
                continue
            name, sep, value = item.partition("=")
            if not sep:
                raise typer.BadParameter(f"thresholds need name=value, got {item!r}")
            try:
                parsed[name.strip()] = float(value)
            except ValueError as exc:
                raise typer.BadParameter(f"not a number in {item!r}") from exc
        data["thresholds"] = parsed
    if substring_score:
        data["substring_score"] = substring_score
    if track_tool_metadata is not None:
        data["track_tool_metadata"] = track_tool_metadata
    try:
        return DetectionConfig.model_validate(data)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _describe_detection(detection: DetectionConfig, threshold: float) -> str:
    gates = (
        ", ".join(f"{k}={v}" for k, v in detection.thresholds.items())
        if detection.thresholds
        else f"all={threshold}"
    )
    return (
        f"{', '.join(detection.detectors)}; thresholds {gates}; "
        f"substring score {detection.substring_score}; "
        f"tool metadata {'tracked' if detection.track_tool_metadata else 'not tracked'}"
    )


@app.command(name="agent-run")
def agent_run(
    scenarios: Annotated[
        list[Path], typer.Option("--scenarios", "-s", exists=True, help="directory or file")
    ],
    backend: Annotated[str, typer.Option(help="scripted | anthropic | ollama")] = "scripted",
    model: Annotated[str, typer.Option(help="e.g. claude-haiku-5-5 or llama3.1:8b")] = "",
    conditions: Annotated[str, typer.Option(help="comma list of none,audit,warn,strict")] = (
        "audit,strict"
    ),
    trials: Annotated[int, typer.Option(min=1)] = 1,
    limit: Annotated[int | None, typer.Option(help="sample at most N per --scenarios path")] = None,
    seed: Annotated[int, typer.Option()] = 0,
    include_same_server: Annotated[bool, typer.Option("--include-same-server")] = False,
    detectors: Annotated[str, typer.Option()] = "substring,structured",
    threshold: Annotated[float, typer.Option(min=0.0, max=1.0)] = 0.6,
    thresholds: Annotated[
        str, typer.Option(help="'' = calibrated defaults, 'none' = one global, or name=value,...")
    ] = "",
    substring_score: Annotated[str, typer.Option(help="longest | coverage (default longest)")] = "",
    track_tool_metadata: Annotated[
        bool | None, typer.Option("--track-tool-metadata/--no-track-tool-metadata")
    ] = None,
    max_steps: Annotated[int, typer.Option(min=1)] = 8,
    concurrency: Annotated[int, typer.Option(min=1)] = 4,
    max_usd: Annotated[float | None, typer.Option(help="stop when spend reaches this")] = None,
    price_in: Annotated[float | None, typer.Option(help="USD per 1M input tokens")] = None,
    price_out: Annotated[float | None, typer.Option(help="USD per 1M output tokens")] = None,
    ollama_url: Annotated[str, typer.Option()] = "http://localhost:11434",
    out: Annotated[Path | None, typer.Option(help="write a markdown report here")] = None,
    cache: Annotated[Path | None, typer.Option(help="JSONL results cache (resumable)")] = None,
    workdir: Annotated[Path, typer.Option()] = Path("logs/agent-runs"),
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Run scenarios with an LLM agent behind ProvMCP and measure attack success.

    Conditions: none (no ProvMCP), audit (ProvMCP logs only: the baseline),
    warn (held calls are never approved), strict (flagged calls are blocked).
    Results are cached, so an interrupted run resumes with the same command.
    """
    import logging
    from datetime import date

    from provmcp.agent.backends import (
        AnthropicBackend,
        Backend,
        BackendError,
        OllamaBackend,
        ScriptedBackend,
    )
    from provmcp.agent.experiment import (
        KNOWN_PRICES,
        estimate_tokens,
        render_report,
        run_suite,
        select_scenarios,
    )
    from provmcp.agent.runner import CONDITIONS, SYSTEM_PROMPT
    from provmcp.benchmark import Scenario

    logging.getLogger("provmcp").setLevel(logging.ERROR)  # the report carries the decisions
    condition_list = [c.strip() for c in conditions.split(",") if c.strip()]
    unknown = [c for c in condition_list if c not in CONDITIONS]
    if unknown:
        raise typer.BadParameter(f"unknown condition(s) {unknown}; use {sorted(CONDITIONS)}")
    detection = _detection_options(detectors, thresholds, substring_score, track_tool_metadata)
    detector_list = detection.detectors
    if backend in {"anthropic", "ollama"} and not model:
        raise typer.BadParameter(f"--model is required for --backend {backend}")
    model_name = model or "scripted"
    known_in, known_out = KNOWN_PRICES.get(model_name, (0.0, 0.0))
    p_in = price_in if price_in is not None else known_in
    p_out = price_out if price_out is not None else known_out
    if backend == "anthropic" and model_name not in KNOWN_PRICES and price_in is None:
        console.print(
            f"[yellow]No price known for {model_name}; pass --price-in/--price-out "
            "for cost tracking and --max-usd.[/yellow]"
        )

    chosen, notes = select_scenarios(
        scenarios, limit=limit, seed=seed, include_same_server=include_same_server
    )
    for note in notes:
        console.print(f"  note: {note}")
    if not chosen:
        console.print("[red]No runnable scenarios (need a task and an oracle).[/red]")
        raise typer.Exit(code=1)

    episodes = len(chosen) * len(condition_list) * trials
    est_in = est_out = 0
    for scenario in chosen:
        i, o = estimate_tokens(scenario, max_steps)
        est_in += i * len(condition_list) * trials
        est_out += o * len(condition_list) * trials
    est_cost = (est_in * p_in + est_out * p_out) / 1_000_000
    console.print(
        f"{len(chosen)} scenario(s) x {len(condition_list)} condition(s) x {trials} trial(s) "
        f"= [bold]{episodes}[/bold] episode(s); backend={backend} model={model_name}"
    )
    console.print(
        f"  rough estimate: {est_in:,} input + {est_out:,} output tokens ≈ ${est_cost:.2f} "
        f"(at ${p_in}/{p_out} per 1M)"
    )
    if dry_run:
        return

    def make_backend(scenario: Scenario) -> Backend:
        if backend == "scripted":
            return ScriptedBackend.from_scenario(scenario)
        if backend == "anthropic":
            return AnthropicBackend(model_name)
        if backend == "ollama":
            return OllamaBackend(model_name, base_url=ollama_url)
        raise typer.BadParameter(f"unknown backend {backend!r}")

    if chosen:
        try:
            make_backend(chosen[0])
        except BackendError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc

    safe_model = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in model_name)
    cache_path = cache or Path("logs") / f"agent-cache-{backend}-{safe_model}.jsonl"
    try:
        results = asyncio.run(
            run_suite(
                chosen,
                make_backend,
                model=model_name,
                conditions=condition_list,
                trials=trials,
                workroot=workdir,
                cache=cache_path,
                detectors=detector_list,
                threshold=threshold,
                detection=detection,
                max_steps=max_steps,
                concurrency=1 if backend == "scripted" else concurrency,
                price_in=p_in,
                price_out=p_out,
                max_usd=max_usd,
                progress=console.print,
            )
        )
    except BackendError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    spent = sum(r.input_tokens * p_in + r.output_tokens * p_out for r in results) / 1_000_000
    report = render_report(
        results,
        title=f"Agent baseline: {backend} / {model_name}",
        settings={
            "date": date.today().isoformat(),
            "provmcp": __version__,
            "backend / model": f"{backend} / {model_name}",
            "conditions": ", ".join(condition_list),
            "trials": str(trials),
            "detection": _describe_detection(detection, threshold),
            "max steps": str(max_steps),
            "scenarios": ", ".join(str(p) for p in scenarios)
            + (f" (limit {limit} per path, seed {seed})" if limit else ""),
            "system prompt": f'"{SYSTEM_PROMPT}"',
            "cost": f"${spent:.4f} at ${p_in}/{p_out} per 1M tokens",
            "cache": str(cache_path),
        },
    )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        console.print(f"Report written to [bold]{out}[/bold]")
    else:
        console.print(report)
    console.print(f"{len(results)} episode(s) reported; spend ${spent:.4f}")


@app.command(name="agent-report")
def agent_report(
    cache: Annotated[Path, typer.Option("--cache", exists=True, help="agent-run JSONL cache")],
    scenarios: Annotated[
        list[Path], typer.Option("--scenarios", "-s", exists=True, help="directory or file")
    ],
    conditions: Annotated[str | None, typer.Option(help="comma list to keep")] = None,
    out: Annotated[Path | None, typer.Option(help="write the markdown report here")] = None,
) -> None:
    """Re-score cached agent episodes with the current oracles and write a report.

    Makes no model calls, so it is free. Use it after an oracle changes, or to
    build a report for a subset of the scenarios in a cache.
    """
    from datetime import date

    from provmcp.agent.experiment import KNOWN_PRICES, load_cache, render_report, rescore
    from provmcp.benchmark import Scenario, load_scenario, load_scenarios

    by_id: dict[str, Scenario] = {}
    for path in scenarios:
        for scenario in load_scenarios(path) if path.is_dir() else [load_scenario(path)]:
            by_id[scenario.id] = scenario
    keep = {c.strip() for c in conditions.split(",")} if conditions else None
    cached = [
        r
        for r in load_cache(cache).values()
        if r.scenario_id in by_id and (keep is None or r.condition in keep)
    ]
    results, missing = rescore(cached, by_id)
    if not results:
        console.print("[red]No cached episodes match these scenarios.[/red]")
        raise typer.Exit(code=1)
    models = sorted({f"{r.backend} / {r.model}" for r in results})
    price_in, price_out = KNOWN_PRICES.get(results[0].model, (0.0, 0.0))
    spent = sum(r.input_tokens * price_in + r.output_tokens * price_out for r in results)
    report = render_report(
        results,
        title=f"Agent baseline (rescored): {', '.join(models)}",
        settings={
            "date": date.today().isoformat(),
            "provmcp": __version__,
            "backend / model": ", ".join(models),
            "conditions": ", ".join(sorted({r.condition for r in results})),
            "trials": str(max(r.trial for r in results) + 1),
            "scenarios": ", ".join(str(p) for p in scenarios),
            "scoring": "rescored from cache: attack goals must follow the entry call and "
            "carry argument evidence",
            "cost of the original runs": f"${spent / 1_000_000:.4f}",
            "cache": str(cache),
        },
    )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        console.print(f"Report written to [bold]{out}[/bold] ({len(results)} episode(s))")
    else:
        console.print(report)
    if missing:
        console.print(f"  note: {len(missing)} cached scenario id(s) had no oracle")


@app.command(name="agent-replay")
def agent_replay(
    cache: Annotated[Path, typer.Option("--cache", exists=True, help="agent-run JSONL cache")],
    scenarios: Annotated[
        list[Path], typer.Option("--scenarios", "-s", exists=True, help="directory or file")
    ],
    conditions: Annotated[str, typer.Option(help="comma list to replay")] = "audit",
    detectors: Annotated[str, typer.Option()] = "substring,structured",
    threshold: Annotated[float, typer.Option(min=0.0, max=1.0)] = 0.6,
    thresholds: Annotated[
        str, typer.Option(help="'' = calibrated defaults, 'none' = one global, or name=value,...")
    ] = "",
    substring_score: Annotated[str, typer.Option(help="longest | coverage (default longest)")] = "",
    track_tool_metadata: Annotated[
        bool | None, typer.Option("--track-tool-metadata/--no-track-tool-metadata")
    ] = None,
    out: Annotated[Path | None, typer.Option(help="write the markdown report here")] = None,
) -> None:
    """Replay cached agent runs through a detector configuration (no model calls).

    Measures false alarms on real model traffic and detection of the attacks
    the model actually attempted, for any detector settings.
    """
    from provmcp.agent.experiment import load_cache
    from provmcp.agent.replay import render_replay_report, replay_all
    from provmcp.benchmark import Scenario, load_scenario, load_scenarios

    detection = _detection_options(detectors, thresholds, substring_score, track_tool_metadata)
    by_id: dict[str, Scenario] = {}
    for path in scenarios:
        for scenario in load_scenarios(path) if path.is_dir() else [load_scenario(path)]:
            by_id[scenario.id] = scenario
    keep = {c.strip() for c in conditions.split(",") if c.strip()}
    cached = [
        r for r in load_cache(cache).values() if r.scenario_id in by_id and r.condition in keep
    ]
    if not cached:
        console.print("[red]No cached episodes match these scenarios and conditions.[/red]")
        raise typer.Exit(code=1)
    replayed = replay_all(cached, by_id, detection, threshold=threshold)
    models = sorted({f"{r.backend} / {r.model}" for r in cached})
    report = render_replay_report(
        replayed,
        title="Replay of cached agent runs",
        settings={
            "provmcp": __version__,
            "runs": ", ".join(models),
            "conditions replayed": ", ".join(sorted(keep)),
            "detection": _describe_detection(detection, threshold),
            "scenarios": ", ".join(str(p) for p in scenarios),
            "cache": str(cache),
        },
    )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        console.print(f"Report written to [bold]{out}[/bold] ({len(replayed)} episode(s))")
    else:
        console.print(report)


if __name__ == "__main__":
    app()
