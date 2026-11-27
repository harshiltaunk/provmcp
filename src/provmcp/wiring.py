"""Wiring: build runtime objects from a parsed config.

Keeps the CLI thin. Everything that turns a `ProvMcpConfig` into a live
`Proxy` goes here, so tests call the same code the CLI calls.
"""

from __future__ import annotations

from provmcp.approvals import ApprovalStore
from provmcp.audit import AuditLog
from provmcp.config import ProvMcpConfig
from provmcp.detectors import (
    CompositeDetector,
    Detector,
    EmbeddingDetector,
    StructuredFieldDetector,
    SubstringDetector,
)
from provmcp.inspector import Inspector
from provmcp.policy import PolicyTemplate
from provmcp.provenance import ProvenanceStore
from provmcp.proxy import Proxy, Router
from provmcp.registry import ServerRecord, ServerRegistry
from provmcp.transports import HttpTransport, StdioTransport, Transport


def build_registry(config: ProvMcpConfig) -> ServerRegistry:
    """Turn config server entries into a ServerRegistry."""
    records = [
        ServerRecord(
            server_id=s.id,
            display_name=s.display_name,
            endpoint=_endpoint_description(s.transport, s.command, s.url),
            trust=s.trust,
        )
        for s in config.servers
    ]
    return ServerRegistry(records)


def build_router(config: ProvMcpConfig) -> Router:
    """Build a Router with one Transport per configured server."""
    router = Router()
    for s in config.servers:
        transport: Transport
        if s.transport == "stdio":
            transport = StdioTransport(s.command)
        else:
            assert s.url is not None  # validated in config
            transport = HttpTransport(s.url)
        router.register(s.id, transport)
    return router


def build_detector(config: ProvMcpConfig) -> Detector:
    """Instantiate the detectors listed in [detection]; compose if more than one."""
    det = config.detection
    built: list[Detector] = []
    for name in det.detectors:
        if name == "substring":
            built.append(SubstringDetector(min_run_length=det.substring_min_run))
        elif name == "structured":
            built.append(StructuredFieldDetector(allowlist=det.allowlist))
        else:
            built.append(EmbeddingDetector(threshold=det.embedding_threshold))
    if len(built) == 1:
        return built[0]
    return CompositeDetector(built)


def build_inspector(config: ProvMcpConfig) -> Inspector | None:
    """Build the live Inspector, or None when detection is disabled."""
    if not config.detection.enabled:
        return None
    pairs: dict[tuple[str, str], PolicyTemplate] = {
        (p.source, p.target): p.policy for p in config.proxy.pair_policies
    }
    return Inspector(
        detector=build_detector(config),
        template=config.proxy.policy,
        threshold=config.proxy.detector_threshold,
        pair_policies=pairs,
        approvals=build_approvals(config),
        audit=build_audit(config),
    )


def build_approvals(config: ProvMcpConfig) -> ApprovalStore:
    return ApprovalStore(
        config.resolve_path(config.proxy.approvals_file),
        ttl_seconds=config.proxy.approval_ttl_seconds,
    )


def build_audit(config: ProvMcpConfig) -> AuditLog:
    return AuditLog(config.resolve_path(config.proxy.audit_log))


def build_proxy(config: ProvMcpConfig) -> Proxy:
    """Build a Proxy that is ready to `await router.start_all()` and serve."""
    return Proxy(
        registry=build_registry(config),
        store=ProvenanceStore.empty(),
        router=build_router(config),
        inspector=build_inspector(config),
    )


def _endpoint_description(transport: str, command: list[str], url: str | None) -> str:
    if transport == "stdio":
        return "stdio://" + " ".join(command)
    return url or "http://unknown"
