"""ProvMCP: runtime detection of cross-server confused-deputy attacks in MCP."""

__version__ = "0.2.0"

from provmcp.provenance import OriginTag, TaggedPayload
from provmcp.registry import ServerRecord, ServerRegistry, TrustClass

__all__ = [
    "OriginTag",
    "ServerRecord",
    "ServerRegistry",
    "TaggedPayload",
    "TrustClass",
    "__version__",
]
