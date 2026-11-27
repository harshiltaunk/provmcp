"""ProvMCP: runtime detection of cross-server confused-deputy attacks in MCP."""

__version__ = "0.1.0"

from provmcp.provenance import OriginTag, TaggedPayload
from provmcp.registry import ServerRecord, ServerRegistry, TrustClass

__all__ = [
    "OriginTag",
    "TaggedPayload",
    "ServerRecord",
    "ServerRegistry",
    "TrustClass",
    "__version__",
]
