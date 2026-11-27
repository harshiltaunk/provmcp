"""Detection strategies for cross-origin propagation."""

from provmcp.detectors.base import Detector
from provmcp.detectors.composite import CompositeDetector
from provmcp.detectors.embedding import EmbeddingDetector
from provmcp.detectors.structured import StructuredFieldDetector
from provmcp.detectors.substring import SubstringDetector

__all__ = [
    "CompositeDetector",
    "Detector",
    "EmbeddingDetector",
    "StructuredFieldDetector",
    "SubstringDetector",
]
