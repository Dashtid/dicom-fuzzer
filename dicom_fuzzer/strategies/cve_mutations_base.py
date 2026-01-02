"""CVE Mutation Base Types.

Core types for CVE-inspired mutation strategies.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class CVECategory(Enum):
    """Categories of CVE-inspired mutations."""

    HEAP_OVERFLOW = "heap_overflow"
    STACK_OVERFLOW = "stack_overflow"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    USE_AFTER_FREE = "use_after_free"
    PATH_TRAVERSAL = "path_traversal"
    DENIAL_OF_SERVICE = "denial_of_service"
    POLYGLOT = "polyglot"
    DEEP_NESTING = "deep_nesting"
    MALFORMED_LENGTH = "malformed_length"
    ENCAPSULATED_PIXEL = "encapsulated_pixel"
    JPEG_CODEC = "jpeg_codec"
    CERTIFICATE_VALIDATION = "certificate_validation"
    URL_SCHEME_BYPASS = "url_scheme_bypass"


@dataclass
class CVEMutation:
    """A CVE-inspired mutation.

    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2025-5943")
        category: Type of vulnerability being tested
        description: Human-readable description of the mutation
        mutation_func: Name of the function to apply
        severity: Severity level (critical, high, medium, low)
        target_component: DICOM component targeted (e.g., "pixel_data")

    """

    cve_id: str
    category: CVECategory
    description: str
    mutation_func: str
    severity: str = "high"
    target_component: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve_id,
            "category": self.category.value,
            "description": self.description,
            "severity": self.severity,
            "target_component": self.target_component,
        }
