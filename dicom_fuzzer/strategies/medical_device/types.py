"""Medical Device Security Types.

Enums and dataclasses for medical device security fuzzing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VulnerabilityClass(Enum):
    """Classes of vulnerabilities targeted by mutations."""

    OUT_OF_BOUNDS_WRITE = "oob_write"  # CVE-2025-35975
    OUT_OF_BOUNDS_READ = "oob_read"  # CVE-2025-36521
    STACK_BUFFER_OVERFLOW = "stack_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    NULL_POINTER_DEREF = "null_deref"
    MEMORY_CORRUPTION = "memory_corruption"
    DENIAL_OF_SERVICE = "dos"


class CVEPattern(Enum):
    """Specific CVE patterns to test for."""

    # 2025 CVEs (most recent threats)
    CVE_2025_35975 = "CVE-2025-35975"  # MicroDicom OOB write (CVSS 8.8)
    CVE_2025_36521 = "CVE-2025-36521"  # MicroDicom OOB read (CVSS 8.8)
    CVE_2025_5943 = "CVE-2025-5943"  # MicroDicom additional vuln (June 2025)
    CVE_2025_1001 = "CVE-2025-1001"  # RadiAnt DICOM Viewer MitM (CVSS 5.7)
    CVE_2025_1002 = "CVE-2025-1002"  # MicroDicom cert verification bypass (CVSS 5.7)
    # Historical CVEs (still relevant)
    CVE_2022_2119 = "CVE-2022-2119"  # DICOM server DoS
    CVE_2022_2120 = "CVE-2022-2120"  # DICOM server RCE


@dataclass
class SecurityMutation:
    """Represents a security-focused mutation.

    Attributes:
        name: Name of the mutation
        vulnerability_class: Target vulnerability class
        cve_pattern: Related CVE pattern if any
        tag: DICOM tag to mutate
        original_value: Original value before mutation
        mutated_value: Value after mutation
        description: Description of the mutation
        severity: Severity if exploited (1-10)
        exploitability: Estimated exploitability

    """

    name: str
    vulnerability_class: VulnerabilityClass
    cve_pattern: CVEPattern | None = None
    tag: tuple[int, int] | None = None
    original_value: Any = None
    mutated_value: Any = None
    description: str = ""
    severity: int = 5
    exploitability: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "vulnerability_class": self.vulnerability_class.value,
            "cve_pattern": self.cve_pattern.value if self.cve_pattern else None,
            "tag": f"({self.tag[0]:04X},{self.tag[1]:04X})" if self.tag else None,
            "description": self.description,
            "severity": self.severity,
            "exploitability": self.exploitability,
        }


@dataclass
class MedicalDeviceSecurityConfig:
    """Configuration for medical device security testing.

    Attributes:
        target_cves: List of CVE patterns to test for
        target_vulns: List of vulnerability classes to target
        max_string_length: Maximum string length for overflow tests
        enable_destructive: Enable potentially destructive mutations
        fuzz_pixel_data: Whether to fuzz pixel data structures
        fuzz_sequence_depth: Maximum depth for nested sequence fuzzing

    """

    target_cves: list[CVEPattern] = field(default_factory=lambda: list(CVEPattern))
    target_vulns: list[VulnerabilityClass] = field(
        default_factory=lambda: list(VulnerabilityClass)
    )
    max_string_length: int = 65536
    enable_destructive: bool = True
    fuzz_pixel_data: bool = True
    fuzz_sequence_depth: int = 10


__all__ = [
    "VulnerabilityClass",
    "CVEPattern",
    "SecurityMutation",
    "MedicalDeviceSecurityConfig",
]
