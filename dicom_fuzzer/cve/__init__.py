"""CVE Replication Module - Deterministic DICOM CVE File Generation.

This module generates DICOM files that replicate known CVEs for security validation.
This is NOT fuzzing - it produces deterministic output for specific vulnerabilities.

Usage:
    from dicom_fuzzer.cve import CVEGenerator, list_cves, get_cve_info

    # List all available CVEs
    cves = list_cves()

    # Get info about a specific CVE
    info = get_cve_info("CVE-2025-5943")

    # Generate all variants for a CVE (some CVEs have multiple attack vectors)
    generator = CVEGenerator()
    files = generator.generate("CVE-2025-5943", template_bytes)

    # Generate files for all known CVEs
    all_files = generator.generate_all(template_bytes)
"""

from .generator import CVEFile, CVEGenerator
from .registry import (
    CVE_REGISTRY,
    CVECategory,
    CVEInfo,
    get_cve_info,
    get_cves_by_category,
    get_cves_by_product,
    list_cves,
)

__all__ = [
    # Main classes
    "CVEFile",
    "CVEGenerator",
    # Registry access
    "CVE_REGISTRY",
    "CVECategory",
    "CVEInfo",
    "list_cves",
    "get_cve_info",
    "get_cves_by_category",
    "get_cves_by_product",
]
