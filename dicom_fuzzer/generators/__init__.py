"""DICOM Security Sample Generators.

This module provides generators for creating DICOM security test samples,
including CVE reproduction samples, preamble attacks, parser stress tests,
compliance violations, and security detection/scanning utilities.
"""

from __future__ import annotations

from typing import Any

# Lazy imports to avoid circular dependencies
__all__ = [
    "CVESampleGenerator",
    "CVE_DATABASE",
    "PreambleAttackGenerator",
    "ParserStressGenerator",
    "ComplianceViolationGenerator",
]


def __getattr__(name: str) -> Any:
    """Lazy import generators to avoid import errors if dependencies missing."""
    if name == "CVESampleGenerator":
        from dicom_fuzzer.generators.cve_reproductions.generator import (
            CVESampleGenerator,
        )

        return CVESampleGenerator
    if name == "CVE_DATABASE":
        from dicom_fuzzer.generators.cve_reproductions.generator import CVE_DATABASE

        return CVE_DATABASE
    if name == "PreambleAttackGenerator":
        from dicom_fuzzer.generators.preamble_attacks.generator import (
            PreambleAttackGenerator,
        )

        return PreambleAttackGenerator
    if name == "ParserStressGenerator":
        from dicom_fuzzer.generators.parser_stress.generator import (
            ParserStressGenerator,
        )

        return ParserStressGenerator
    if name == "ComplianceViolationGenerator":
        from dicom_fuzzer.generators.compliance_violations.generator import (
            ComplianceViolationGenerator,
        )

        return ComplianceViolationGenerator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
