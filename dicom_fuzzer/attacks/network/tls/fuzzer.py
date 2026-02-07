"""DICOM TLS Security Fuzzer.

Comprehensive security testing for DICOM over TLS connections including:
- TLS/SSL configuration fuzzing
- Certificate validation bypass attempts
- Authentication protocol testing
- PACS query injection attacks

Based on:
- DICOM PS3.15 Security Profiles
- OWASP TLS Testing Guide
- NIST SP 800-52 Guidelines for TLS Implementation

Security Research References:
- CVE-2025-xxxx (DICOM TLS implementation flaws)
- "Security Analysis of Medical Imaging Networks" (HIMSS 2024)

This module serves as the main facade, coordinating the modular components:
- tls_types.py: Shared types, enums, and constants
- tls_security_tester.py: TLS version and cipher testing
- dicom_auth_tester.py: DICOM authentication testing
- pacs_query_fuzzer.py: PACS query injection testing
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

# Import PDUType from types.py for backward compatibility
from dicom_fuzzer.core.types import PDUType

from .auth import DICOMAuthTester
from .query import (
    INJECTION_PAYLOADS,
    PACSQueryInjector,
)

# Import component testers
from .security import (
    SSL_VERSIONS,
    WEAK_CIPHERS,
    TLSSecurityTester,
)

# Import and re-export from tls_types for backward compatibility
from .types import (
    COMMON_AE_TITLES,
    SOP_CLASS_UIDS,
    AuthBypassType,
    DICOMTLSFuzzerConfig,
    QueryInjectionType,
    TLSFuzzResult,
    TLSVulnerability,
)

logger = logging.getLogger(__name__)

# Re-export all public symbols for backward compatibility
__all__ = [
    # Types and Enums
    "TLSVulnerability",
    "AuthBypassType",
    "QueryInjectionType",
    "TLSFuzzResult",
    "DICOMTLSFuzzerConfig",
    "PDUType",
    # Constants
    "COMMON_AE_TITLES",
    "SOP_CLASS_UIDS",
    "SSL_VERSIONS",
    "WEAK_CIPHERS",
    "INJECTION_PAYLOADS",
    # Classes
    "TLSSecurityTester",
    "DICOMAuthTester",
    "PACSQueryInjector",
    "DICOMTLSFuzzer",
    # Factory functions
    "create_dicom_tls_fuzzer",
    "quick_scan",
]


# =============================================================================
# Main DICOM TLS Fuzzer
# =============================================================================


class DICOMTLSFuzzer:
    """Main DICOM TLS security fuzzer.

    Coordinates TLS testing, authentication testing, and query injection.

    Usage:
        config = DICOMTLSFuzzerConfig(
            target_host="pacs.example.com",
            target_port=11112,
            use_tls=True
        )
        fuzzer = DICOMTLSFuzzer(config)
        results = fuzzer.run_all_tests()

    """

    def __init__(self, config: DICOMTLSFuzzerConfig | None = None) -> None:
        """Initialize the DICOM TLS fuzzer.

        Args:
            config: Configuration for the fuzzer. Uses defaults if not provided.

        """
        self.config = config or DICOMTLSFuzzerConfig()
        self.tls_tester = TLSSecurityTester(self.config)
        self.auth_tester = DICOMAuthTester(self.config)
        self.query_injector = PACSQueryInjector(self.config)
        self.results: list[TLSFuzzResult] = []

    def run_all_tests(self) -> list[TLSFuzzResult]:
        """Run all security tests.

        Returns:
            List of all test results.

        """
        all_results = []

        logger.info(
            f"Starting DICOM TLS security tests against {self.config.target_host}:{self.config.target_port}"
        )

        # TLS vulnerability tests
        if self.config.test_tls_vulns:
            logger.info("Running TLS version tests...")
            all_results.extend(self.tls_tester.test_ssl_version_support())

            logger.info("Running weak cipher tests...")
            all_results.extend(self.tls_tester.test_weak_ciphers())

            logger.info("Running certificate validation tests...")
            all_results.extend(self.tls_tester.test_certificate_validation())

        # Authentication tests
        if self.config.test_auth_bypass:
            logger.info("Running AE Title enumeration...")
            all_results.extend(self.auth_tester.test_ae_title_enumeration())

            logger.info("Testing anonymous association...")
            all_results.append(self.auth_tester.test_anonymous_association())

        # Query injection tests
        if self.config.test_query_injection:
            logger.info("Running query injection tests...")
            all_results.extend(self.query_injector.test_wildcard_queries())

        self.results = all_results

        # Log summary
        vulns_found = sum(1 for r in all_results if r.vulnerability_found)
        logger.info(
            f"Tests complete: {len(all_results)} tests run, {vulns_found} vulnerabilities found"
        )

        return all_results

    def run_tls_tests(self) -> list[TLSFuzzResult]:
        """Run only TLS security tests.

        Returns:
            List of TLS test results.

        """
        results = []
        results.extend(self.tls_tester.test_ssl_version_support())
        results.extend(self.tls_tester.test_weak_ciphers())
        results.extend(self.tls_tester.test_certificate_validation())
        return results

    def run_auth_tests(self) -> list[TLSFuzzResult]:
        """Run only authentication tests.

        Returns:
            List of authentication test results.

        """
        results = []
        results.extend(self.auth_tester.test_ae_title_enumeration())
        results.append(self.auth_tester.test_anonymous_association())
        return results

    def run_injection_tests(self) -> list[TLSFuzzResult]:
        """Run only query injection tests.

        Returns:
            List of injection test results.

        """
        return self.query_injector.test_wildcard_queries()

    def get_vulnerabilities(self) -> list[TLSFuzzResult]:
        """Get only results that found vulnerabilities.

        Returns:
            List of results where vulnerabilities were found.

        """
        return [r for r in self.results if r.vulnerability_found]

    def get_report(self) -> dict[str, Any]:
        """Generate a summary report.

        Returns:
            Dictionary with test summary and findings.

        """
        vulns = self.get_vulnerabilities()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in self.results:
            severity_counts[result.severity] = (
                severity_counts.get(result.severity, 0) + 1
            )

        return {
            "target": f"{self.config.target_host}:{self.config.target_port}",
            "total_tests": len(self.results),
            "vulnerabilities_found": len(vulns),
            "severity_breakdown": severity_counts,
            "critical_findings": [
                v.to_dict() for v in vulns if v.severity == "critical"
            ],
            "high_findings": [v.to_dict() for v in vulns if v.severity == "high"],
            "all_findings": [v.to_dict() for v in vulns],
        }

    def save_report(self, path: Path) -> None:
        """Save report to JSON file.

        Args:
            path: Path to save the JSON report.

        """
        import json

        report = self.get_report()
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report saved to {path}")


# =============================================================================
# Convenience Functions
# =============================================================================


def create_dicom_tls_fuzzer(
    host: str = "localhost",
    port: int = 11112,
    use_tls: bool = True,
    calling_ae: str = "FUZZ_SCU",
    called_ae: str = "PACS",
) -> DICOMTLSFuzzer:
    """Create a DICOM TLS fuzzer with common configuration.

    Args:
        host: Target host.
        port: Target port.
        use_tls: Use TLS connection.
        calling_ae: Calling AE Title.
        called_ae: Called AE Title.

    Returns:
        Configured DICOMTLSFuzzer instance.

    """
    config = DICOMTLSFuzzerConfig(
        target_host=host,
        target_port=port,
        use_tls=use_tls,
        calling_ae=calling_ae,
        called_ae=called_ae,
    )
    return DICOMTLSFuzzer(config)


def quick_scan(host: str, port: int = 11112) -> dict[str, Any]:
    """Perform a quick security scan of a DICOM server.

    Args:
        host: Target host.
        port: Target port.

    Returns:
        Scan results dictionary.

    """
    fuzzer = create_dicom_tls_fuzzer(host=host, port=port)
    fuzzer.run_all_tests()
    return fuzzer.get_report()
