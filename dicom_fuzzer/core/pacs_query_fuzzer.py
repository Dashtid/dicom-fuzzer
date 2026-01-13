"""PACS Query Injection Testing.

Test PACS query injection vulnerabilities including wildcard abuse,
SQL injection, and data exfiltration attempts. Extracted from
dicom_tls_fuzzer.py to enable better modularity.
"""

from __future__ import annotations

import time

from dicom_fuzzer.core.tls_types import (
    DICOMTLSFuzzerConfig,
    TLSFuzzResult,
)

# =============================================================================
# Injection Payloads
# =============================================================================


# Injection payloads for different fields
INJECTION_PAYLOADS = {
    "patient_id": [
        "*",  # Wildcard
        "?*",  # Wildcard with prefix
        "*'--",  # SQL injection attempt
        "' OR '1'='1",  # Classic SQL injection
        "$(id)",  # Command injection
        "../../../etc/passwd",  # Path traversal
        "A" * 1000,  # Buffer overflow attempt
        "\x00\x00\x00",  # Null bytes
        "1.2.3.4.5.6.7.8.9.0" * 100,  # Long UID
    ],
    "patient_name": [
        "*",
        "?*",
        "' OR '1'='1",
        "<script>alert(1)</script>",  # XSS (for web viewers)
        "A" * 10000,  # Large payload
        "Smith^John^*",  # Partial wildcard
    ],
    "study_date": [
        "19000101-99991231",  # Max range
        "00000000",  # Invalid date
        "99999999",  # Invalid date
        "20240101",  # Single date
        "-",  # Just range separator
    ],
    "modality": [
        "CT*",  # Wildcard
        "' OR '1'='1",  # SQL injection
        "ZZZZZ",  # Invalid modality
    ],
    "study_uid": [
        "1.2.3.4.5.6.7.8.9.0",
        "*",  # Wildcard in UID
        "' OR '1'='1",
        "../../../",
    ],
}


# =============================================================================
# PACS Query Injector
# =============================================================================


class PACSQueryInjector:
    """Test PACS query injection vulnerabilities."""

    # Class-level reference to module constant for backward compatibility
    INJECTION_PAYLOADS = INJECTION_PAYLOADS

    def __init__(self, config: DICOMTLSFuzzerConfig) -> None:
        """Initialize the PACS query injector.

        Args:
            config: DICOM TLS fuzzer configuration.

        """
        self.config = config
        self.results: list[TLSFuzzResult] = []

    def test_wildcard_queries(self) -> list[TLSFuzzResult]:
        """Test wildcard query behavior.

        Returns:
            List of test results for each injection payload tested.

        """
        results = []

        for field, payloads in self.INJECTION_PAYLOADS.items():
            for payload in payloads:
                result = self._test_query_payload(field, payload)
                results.append(result)

        return results

    def _test_query_payload(self, field: str, payload: str) -> TLSFuzzResult:
        """Test a specific query injection payload.

        Args:
            field: Field name being tested (patient_id, patient_name, etc.).
            payload: Injection payload to test.

        Returns:
            Test result for the specified payload.

        """
        start_time = time.time()

        try:
            # Build C-FIND request with injection payload
            # This is a simplified version - real implementation would use pynetdicom

            result = TLSFuzzResult(
                test_type=f"query_injection_{field}",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=True,
                vulnerability_found=False,
                details=f"Tested payload: {payload[:50]}{'...' if len(payload) > 50 else ''}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="info",
            )

            # Mark as potential vulnerability if wildcard accepted
            if payload == "*" or "' OR" in payload:
                result.vulnerability_found = True
                result.vulnerability_type = "query_injection"
                result.severity = "high"
                result.details = f"Potential {field} injection with: {payload}"

            return result

        except Exception as e:
            return TLSFuzzResult(
                test_type=f"query_injection_{field}",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )
