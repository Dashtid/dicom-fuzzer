"""Tests for PACS Query Fuzzer module."""

from __future__ import annotations

import pytest

from dicom_fuzzer.strategies.network.tls.query import (
    INJECTION_PAYLOADS,
    PACSQueryInjector,
)
from dicom_fuzzer.strategies.network.tls.types import DICOMTLSFuzzerConfig


class TestConstants:
    """Tests for module constants."""

    def test_injection_payloads_dict(self) -> None:
        """Verify injection payloads dictionary structure."""
        assert isinstance(INJECTION_PAYLOADS, dict)
        assert len(INJECTION_PAYLOADS) == 5

        # Verify all expected fields exist
        expected_fields = [
            "patient_id",
            "patient_name",
            "study_date",
            "modality",
            "study_uid",
        ]
        for field in expected_fields:
            assert field in INJECTION_PAYLOADS
            assert isinstance(INJECTION_PAYLOADS[field], list)
            assert len(INJECTION_PAYLOADS[field]) > 0

    def test_patient_id_payloads(self) -> None:
        """Verify patient_id injection payloads."""
        payloads = INJECTION_PAYLOADS["patient_id"]
        assert "*" in payloads
        assert "' OR '1'='1" in payloads
        assert "../../../etc/passwd" in payloads

    def test_patient_name_payloads(self) -> None:
        """Verify patient_name injection payloads."""
        payloads = INJECTION_PAYLOADS["patient_name"]
        assert "*" in payloads
        assert "<script>alert(1)</script>" in payloads

    def test_study_date_payloads(self) -> None:
        """Verify study_date injection payloads."""
        payloads = INJECTION_PAYLOADS["study_date"]
        assert "19000101-99991231" in payloads
        assert "00000000" in payloads


class TestPACSQueryInjector:
    """Tests for PACSQueryInjector class."""

    @pytest.fixture
    def config(self) -> DICOMTLSFuzzerConfig:
        """Create test configuration."""
        return DICOMTLSFuzzerConfig(
            target_host="localhost",
            target_port=11112,
            timeout=1.0,
        )

    @pytest.fixture
    def injector(self, config: DICOMTLSFuzzerConfig) -> PACSQueryInjector:
        """Create PACS query injector instance."""
        return PACSQueryInjector(config)

    def test_initialization(
        self, injector: PACSQueryInjector, config: DICOMTLSFuzzerConfig
    ) -> None:
        """Test injector initialization."""
        assert injector.config is config
        assert injector.results == []

    def test_class_level_constant(self, injector: PACSQueryInjector) -> None:
        """Verify class-level constant is accessible."""
        assert injector.INJECTION_PAYLOADS == INJECTION_PAYLOADS

    def test_wildcard_queries(self, injector: PACSQueryInjector) -> None:
        """Test wildcard query testing."""
        results = injector.test_wildcard_queries()

        # Calculate expected result count
        total_payloads = sum(len(p) for p in INJECTION_PAYLOADS.values())
        assert len(results) == total_payloads

        # All results should be TLSFuzzResult instances
        for result in results:
            assert result.test_type.startswith("query_injection_")
            assert result.target == "localhost:11112"

    def test_wildcard_detected_as_vulnerability(
        self, injector: PACSQueryInjector
    ) -> None:
        """Test that wildcard payloads are flagged as vulnerabilities."""
        result = injector._test_query_payload("patient_id", "*")

        assert result.vulnerability_found is True
        assert result.vulnerability_type == "query_injection"
        assert result.severity == "high"

    def test_sql_injection_detected_as_vulnerability(
        self, injector: PACSQueryInjector
    ) -> None:
        """Test that SQL injection payloads are flagged as vulnerabilities."""
        result = injector._test_query_payload("patient_name", "' OR '1'='1")

        assert result.vulnerability_found is True
        assert result.vulnerability_type == "query_injection"
        assert result.severity == "high"

    def test_normal_payload_not_vulnerability(
        self, injector: PACSQueryInjector
    ) -> None:
        """Test that normal payloads are not flagged as vulnerabilities."""
        result = injector._test_query_payload("patient_id", "12345")

        assert result.vulnerability_found is False
        assert result.severity == "info"

    def test_long_payload_truncated_in_details(
        self, injector: PACSQueryInjector
    ) -> None:
        """Test that long payloads are truncated in details."""
        long_payload = "A" * 100
        result = injector._test_query_payload("patient_id", long_payload)

        assert "..." in result.details
        assert len(result.details) < len(long_payload) + 50


class TestBackwardCompatibility:
    """Test backward compatibility with dicom_tls_fuzzer module."""

    def test_imports_from_dicom_tls_fuzzer(self) -> None:
        """Verify types can be imported from dicom_tls_fuzzer."""
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            INJECTION_PAYLOADS as PAYLOADS,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            PACSQueryInjector as Injector,
        )

        assert PAYLOADS is INJECTION_PAYLOADS
        assert Injector is PACSQueryInjector

    def test_imports_from_core(self) -> None:
        """Verify types can be imported from core __init__."""
        from dicom_fuzzer.core import (
            INJECTION_PAYLOADS as PAYLOADS,
        )
        from dicom_fuzzer.core import (
            PACSQueryInjector as Injector,
        )

        assert PAYLOADS is INJECTION_PAYLOADS
        assert Injector is PACSQueryInjector
