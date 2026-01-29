"""Tests for TLS Security Tester module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.strategies.robustness.network.tls.security import (
    SSL_VERSIONS,
    WEAK_CIPHERS,
    TLSSecurityTester,
)
from dicom_fuzzer.strategies.robustness.network.tls.types import DICOMTLSFuzzerConfig


class TestConstants:
    """Tests for module constants."""

    def test_weak_ciphers_list(self) -> None:
        """Verify weak ciphers list."""
        assert isinstance(WEAK_CIPHERS, list)
        assert len(WEAK_CIPHERS) == 10
        assert "NULL-MD5" in WEAK_CIPHERS
        assert "RC4-MD5" in WEAK_CIPHERS
        assert "DES-CBC-SHA" in WEAK_CIPHERS

    def test_ssl_versions_list(self) -> None:
        """Verify SSL versions list."""
        assert isinstance(SSL_VERSIONS, list)
        assert len(SSL_VERSIONS) == 4
        version_names = [v[0] for v in SSL_VERSIONS]
        assert "TLSv1.0" in version_names
        assert "TLSv1.1" in version_names
        assert "TLSv1.2" in version_names
        assert "TLSv1.3" in version_names


class TestTLSSecurityTester:
    """Tests for TLSSecurityTester class."""

    @pytest.fixture
    def config(self) -> DICOMTLSFuzzerConfig:
        """Create test configuration."""
        return DICOMTLSFuzzerConfig(
            target_host="localhost",
            target_port=11112,
            timeout=1.0,
        )

    @pytest.fixture
    def tester(self, config: DICOMTLSFuzzerConfig) -> TLSSecurityTester:
        """Create TLS security tester instance."""
        return TLSSecurityTester(config)

    def test_initialization(
        self, tester: TLSSecurityTester, config: DICOMTLSFuzzerConfig
    ) -> None:
        """Test tester initialization."""
        assert tester.config is config
        assert tester.results == []

    def test_class_level_constants(self, tester: TLSSecurityTester) -> None:
        """Verify class-level constants are accessible."""
        assert tester.WEAK_CIPHERS == WEAK_CIPHERS
        assert tester.SSL_VERSIONS == SSL_VERSIONS

    @patch("dicom_fuzzer.strategies.robustness.network.tls.security.socket.socket")
    def test_ssl_version_connection_error(
        self, mock_socket: MagicMock, tester: TLSSecurityTester
    ) -> None:
        """Test handling of connection errors in version testing."""
        mock_socket.return_value.__enter__.return_value.connect.side_effect = (
            ConnectionRefusedError("Connection refused")
        )

        results = tester.test_ssl_version_support()

        # Should return results with connection errors
        assert len(results) > 0
        for result in results:
            assert result.success is False
            assert "error" in result.severity.lower() or "Connection" in result.details

    @patch("dicom_fuzzer.strategies.robustness.network.tls.security.socket.socket")
    def test_weak_cipher_connection_error(
        self, mock_socket: MagicMock, tester: TLSSecurityTester
    ) -> None:
        """Test handling of connection errors in cipher testing."""
        mock_socket.return_value.__enter__.return_value.connect.side_effect = (
            ConnectionRefusedError("Connection refused")
        )

        results = tester.test_weak_ciphers()

        # Should return results for all weak ciphers
        assert len(results) == len(WEAK_CIPHERS)

    @patch("dicom_fuzzer.strategies.robustness.network.tls.security.socket.socket")
    def test_certificate_validation_tests(
        self, mock_socket: MagicMock, tester: TLSSecurityTester
    ) -> None:
        """Test certificate validation test suite."""
        mock_socket.return_value.__enter__.return_value.connect.side_effect = (
            ConnectionRefusedError("Connection refused")
        )

        results = tester.test_certificate_validation()

        # Should return 3 results (self-signed, expired, hostname mismatch)
        assert len(results) == 3
        test_types = [r.test_type for r in results]
        assert "cert_validation" in test_types
        assert "expired_cert" in test_types
        assert "hostname_mismatch" in test_types


class TestBackwardCompatibility:
    """Test backward compatibility with dicom_tls_fuzzer module."""

    def test_imports_from_dicom_tls_fuzzer(self) -> None:
        """Verify types can be imported from dicom_tls_fuzzer."""
        from dicom_fuzzer.strategies.robustness.network.tls.fuzzer import (
            SSL_VERSIONS as VERSIONS,
        )
        from dicom_fuzzer.strategies.robustness.network.tls.fuzzer import (
            WEAK_CIPHERS as CIPHERS,
        )
        from dicom_fuzzer.strategies.robustness.network.tls.fuzzer import (
            TLSSecurityTester as Tester,
        )

        assert VERSIONS is SSL_VERSIONS
        assert CIPHERS is WEAK_CIPHERS
        assert Tester is TLSSecurityTester

    def test_imports_from_core(self) -> None:
        """Verify types can be imported from core __init__."""
        from dicom_fuzzer.core import (
            SSL_VERSIONS as VERSIONS,
        )
        from dicom_fuzzer.core import (
            WEAK_CIPHERS as CIPHERS,
        )
        from dicom_fuzzer.core import (
            TLSSecurityTester as Tester,
        )

        assert VERSIONS is SSL_VERSIONS
        assert CIPHERS is WEAK_CIPHERS
        assert Tester is TLSSecurityTester
