"""Tests for DICOM Authentication Tester module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.dicom_auth_tester import DICOMAuthTester
from dicom_fuzzer.core.tls_types import (
    COMMON_AE_TITLES,
    DICOMTLSFuzzerConfig,
)
from dicom_fuzzer.core.types import PDUType


class TestDICOMAuthTester:
    """Tests for DICOMAuthTester class."""

    @pytest.fixture
    def config(self) -> DICOMTLSFuzzerConfig:
        """Create test configuration."""
        return DICOMTLSFuzzerConfig(
            target_host="localhost",
            target_port=11112,
            timeout=1.0,
            calling_ae="TEST_SCU",
            called_ae="TEST_SCP",
            use_tls=False,
        )

    @pytest.fixture
    def tester(self, config: DICOMTLSFuzzerConfig) -> DICOMAuthTester:
        """Create DICOM auth tester instance."""
        return DICOMAuthTester(config)

    def test_initialization(
        self, tester: DICOMAuthTester, config: DICOMTLSFuzzerConfig
    ) -> None:
        """Test tester initialization."""
        assert tester.config is config
        assert tester.results == []

    def test_build_associate_request(self, tester: DICOMAuthTester) -> None:
        """Test A-ASSOCIATE-RQ PDU building."""
        pdu = tester._build_associate_request(
            calling_ae="CALLING",
            called_ae="CALLED",
        )

        # Verify PDU structure
        assert isinstance(pdu, bytes)
        assert len(pdu) > 68  # Minimum PDU size

        # First byte should be PDU type (A-ASSOCIATE-RQ = 0x01)
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

    def test_build_associate_request_custom_syntax(
        self, tester: DICOMAuthTester
    ) -> None:
        """Test A-ASSOCIATE-RQ with custom abstract syntax."""
        pdu = tester._build_associate_request(
            calling_ae="SCU",
            called_ae="SCP",
            abstract_syntax="1.2.840.10008.5.1.4.1.1.2",  # CT Storage
        )

        assert isinstance(pdu, bytes)
        # Verify abstract syntax is included (encoded as ASCII)
        assert b"1.2.840.10008.5.1.4.1.1.2" in pdu

    @patch("dicom_fuzzer.core.dicom_auth_tester.socket.socket")
    def test_ae_title_enumeration_connection_error(
        self, mock_socket: MagicMock, tester: DICOMAuthTester
    ) -> None:
        """Test handling of connection errors in AE title enumeration."""
        mock_socket.return_value.__enter__.return_value.connect.side_effect = (
            ConnectionRefusedError("Connection refused")
        )

        results = tester.test_ae_title_enumeration()

        # Should return results for all common AE titles
        assert len(results) == len(COMMON_AE_TITLES)
        for result in results:
            assert result.success is False
            assert "Error" in result.details

    @patch("dicom_fuzzer.core.dicom_auth_tester.socket.socket")
    def test_anonymous_association_connection_error(
        self, mock_socket: MagicMock, tester: DICOMAuthTester
    ) -> None:
        """Test handling of connection errors in anonymous association test."""
        mock_socket.return_value.__enter__.return_value.connect.side_effect = (
            ConnectionRefusedError("Connection refused")
        )

        result = tester.test_anonymous_association()

        assert result.test_type == "anonymous_assoc"
        assert result.success is False
        assert "Error" in result.details

    @patch("dicom_fuzzer.core.dicom_auth_tester.socket.socket")
    def test_ae_title_accepted_response(
        self, mock_socket: MagicMock, tester: DICOMAuthTester
    ) -> None:
        """Test detection of accepted AE title."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_AC.value]) + b"\x00" * 100
        )
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = tester._test_ae_title("PACS")

        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "ae_title_accepted"
        assert "PACS" in result.details

    @patch("dicom_fuzzer.core.dicom_auth_tester.socket.socket")
    def test_ae_title_rejected_response(
        self, mock_socket: MagicMock, tester: DICOMAuthTester
    ) -> None:
        """Test detection of rejected AE title."""
        mock_sock = MagicMock()
        # A-ASSOCIATE-RJ PDU with rejection reason
        response = bytes([PDUType.A_ASSOCIATE_RJ.value]) + b"\x00" * 6 + b"\x02"
        mock_sock.recv.return_value = response
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = tester._test_ae_title("INVALID")

        assert result.success is True
        assert result.vulnerability_found is False
        assert "rejected" in result.details

    @patch("dicom_fuzzer.core.dicom_auth_tester.socket.socket")
    def test_anonymous_association_accepted(
        self, mock_socket: MagicMock, tester: DICOMAuthTester
    ) -> None:
        """Test detection of anonymous association acceptance."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_AC.value]) + b"\x00" * 100
        )
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = tester.test_anonymous_association()

        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "anonymous_access"
        assert result.severity == "critical"


class TestBackwardCompatibility:
    """Test backward compatibility with dicom_tls_fuzzer module."""

    def test_imports_from_dicom_tls_fuzzer(self) -> None:
        """Verify DICOMAuthTester can be imported from dicom_tls_fuzzer."""
        from dicom_fuzzer.core.dicom_tls_fuzzer import DICOMAuthTester as Tester

        assert Tester is DICOMAuthTester

    def test_imports_from_core(self) -> None:
        """Verify DICOMAuthTester can be imported from core __init__."""
        from dicom_fuzzer.core import DICOMAuthTester as Tester

        assert Tester is DICOMAuthTester
