"""Tests for DICOM TLS Security Fuzzer.

Session 5: Technical debt - unit tests for dicom_tls_fuzzer.py
Target: 0% -> 75-85% coverage
"""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.dicom_tls_fuzzer import (
    COMMON_AE_TITLES,
    SOP_CLASS_UIDS,
    AuthBypassType,
    DICOMAuthTester,
    DICOMTLSFuzzer,
    DICOMTLSFuzzerConfig,
    PACSQueryInjector,
    PDUType,
    QueryInjectionType,
    TLSFuzzResult,
    TLSSecurityTester,
    TLSVulnerability,
    create_dicom_tls_fuzzer,
    quick_scan,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def default_config():
    """Create a default configuration for testing."""
    return DICOMTLSFuzzerConfig(
        target_host="localhost",
        target_port=11112,
        timeout=1.0,
        calling_ae="TEST_SCU",
        called_ae="TEST_SCP",
    )


@pytest.fixture
def mock_socket():
    """Mock socket for network tests."""
    with patch("socket.socket") as mock:
        sock_instance = MagicMock()
        mock.return_value.__enter__.return_value = sock_instance
        mock.return_value = sock_instance
        sock_instance.__enter__ = MagicMock(return_value=sock_instance)
        sock_instance.__exit__ = MagicMock(return_value=False)
        yield sock_instance


@pytest.fixture
def mock_ssl_context():
    """Mock SSL context for TLS tests."""
    with patch("ssl.SSLContext") as mock:
        ctx = MagicMock()
        mock.return_value = ctx
        yield ctx


def make_mock_ssl_socket(cipher_info=None, peer_cert=None, version="TLSv1.2"):
    """Create configurable SSL socket mock."""
    ssl_sock = MagicMock()
    ssl_sock.cipher.return_value = cipher_info or ("AES256-GCM-SHA384", "TLSv1.2", 256)
    ssl_sock.getpeercert.return_value = peer_cert or {}
    ssl_sock.version.return_value = version
    ssl_sock.__enter__ = MagicMock(return_value=ssl_sock)
    ssl_sock.__exit__ = MagicMock(return_value=False)
    return ssl_sock


# =============================================================================
# TestEnums
# =============================================================================


class TestPDUType:
    """Tests for PDUType enum."""

    def test_pdu_type_values(self):
        """Test PDUType enum has correct values."""
        assert PDUType.A_ASSOCIATE_RQ.value == 0x01
        assert PDUType.A_ASSOCIATE_AC.value == 0x02
        assert PDUType.A_ASSOCIATE_RJ.value == 0x03
        assert PDUType.P_DATA_TF.value == 0x04
        assert PDUType.A_RELEASE_RQ.value == 0x05
        assert PDUType.A_RELEASE_RP.value == 0x06
        assert PDUType.A_ABORT.value == 0x07

    def test_pdu_type_count(self):
        """Test PDUType has expected number of values."""
        assert len(PDUType) == 7


class TestTLSVulnerability:
    """Tests for TLSVulnerability enum."""

    def test_tls_vulnerability_values(self):
        """Test TLSVulnerability enum values."""
        assert TLSVulnerability.HEARTBLEED.value == "heartbleed"
        assert TLSVulnerability.POODLE.value == "poodle"
        assert TLSVulnerability.BEAST.value == "beast"
        assert TLSVulnerability.CRIME.value == "crime"
        assert TLSVulnerability.DROWN.value == "drown"
        assert TLSVulnerability.RC4.value == "rc4"

    def test_tls_vulnerability_count(self):
        """Test TLSVulnerability has expected number of values."""
        assert len(TLSVulnerability) == 12


class TestAuthBypassType:
    """Tests for AuthBypassType enum."""

    def test_auth_bypass_type_values(self):
        """Test AuthBypassType enum values."""
        assert AuthBypassType.DEFAULT_CREDS.value == "default_creds"
        assert AuthBypassType.BLANK_PASSWORD.value == "blank_password"
        assert AuthBypassType.AE_TITLE_ENUM.value == "ae_title_enum"
        assert AuthBypassType.ANONYMOUS_ASSOC.value == "anonymous_assoc"

    def test_auth_bypass_type_count(self):
        """Test AuthBypassType has expected number of values."""
        assert len(AuthBypassType) == 8


class TestQueryInjectionType:
    """Tests for QueryInjectionType enum."""

    def test_query_injection_type_values(self):
        """Test QueryInjectionType enum values."""
        assert QueryInjectionType.WILDCARD_ABUSE.value == "wildcard_abuse"
        assert QueryInjectionType.UID_MANIPULATION.value == "uid_manipulation"
        assert QueryInjectionType.PATIENT_ID_INJECTION.value == "patient_id_injection"

    def test_query_injection_type_count(self):
        """Test QueryInjectionType has expected number of values."""
        assert len(QueryInjectionType) == 6


# =============================================================================
# TestDataclasses
# =============================================================================


class TestTLSFuzzResult:
    """Tests for TLSFuzzResult dataclass."""

    def test_tls_fuzz_result_creation(self):
        """Test TLSFuzzResult creation with required fields."""
        result = TLSFuzzResult(
            test_type="ssl_version",
            target="localhost:11112",
        )
        assert result.test_type == "ssl_version"
        assert result.target == "localhost:11112"

    def test_tls_fuzz_result_defaults(self):
        """Test TLSFuzzResult default values."""
        result = TLSFuzzResult(test_type="test", target="host:port")
        assert result.success is False
        assert result.vulnerability_found is False
        assert result.vulnerability_type == ""
        assert result.details == ""
        assert result.raw_response == b""
        assert result.duration_ms == 0.0
        assert result.severity == "unknown"

    def test_tls_fuzz_result_full_creation(self):
        """Test TLSFuzzResult with all fields."""
        result = TLSFuzzResult(
            test_type="cipher_test",
            target="pacs.example.com:11112",
            success=True,
            vulnerability_found=True,
            vulnerability_type="weak_cipher",
            details="RC4 accepted",
            raw_response=b"\x01\x02\x03",
            duration_ms=150.5,
            severity="high",
        )
        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "weak_cipher"
        assert result.severity == "high"

    def test_tls_fuzz_result_to_dict(self):
        """Test TLSFuzzResult.to_dict() method."""
        result = TLSFuzzResult(
            test_type="test",
            target="host:port",
            success=True,
            vulnerability_found=True,
            vulnerability_type="vuln",
            details="detail",
            duration_ms=100.0,
            severity="high",
        )
        d = result.to_dict()
        assert d["test_type"] == "test"
        assert d["target"] == "host:port"
        assert d["success"] is True
        assert d["vulnerability_found"] is True
        assert d["severity"] == "high"
        # raw_response is not in to_dict
        assert "raw_response" not in d

    def test_tls_fuzz_result_to_dict_excludes_raw_response(self):
        """Test that raw_response is not included in to_dict()."""
        result = TLSFuzzResult(
            test_type="test",
            target="host:port",
            raw_response=b"sensitive data",
        )
        d = result.to_dict()
        assert "raw_response" not in d


class TestDICOMTLSFuzzerConfig:
    """Tests for DICOMTLSFuzzerConfig dataclass."""

    def test_config_creation(self):
        """Test DICOMTLSFuzzerConfig creation with defaults."""
        config = DICOMTLSFuzzerConfig()
        assert config.target_host == "localhost"
        assert config.target_port == 11112
        assert config.timeout == 10.0
        assert config.calling_ae == "FUZZ_SCU"
        assert config.called_ae == "PACS"
        assert config.use_tls is True
        assert config.verify_certs is True

    def test_config_custom_values(self):
        """Test DICOMTLSFuzzerConfig with custom values."""
        config = DICOMTLSFuzzerConfig(
            target_host="pacs.example.com",
            target_port=10104,
            timeout=30.0,
            calling_ae="MY_SCU",
            called_ae="MY_SCP",
            use_tls=False,
            verify_certs=False,
        )
        assert config.target_host == "pacs.example.com"
        assert config.target_port == 10104
        assert config.timeout == 30.0
        assert config.use_tls is False
        assert config.verify_certs is False

    def test_config_test_flags(self):
        """Test DICOMTLSFuzzerConfig test flags defaults."""
        config = DICOMTLSFuzzerConfig()
        assert config.test_tls_vulns is True
        assert config.test_auth_bypass is True
        assert config.test_query_injection is True

    def test_config_certificate_paths(self):
        """Test DICOMTLSFuzzerConfig certificate path handling."""
        config = DICOMTLSFuzzerConfig(
            client_cert=Path("/path/to/cert.pem"),
            client_key=Path("/path/to/key.pem"),
            ca_bundle=Path("/path/to/ca.pem"),
        )
        assert config.client_cert == Path("/path/to/cert.pem")
        assert config.client_key == Path("/path/to/key.pem")
        assert config.ca_bundle == Path("/path/to/ca.pem")

    def test_config_certificate_paths_default_none(self):
        """Test DICOMTLSFuzzerConfig certificate paths default to None."""
        config = DICOMTLSFuzzerConfig()
        assert config.client_cert is None
        assert config.client_key is None
        assert config.ca_bundle is None


# =============================================================================
# TestTLSSecurityTester
# =============================================================================


class TestTLSSecurityTester:
    """Tests for TLSSecurityTester class."""

    def test_tls_tester_initialization(self, default_config):
        """Test TLSSecurityTester initialization."""
        tester = TLSSecurityTester(default_config)
        assert tester.config == default_config
        assert tester.results == []

    def test_weak_ciphers_list_exists(self, default_config):
        """Test that WEAK_CIPHERS list is populated."""
        tester = TLSSecurityTester(default_config)
        assert len(tester.WEAK_CIPHERS) > 0
        assert "NULL-MD5" in tester.WEAK_CIPHERS
        assert "RC4-MD5" in tester.WEAK_CIPHERS

    def test_ssl_versions_list_exists(self, default_config):
        """Test that SSL_VERSIONS list is populated."""
        tester = TLSSecurityTester(default_config)
        version_names = [v[0] for v in tester.SSL_VERSIONS]
        assert "TLSv1.2" in version_names
        assert "TLSv1.3" in version_names

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_ssl_version_support_tls12_success(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test TLS 1.2 version support detection."""
        # Setup mocks
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssl_sock = make_mock_ssl_socket(version="TLSv1.2")
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

        tester = TLSSecurityTester(default_config)
        result = tester._test_single_version("TLSv1.2", ssl.TLSVersion.TLSv1_2)

        assert result.test_type == "ssl_version_TLSv1.2"
        assert result.success is True
        assert result.vulnerability_found is False  # TLSv1.2 is not deprecated
        assert result.severity == "info"

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_ssl_version_support_deprecated_version(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test deprecated TLS version detection."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssl_sock = make_mock_ssl_socket(version="TLSv1.0")
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

        tester = TLSSecurityTester(default_config)
        # Mock TLSv1.0 if available
        if hasattr(ssl.TLSVersion, "TLSv1"):
            result = tester._test_single_version("TLSv1.0", ssl.TLSVersion.TLSv1)
            assert result.vulnerability_found is True
            assert result.vulnerability_type == "deprecated_tls"
            assert result.severity == "high"

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_ssl_version_ssl_error(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test SSL error handling during version test."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("Version not supported")

        tester = TLSSecurityTester(default_config)
        result = tester._test_single_version("TLSv1.2", ssl.TLSVersion.TLSv1_2)

        assert result.success is False
        assert result.vulnerability_found is False
        assert "not supported" in result.details

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_ssl_version_connection_error(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test connection error handling during version test."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

        tester = TLSSecurityTester(default_config)
        result = tester._test_single_version("TLSv1.2", ssl.TLSVersion.TLSv1_2)

        assert result.success is False
        assert "Connection" in result.details or "error" in result.details.lower()
        assert result.severity == "error"

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_weak_cipher_accepted(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test weak cipher detection when accepted."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssl_sock = make_mock_ssl_socket(cipher_info=("RC4-MD5", "TLSv1.2", 128))
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

        tester = TLSSecurityTester(default_config)
        result = tester._test_cipher("RC4-MD5")

        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "weak_cipher"
        assert result.severity == "high"

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_weak_cipher_rejected(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test weak cipher rejected by server."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("Cipher not accepted")

        tester = TLSSecurityTester(default_config)
        result = tester._test_cipher("NULL-MD5")

        assert result.success is False
        assert result.vulnerability_found is False
        assert "rejected" in result.details.lower()

    @patch("ssl.SSLContext")
    def test_weak_cipher_not_available_locally(self, mock_ssl_ctx, default_config):
        """Test when cipher is not available in local OpenSSL."""
        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.set_ciphers.side_effect = ssl.SSLError("Cipher not available")

        tester = TLSSecurityTester(default_config)
        result = tester._test_cipher("INVALID-CIPHER")

        assert result.success is False
        assert "not available locally" in result.details

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_certificate_validation_self_signed(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test self-signed certificate detection."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssl_sock = make_mock_ssl_socket()
        mock_ssl_sock.getpeercert.return_value = b"certificate_data"
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

        tester = TLSSecurityTester(default_config)
        result = tester._test_self_signed_cert()

        assert result.test_type == "cert_validation"
        assert result.success is True

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_certificate_validation_error(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test certificate validation error handling."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = Exception("Connection error")

        tester = TLSSecurityTester(default_config)
        result = tester._test_self_signed_cert()

        assert result.success is False
        assert "Error" in result.details

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_hostname_mismatch_rejected(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test hostname mismatch properly rejected."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.CertificateError("Hostname mismatch")

        tester = TLSSecurityTester(default_config)
        result = tester._test_hostname_mismatch()

        assert result.vulnerability_found is False
        assert "working correctly" in result.details.lower()

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_hostname_mismatch_accepted_vulnerability(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test hostname mismatch accepted (vulnerability)."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssl_sock = make_mock_ssl_socket()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

        tester = TLSSecurityTester(default_config)
        result = tester._test_hostname_mismatch()

        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "hostname_mismatch"
        assert result.severity == "high"

    def test_test_ssl_version_support_returns_list(self, default_config):
        """Test that test_ssl_version_support returns a list."""
        tester = TLSSecurityTester(default_config)
        with patch.object(tester, "_test_single_version") as mock_test:
            mock_test.return_value = TLSFuzzResult(test_type="test", target="host:port")
            results = tester.test_ssl_version_support()
            assert isinstance(results, list)

    def test_test_weak_ciphers_returns_list(self, default_config):
        """Test that test_weak_ciphers returns a list."""
        tester = TLSSecurityTester(default_config)
        with patch.object(tester, "_test_cipher") as mock_test:
            mock_test.return_value = TLSFuzzResult(test_type="test", target="host:port")
            results = tester.test_weak_ciphers()
            assert isinstance(results, list)
            assert len(results) == len(tester.WEAK_CIPHERS)

    def test_test_certificate_validation_returns_list(self, default_config):
        """Test that test_certificate_validation returns a list."""
        tester = TLSSecurityTester(default_config)
        with patch.object(tester, "_test_self_signed_cert") as mock1:
            with patch.object(tester, "_test_expired_cert") as mock2:
                with patch.object(tester, "_test_hostname_mismatch") as mock3:
                    mock1.return_value = TLSFuzzResult(test_type="t1", target="h:p")
                    mock2.return_value = TLSFuzzResult(test_type="t2", target="h:p")
                    mock3.return_value = TLSFuzzResult(test_type="t3", target="h:p")
                    results = tester.test_certificate_validation()
                    assert len(results) == 3


# =============================================================================
# TestDICOMAuthTester
# =============================================================================


class TestDICOMAuthTester:
    """Tests for DICOMAuthTester class."""

    def test_auth_tester_initialization(self, default_config):
        """Test DICOMAuthTester initialization."""
        tester = DICOMAuthTester(default_config)
        assert tester.config == default_config
        assert tester.results == []

    def test_build_associate_request_structure(self, default_config):
        """Test _build_associate_request PDU structure."""
        tester = DICOMAuthTester(default_config)
        pdu = tester._build_associate_request(
            calling_ae="CALLER",
            called_ae="CALLEE",
        )

        # PDU should start with A-ASSOCIATE-RQ type
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value
        # Should have reasonable length
        assert len(pdu) > 68  # Minimum fixed fields

    def test_build_associate_request_ae_titles(self, default_config):
        """Test AE titles are properly encoded in PDU."""
        tester = DICOMAuthTester(default_config)
        pdu = tester._build_associate_request(
            calling_ae="TEST_CALLER",
            called_ae="TEST_CALLEE",
        )

        # AE titles should be in the PDU (padded to 16 bytes each)
        pdu_str = pdu.decode("latin-1", errors="replace")
        assert "TEST_CALLER" in pdu_str or b"TEST_CALLER" in pdu
        assert "TEST_CALLEE" in pdu_str or b"TEST_CALLEE" in pdu

    def test_build_associate_request_empty_ae_titles(self, default_config):
        """Test PDU with empty AE titles."""
        tester = DICOMAuthTester(default_config)
        pdu = tester._build_associate_request(
            calling_ae="",
            called_ae="",
        )

        # Should still create valid PDU structure
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value
        assert len(pdu) > 0

    def test_build_associate_request_long_ae_title(self, default_config):
        """Test PDU with AE title longer than 16 chars."""
        tester = DICOMAuthTester(default_config)
        pdu = tester._build_associate_request(
            calling_ae="A" * 20,  # Too long
            called_ae="B" * 20,
        )

        # Should truncate to 16 bytes
        assert len(pdu) > 0
        # PDU should still be valid
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

    @patch("socket.socket")
    def test_ae_title_enumeration_accepted(self, mock_socket_class, default_config):
        """Test AE title enumeration when accepted."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        # Simulate A-ASSOCIATE-AC response
        mock_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_AC.value]) + b"\x00" * 100
        )

        # Disable TLS for this test
        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester._test_ae_title("ORTHANC")

        assert result.test_type == "ae_title_enum"
        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "ae_title_accepted"
        assert "ORTHANC" in result.details

    @patch("socket.socket")
    def test_ae_title_enumeration_rejected(self, mock_socket_class, default_config):
        """Test AE title enumeration when rejected."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        # Simulate A-ASSOCIATE-RJ response with reject reason
        mock_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_RJ.value]) + b"\x00" * 10
        )

        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester._test_ae_title("INVALID_AE")

        assert result.success is True
        assert result.vulnerability_found is False
        assert "rejected" in result.details.lower()

    @patch("socket.socket")
    def test_ae_title_enumeration_connection_error(
        self, mock_socket_class, default_config
    ):
        """Test AE title enumeration with connection error."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester._test_ae_title("TEST")

        assert result.success is False
        assert "Error" in result.details

    @patch("socket.socket")
    def test_anonymous_association_accepted(self, mock_socket_class, default_config):
        """Test anonymous association accepted (vulnerability)."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        # A-ASSOCIATE-AC response
        mock_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_AC.value]) + b"\x00" * 100
        )

        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester.test_anonymous_association()

        assert result.test_type == "anonymous_assoc"
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "anonymous_access"
        assert result.severity == "critical"

    @patch("socket.socket")
    def test_anonymous_association_rejected(self, mock_socket_class, default_config):
        """Test anonymous association properly rejected."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        # A-ASSOCIATE-RJ response
        mock_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_RJ.value]) + b"\x00" * 10
        )

        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester.test_anonymous_association()

        assert result.vulnerability_found is False
        assert "rejected" in result.details.lower()

    @patch("socket.socket")
    def test_anonymous_association_error(self, mock_socket_class, default_config):
        """Test anonymous association with connection error."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect.side_effect = TimeoutError("Timeout")

        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester.test_anonymous_association()

        assert result.success is False
        assert "Error" in result.details

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_ae_title_enumeration_with_tls(
        self, mock_ssl_ctx, mock_socket_class, default_config
    ):
        """Test AE title enumeration over TLS."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_ssl_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.recv.return_value = (
            bytes([PDUType.A_ASSOCIATE_AC.value]) + b"\x00" * 100
        )

        default_config.use_tls = True

        tester = DICOMAuthTester(default_config)
        result = tester._test_ae_title("ORTHANC")

        assert result.success is True
        mock_ctx.wrap_socket.assert_called_once()

    def test_ae_title_enumeration_returns_list(self, default_config):
        """Test that test_ae_title_enumeration returns a list."""
        tester = DICOMAuthTester(default_config)
        with patch.object(tester, "_test_ae_title") as mock_test:
            mock_test.return_value = TLSFuzzResult(
                test_type="ae_title", target="host:port"
            )
            results = tester.test_ae_title_enumeration()
            assert isinstance(results, list)
            assert len(results) == len(COMMON_AE_TITLES)

    @patch("socket.socket")
    def test_ae_title_unknown_response(self, mock_socket_class, default_config):
        """Test AE title enumeration with unknown response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_socket_class.return_value = mock_sock
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        # Unknown PDU type
        mock_sock.recv.return_value = bytes([0xFF]) + b"\x00" * 10

        default_config.use_tls = False

        tester = DICOMAuthTester(default_config)
        result = tester._test_ae_title("TEST")

        assert result.success is True
        assert "Unknown response" in result.details


# =============================================================================
# TestPACSQueryInjector
# =============================================================================


class TestPACSQueryInjector:
    """Tests for PACSQueryInjector class."""

    def test_query_injector_initialization(self, default_config):
        """Test PACSQueryInjector initialization."""
        injector = PACSQueryInjector(default_config)
        assert injector.config == default_config
        assert injector.results == []

    def test_injection_payloads_exist(self, default_config):
        """Test that injection payloads are defined."""
        injector = PACSQueryInjector(default_config)
        assert "patient_id" in injector.INJECTION_PAYLOADS
        assert "patient_name" in injector.INJECTION_PAYLOADS
        assert "study_date" in injector.INJECTION_PAYLOADS
        assert "modality" in injector.INJECTION_PAYLOADS
        assert "study_uid" in injector.INJECTION_PAYLOADS

    def test_patient_id_payloads(self, default_config):
        """Test patient ID injection payloads."""
        injector = PACSQueryInjector(default_config)
        payloads = injector.INJECTION_PAYLOADS["patient_id"]
        assert "*" in payloads
        assert "' OR '1'='1" in payloads

    def test_wildcard_query_detection(self, default_config):
        """Test wildcard query vulnerability detection."""
        injector = PACSQueryInjector(default_config)
        result = injector._test_query_payload("patient_id", "*")

        assert result.vulnerability_found is True
        assert result.vulnerability_type == "query_injection"
        assert result.severity == "high"

    def test_sql_injection_detection(self, default_config):
        """Test SQL injection attempt detection."""
        injector = PACSQueryInjector(default_config)
        result = injector._test_query_payload("patient_name", "' OR '1'='1")

        assert result.vulnerability_found is True
        assert result.vulnerability_type == "query_injection"
        assert result.severity == "high"

    def test_normal_query_not_flagged(self, default_config):
        """Test normal query values not flagged as vulnerable."""
        injector = PACSQueryInjector(default_config)
        result = injector._test_query_payload("patient_id", "12345")

        assert result.vulnerability_found is False

    def test_test_wildcard_queries_returns_list(self, default_config):
        """Test that test_wildcard_queries returns a list."""
        injector = PACSQueryInjector(default_config)
        results = injector.test_wildcard_queries()

        assert isinstance(results, list)
        assert len(results) > 0

    def test_test_wildcard_queries_covers_all_fields(self, default_config):
        """Test that all injection fields are tested."""
        injector = PACSQueryInjector(default_config)
        results = injector.test_wildcard_queries()

        test_types = {r.test_type for r in results}
        assert any("patient_id" in t for t in test_types)
        assert any("patient_name" in t for t in test_types)
        assert any("study_date" in t for t in test_types)

    def test_long_payload_truncated_in_details(self, default_config):
        """Test that long payloads are truncated in details."""
        injector = PACSQueryInjector(default_config)
        long_payload = "A" * 1000
        result = injector._test_query_payload("patient_id", long_payload)

        assert len(result.details) < 200  # Details should be reasonable length
        assert "..." in result.details

    def test_query_payload_basic_flow(self, default_config):
        """Test basic query payload test flow."""
        injector = PACSQueryInjector(default_config)

        # Test a normal, non-injection payload
        result = injector._test_query_payload("patient_id", "NORMAL123")

        assert result is not None
        assert result.test_type == "query_injection_patient_id"
        assert result.success is True
        # Normal payload should not be flagged as vulnerable
        assert result.vulnerability_found is False


# =============================================================================
# TestDICOMTLSFuzzer
# =============================================================================


class TestDICOMTLSFuzzer:
    """Tests for DICOMTLSFuzzer main class."""

    def test_fuzzer_initialization_default(self):
        """Test DICOMTLSFuzzer initialization with defaults."""
        fuzzer = DICOMTLSFuzzer()
        assert fuzzer.config is not None
        assert fuzzer.config.target_host == "localhost"
        assert fuzzer.tls_tester is not None
        assert fuzzer.auth_tester is not None
        assert fuzzer.query_injector is not None
        assert fuzzer.results == []

    def test_fuzzer_initialization_with_config(self, default_config):
        """Test DICOMTLSFuzzer initialization with custom config."""
        fuzzer = DICOMTLSFuzzer(default_config)
        assert fuzzer.config == default_config

    def test_run_all_tests_integrates_all_testers(self, default_config):
        """Test run_all_tests calls all testers."""
        fuzzer = DICOMTLSFuzzer(default_config)

        with patch.object(fuzzer.tls_tester, "test_ssl_version_support") as mock_ssl:
            with patch.object(fuzzer.tls_tester, "test_weak_ciphers") as mock_cipher:
                with patch.object(
                    fuzzer.tls_tester, "test_certificate_validation"
                ) as mock_cert:
                    with patch.object(
                        fuzzer.auth_tester, "test_ae_title_enumeration"
                    ) as mock_ae:
                        with patch.object(
                            fuzzer.auth_tester, "test_anonymous_association"
                        ) as mock_anon:
                            with patch.object(
                                fuzzer.query_injector, "test_wildcard_queries"
                            ) as mock_query:
                                mock_ssl.return_value = [
                                    TLSFuzzResult(test_type="ssl", target="h:p")
                                ]
                                mock_cipher.return_value = [
                                    TLSFuzzResult(test_type="cipher", target="h:p")
                                ]
                                mock_cert.return_value = [
                                    TLSFuzzResult(test_type="cert", target="h:p")
                                ]
                                mock_ae.return_value = [
                                    TLSFuzzResult(test_type="ae", target="h:p")
                                ]
                                mock_anon.return_value = TLSFuzzResult(
                                    test_type="anon", target="h:p"
                                )
                                mock_query.return_value = [
                                    TLSFuzzResult(test_type="query", target="h:p")
                                ]

                                results = fuzzer.run_all_tests()

                                mock_ssl.assert_called_once()
                                mock_cipher.assert_called_once()
                                mock_cert.assert_called_once()
                                mock_ae.assert_called_once()
                                mock_anon.assert_called_once()
                                mock_query.assert_called_once()
                                assert len(results) == 6

    def test_run_all_tests_respects_flags(self, default_config):
        """Test run_all_tests respects test flags."""
        default_config.test_tls_vulns = False
        default_config.test_auth_bypass = False
        default_config.test_query_injection = False

        fuzzer = DICOMTLSFuzzer(default_config)
        results = fuzzer.run_all_tests()

        # Should be empty if all tests disabled
        assert results == []

    def test_run_tls_tests_only(self, default_config):
        """Test run_tls_tests method."""
        fuzzer = DICOMTLSFuzzer(default_config)

        with patch.object(fuzzer.tls_tester, "test_ssl_version_support") as mock_ssl:
            with patch.object(fuzzer.tls_tester, "test_weak_ciphers") as mock_cipher:
                with patch.object(
                    fuzzer.tls_tester, "test_certificate_validation"
                ) as mock_cert:
                    mock_ssl.return_value = []
                    mock_cipher.return_value = []
                    mock_cert.return_value = []

                    fuzzer.run_tls_tests()

                    mock_ssl.assert_called_once()
                    mock_cipher.assert_called_once()
                    mock_cert.assert_called_once()

    def test_run_auth_tests_only(self, default_config):
        """Test run_auth_tests method."""
        fuzzer = DICOMTLSFuzzer(default_config)

        with patch.object(fuzzer.auth_tester, "test_ae_title_enumeration") as mock_ae:
            with patch.object(
                fuzzer.auth_tester, "test_anonymous_association"
            ) as mock_anon:
                mock_ae.return_value = []
                mock_anon.return_value = TLSFuzzResult(test_type="anon", target="h:p")

                results = fuzzer.run_auth_tests()

                mock_ae.assert_called_once()
                mock_anon.assert_called_once()
                assert len(results) == 1  # Only anon result

    def test_run_injection_tests_only(self, default_config):
        """Test run_injection_tests method."""
        fuzzer = DICOMTLSFuzzer(default_config)

        with patch.object(fuzzer.query_injector, "test_wildcard_queries") as mock_query:
            mock_query.return_value = []
            fuzzer.run_injection_tests()
            mock_query.assert_called_once()

    def test_get_vulnerabilities(self, default_config):
        """Test get_vulnerabilities filters correctly."""
        fuzzer = DICOMTLSFuzzer(default_config)
        fuzzer.results = [
            TLSFuzzResult(test_type="test1", target="h:p", vulnerability_found=True),
            TLSFuzzResult(test_type="test2", target="h:p", vulnerability_found=False),
            TLSFuzzResult(test_type="test3", target="h:p", vulnerability_found=True),
        ]

        vulns = fuzzer.get_vulnerabilities()
        assert len(vulns) == 2
        assert all(v.vulnerability_found for v in vulns)

    def test_get_report_structure(self, default_config):
        """Test get_report returns expected structure."""
        fuzzer = DICOMTLSFuzzer(default_config)
        fuzzer.results = [
            TLSFuzzResult(
                test_type="test1",
                target="localhost:11112",
                vulnerability_found=True,
                severity="critical",
            ),
            TLSFuzzResult(
                test_type="test2",
                target="localhost:11112",
                vulnerability_found=True,
                severity="high",
            ),
            TLSFuzzResult(
                test_type="test3",
                target="localhost:11112",
                vulnerability_found=False,
                severity="info",
            ),
        ]

        report = fuzzer.get_report()

        assert "target" in report
        assert "total_tests" in report
        assert "vulnerabilities_found" in report
        assert "severity_breakdown" in report
        assert "critical_findings" in report
        assert "high_findings" in report
        assert "all_findings" in report

        assert report["total_tests"] == 3
        assert report["vulnerabilities_found"] == 2
        assert report["severity_breakdown"]["critical"] == 1
        assert report["severity_breakdown"]["high"] == 1
        assert len(report["critical_findings"]) == 1
        assert len(report["high_findings"]) == 1

    def test_get_report_empty_results(self, default_config):
        """Test get_report with no results."""
        fuzzer = DICOMTLSFuzzer(default_config)
        report = fuzzer.get_report()

        assert report["total_tests"] == 0
        assert report["vulnerabilities_found"] == 0
        assert report["all_findings"] == []

    def test_save_report(self, default_config, tmp_path):
        """Test save_report saves JSON file."""
        fuzzer = DICOMTLSFuzzer(default_config)
        fuzzer.results = [
            TLSFuzzResult(
                test_type="test",
                target="localhost:11112",
                vulnerability_found=True,
                severity="high",
            )
        ]

        report_path = tmp_path / "reports" / "tls_report.json"
        fuzzer.save_report(report_path)

        assert report_path.exists()
        with open(report_path) as f:
            saved_report = json.load(f)
        assert saved_report["total_tests"] == 1
        assert saved_report["vulnerabilities_found"] == 1

    def test_save_report_creates_directory(self, default_config, tmp_path):
        """Test save_report creates parent directories."""
        fuzzer = DICOMTLSFuzzer(default_config)
        fuzzer.results = []

        report_path = tmp_path / "deep" / "nested" / "dir" / "report.json"
        fuzzer.save_report(report_path)

        assert report_path.exists()


# =============================================================================
# TestConvenienceFunctions
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_dicom_tls_fuzzer_defaults(self):
        """Test create_dicom_tls_fuzzer with defaults."""
        fuzzer = create_dicom_tls_fuzzer()
        assert fuzzer.config.target_host == "localhost"
        assert fuzzer.config.target_port == 11112
        assert fuzzer.config.use_tls is True

    def test_create_dicom_tls_fuzzer_custom(self):
        """Test create_dicom_tls_fuzzer with custom values."""
        fuzzer = create_dicom_tls_fuzzer(
            host="pacs.example.com",
            port=10104,
            use_tls=False,
            calling_ae="MY_SCU",
            called_ae="MY_SCP",
        )
        assert fuzzer.config.target_host == "pacs.example.com"
        assert fuzzer.config.target_port == 10104
        assert fuzzer.config.use_tls is False
        assert fuzzer.config.calling_ae == "MY_SCU"
        assert fuzzer.config.called_ae == "MY_SCP"

    def test_quick_scan_returns_report(self):
        """Test quick_scan returns a report dictionary."""
        with patch.object(DICOMTLSFuzzer, "run_all_tests") as mock_run:
            with patch.object(DICOMTLSFuzzer, "get_report") as mock_report:
                mock_run.return_value = []
                mock_report.return_value = {"target": "host:11112", "total_tests": 0}

                result = quick_scan("host")

                assert "target" in result
                mock_run.assert_called_once()
                mock_report.assert_called_once()


# =============================================================================
# TestConstants
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_common_ae_titles_not_empty(self):
        """Test COMMON_AE_TITLES list is populated."""
        assert len(COMMON_AE_TITLES) > 0
        assert "ORTHANC" in COMMON_AE_TITLES
        assert "PACS" in COMMON_AE_TITLES

    def test_sop_class_uids_not_empty(self):
        """Test SOP_CLASS_UIDS dict is populated."""
        assert len(SOP_CLASS_UIDS) > 0
        assert "verification" in SOP_CLASS_UIDS
        assert SOP_CLASS_UIDS["verification"] == "1.2.840.10008.1.1"
