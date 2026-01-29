"""Tests for TLS types and constants module."""

from __future__ import annotations

from dicom_fuzzer.strategies.network.tls.types import (
    COMMON_AE_TITLES,
    SOP_CLASS_UIDS,
    AuthBypassType,
    DICOMTLSFuzzerConfig,
    QueryInjectionType,
    TLSFuzzResult,
    TLSVulnerability,
)


class TestTLSVulnerability:
    """Tests for TLSVulnerability enum."""

    def test_all_values_exist(self) -> None:
        """Verify all TLS vulnerability types exist."""
        expected = [
            "HEARTBLEED",
            "POODLE",
            "BEAST",
            "CRIME",
            "DROWN",
            "ROBOT",
            "RENEGOTIATION",
            "WEAK_DH",
            "NULL_CIPHER",
            "EXPORT_CIPHER",
            "RC4",
            "SWEET32",
        ]
        for name in expected:
            assert hasattr(TLSVulnerability, name)

    def test_enum_values(self) -> None:
        """Verify enum values are strings."""
        assert TLSVulnerability.HEARTBLEED.value == "heartbleed"
        assert TLSVulnerability.POODLE.value == "poodle"
        assert TLSVulnerability.SWEET32.value == "sweet32"

    def test_member_count(self) -> None:
        """Verify the correct number of vulnerability types."""
        assert len(TLSVulnerability) == 12


class TestAuthBypassType:
    """Tests for AuthBypassType enum."""

    def test_all_values_exist(self) -> None:
        """Verify all auth bypass types exist."""
        expected = [
            "DEFAULT_CREDS",
            "BLANK_PASSWORD",
            "AE_TITLE_ENUM",
            "ANONYMOUS_ASSOC",
            "CERT_VALIDATION_BYPASS",
            "DOWNGRADE_ATTACK",
            "SESSION_HIJACK",
            "REPLAY_ATTACK",
        ]
        for name in expected:
            assert hasattr(AuthBypassType, name)

    def test_member_count(self) -> None:
        """Verify the correct number of bypass types."""
        assert len(AuthBypassType) == 8


class TestQueryInjectionType:
    """Tests for QueryInjectionType enum."""

    def test_all_values_exist(self) -> None:
        """Verify all query injection types exist."""
        expected = [
            "WILDCARD_ABUSE",
            "UID_MANIPULATION",
            "DATE_RANGE_OVERFLOW",
            "PATIENT_ID_INJECTION",
            "MODALITY_FILTER_BYPASS",
            "BULK_DATA_EXFIL",
        ]
        for name in expected:
            assert hasattr(QueryInjectionType, name)

    def test_member_count(self) -> None:
        """Verify the correct number of injection types."""
        assert len(QueryInjectionType) == 6


class TestTLSFuzzResult:
    """Tests for TLSFuzzResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        result = TLSFuzzResult(
            test_type="test",
            target="localhost:11112",
        )
        assert result.success is False
        assert result.vulnerability_found is False
        assert result.vulnerability_type == ""
        assert result.details == ""
        assert result.raw_response == b""
        assert result.duration_ms == 0.0
        assert result.severity == "unknown"

    def test_full_initialization(self) -> None:
        """Test full initialization with all values."""
        result = TLSFuzzResult(
            test_type="ssl_version_TLSv1.0",
            target="pacs.example.com:11112",
            success=True,
            vulnerability_found=True,
            vulnerability_type="deprecated_tls",
            details="TLSv1.0 supported",
            raw_response=b"\x16\x03\x01",
            duration_ms=123.45,
            severity="high",
        )
        assert result.test_type == "ssl_version_TLSv1.0"
        assert result.target == "pacs.example.com:11112"
        assert result.success is True
        assert result.vulnerability_found is True
        assert result.vulnerability_type == "deprecated_tls"
        assert result.severity == "high"

    def test_to_dict(self) -> None:
        """Test to_dict method."""
        result = TLSFuzzResult(
            test_type="cipher_test",
            target="localhost:11112",
            success=True,
            vulnerability_found=True,
            vulnerability_type="weak_cipher",
            details="NULL cipher accepted",
            duration_ms=50.0,
            severity="high",
        )
        d = result.to_dict()

        assert d["test_type"] == "cipher_test"
        assert d["target"] == "localhost:11112"
        assert d["success"] is True
        assert d["vulnerability_found"] is True
        assert d["vulnerability_type"] == "weak_cipher"
        assert d["details"] == "NULL cipher accepted"
        assert d["duration_ms"] == 50.0
        assert d["severity"] == "high"
        # raw_response is not included in to_dict
        assert "raw_response" not in d


class TestDICOMTLSFuzzerConfig:
    """Tests for DICOMTLSFuzzerConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = DICOMTLSFuzzerConfig()
        assert config.target_host == "localhost"
        assert config.target_port == 11112
        assert config.timeout == 10.0
        assert config.calling_ae == "FUZZ_SCU"
        assert config.called_ae == "PACS"
        assert config.test_tls_vulns is True
        assert config.test_auth_bypass is True
        assert config.test_query_injection is True
        assert config.use_tls is True
        assert config.verify_certs is True
        assert config.client_cert is None
        assert config.client_key is None
        assert config.ca_bundle is None

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = DICOMTLSFuzzerConfig(
            target_host="pacs.hospital.org",
            target_port=2762,
            timeout=30.0,
            calling_ae="MY_SCU",
            called_ae="HOSPITAL_PACS",
            test_tls_vulns=False,
            use_tls=False,
        )
        assert config.target_host == "pacs.hospital.org"
        assert config.target_port == 2762
        assert config.timeout == 30.0
        assert config.calling_ae == "MY_SCU"
        assert config.called_ae == "HOSPITAL_PACS"
        assert config.test_tls_vulns is False
        assert config.use_tls is False


class TestConstants:
    """Tests for module constants."""

    def test_common_ae_titles(self) -> None:
        """Verify common AE titles list."""
        assert isinstance(COMMON_AE_TITLES, list)
        assert len(COMMON_AE_TITLES) == 17
        assert "STORESCU" in COMMON_AE_TITLES
        assert "PACS" in COMMON_AE_TITLES
        assert "ORTHANC" in COMMON_AE_TITLES

    def test_sop_class_uids(self) -> None:
        """Verify SOP class UIDs dictionary."""
        assert isinstance(SOP_CLASS_UIDS, dict)
        assert len(SOP_CLASS_UIDS) == 10
        assert SOP_CLASS_UIDS["verification"] == "1.2.840.10008.1.1"
        assert SOP_CLASS_UIDS["ct_image_storage"] == "1.2.840.10008.5.1.4.1.1.2"
        assert "patient_root_qr_find" in SOP_CLASS_UIDS


class TestBackwardCompatibility:
    """Test backward compatibility with dicom_tls_fuzzer module."""

    def test_imports_from_dicom_tls_fuzzer(self) -> None:
        """Verify types can be imported from dicom_tls_fuzzer."""
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            COMMON_AE_TITLES as AE_TITLES,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            SOP_CLASS_UIDS as SOP_UIDS,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            AuthBypassType as AuthType,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            DICOMTLSFuzzerConfig as Config,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            QueryInjectionType as InjType,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            TLSFuzzResult as Result,
        )
        from dicom_fuzzer.strategies.network.tls.fuzzer import (
            TLSVulnerability as Vuln,
        )

        # Verify they're the same types
        assert Vuln is TLSVulnerability
        assert AuthType is AuthBypassType
        assert InjType is QueryInjectionType
        assert Result is TLSFuzzResult
        assert Config is DICOMTLSFuzzerConfig
        assert AE_TITLES is COMMON_AE_TITLES
        assert SOP_UIDS is SOP_CLASS_UIDS

    def test_imports_from_core(self) -> None:
        """Verify types can be imported from core __init__."""
        from dicom_fuzzer.core import (
            COMMON_AE_TITLES as AE_TITLES,
        )
        from dicom_fuzzer.core import (
            SOP_CLASS_UIDS as SOP_UIDS,
        )
        from dicom_fuzzer.core import (
            AuthBypassType as AuthType,
        )
        from dicom_fuzzer.core import (
            DICOMTLSFuzzerConfig as Config,
        )
        from dicom_fuzzer.core import (
            QueryInjectionType as InjType,
        )
        from dicom_fuzzer.core import (
            TLSFuzzResult as Result,
        )
        from dicom_fuzzer.core import (
            TLSVulnerability as Vuln,
        )

        assert Vuln is TLSVulnerability
        assert AuthType is AuthBypassType
        assert InjType is QueryInjectionType
        assert Result is TLSFuzzResult
        assert Config is DICOMTLSFuzzerConfig
        assert AE_TITLES is COMMON_AE_TITLES
        assert SOP_UIDS is SOP_CLASS_UIDS
