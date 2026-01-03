"""TLS Security Types and Constants.

Shared types for TLS security fuzzing including enums, data classes,
and DICOM protocol constants. Extracted from dicom_tls_fuzzer.py
to enable better modularity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

# =============================================================================
# DICOM Network Protocol Constants
# =============================================================================


# Common DICOM Application Entity Titles
COMMON_AE_TITLES = [
    "STORESCU",
    "STORESCP",
    "DCMQRSCP",
    "ORTHANC",
    "PACS",
    "WORKLIST",
    "MPPS",
    "MWL",
    "ECHOSCU",
    "ECHOSCP",
    "FINDSCU",
    "MOVESCU",
    "DCM4CHEE",
    "OSIRIX",
    "HOROS",
    "CONQUEST",
    "CLEARCANVAS",
]

# Standard DICOM SOP Class UIDs for PACS operations
SOP_CLASS_UIDS = {
    "verification": "1.2.840.10008.1.1",
    "patient_root_qr_find": "1.2.840.10008.5.1.4.1.2.1.1",
    "patient_root_qr_move": "1.2.840.10008.5.1.4.1.2.1.2",
    "patient_root_qr_get": "1.2.840.10008.5.1.4.1.2.1.3",
    "study_root_qr_find": "1.2.840.10008.5.1.4.1.2.2.1",
    "study_root_qr_move": "1.2.840.10008.5.1.4.1.2.2.2",
    "study_root_qr_get": "1.2.840.10008.5.1.4.1.2.2.3",
    "modality_worklist_find": "1.2.840.10008.5.1.4.31",
    "ct_image_storage": "1.2.840.10008.5.1.4.1.1.2",
    "mr_image_storage": "1.2.840.10008.5.1.4.1.1.4",
}


# =============================================================================
# TLS Security Enums
# =============================================================================


class TLSVulnerability(Enum):
    """Known TLS vulnerability types to test."""

    HEARTBLEED = "heartbleed"  # CVE-2014-0160
    POODLE = "poodle"  # CVE-2014-3566
    BEAST = "beast"  # CVE-2011-3389
    CRIME = "crime"  # CVE-2012-4929
    DROWN = "drown"  # CVE-2016-0800
    ROBOT = "robot"  # CVE-2017-13099
    RENEGOTIATION = "renegotiation"  # CVE-2009-3555
    WEAK_DH = "weak_dh"  # Weak Diffie-Hellman
    NULL_CIPHER = "null_cipher"  # NULL cipher suite
    EXPORT_CIPHER = "export_cipher"  # Export-grade ciphers
    RC4 = "rc4"  # RC4 weaknesses
    SWEET32 = "sweet32"  # CVE-2016-2183


class AuthBypassType(Enum):
    """Authentication bypass attack types."""

    DEFAULT_CREDS = "default_creds"
    BLANK_PASSWORD = "blank_password"  # nosec B105 - enum value, not a password
    AE_TITLE_ENUM = "ae_title_enum"
    ANONYMOUS_ASSOC = "anonymous_assoc"
    CERT_VALIDATION_BYPASS = "cert_validation_bypass"
    DOWNGRADE_ATTACK = "downgrade_attack"
    SESSION_HIJACK = "session_hijack"
    REPLAY_ATTACK = "replay_attack"


class QueryInjectionType(Enum):
    """PACS query injection types."""

    WILDCARD_ABUSE = "wildcard_abuse"
    UID_MANIPULATION = "uid_manipulation"
    DATE_RANGE_OVERFLOW = "date_range_overflow"
    PATIENT_ID_INJECTION = "patient_id_injection"
    MODALITY_FILTER_BYPASS = "modality_filter_bypass"
    BULK_DATA_EXFIL = "bulk_data_exfil"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class TLSFuzzResult:
    """Result of a TLS fuzzing attempt.

    Attributes:
        test_type: Type of test performed
        target: Target host:port
        success: Whether connection succeeded
        vulnerability_found: Whether a vulnerability was found
        vulnerability_type: Type of vulnerability if found
        details: Additional details
        raw_response: Raw response data if any
        duration_ms: Test duration in milliseconds

    """

    test_type: str
    target: str
    success: bool = False
    vulnerability_found: bool = False
    vulnerability_type: str = ""
    details: str = ""
    raw_response: bytes = b""
    duration_ms: float = 0.0
    severity: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_type": self.test_type,
            "target": self.target,
            "success": self.success,
            "vulnerability_found": self.vulnerability_found,
            "vulnerability_type": self.vulnerability_type,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "severity": self.severity,
        }


@dataclass
class DICOMTLSFuzzerConfig:
    """Configuration for DICOM TLS fuzzer.

    Attributes:
        target_host: Target DICOM server hostname
        target_port: Target port (default 11112 for DICOM TLS)
        timeout: Connection timeout in seconds
        calling_ae: Calling AE Title
        called_ae: Called AE Title (target)
        test_tls_vulns: Test for TLS vulnerabilities
        test_auth_bypass: Test authentication bypass
        test_query_injection: Test PACS query injection
        use_tls: Use TLS connection
        verify_certs: Verify TLS certificates
        client_cert: Path to client certificate
        client_key: Path to client private key
        ca_bundle: Path to CA certificate bundle

    """

    target_host: str = "localhost"
    target_port: int = 11112
    timeout: float = 10.0
    calling_ae: str = "FUZZ_SCU"
    called_ae: str = "PACS"
    test_tls_vulns: bool = True
    test_auth_bypass: bool = True
    test_query_injection: bool = True
    use_tls: bool = True
    verify_certs: bool = True
    client_cert: Path | None = None
    client_key: Path | None = None
    ca_bundle: Path | None = None
