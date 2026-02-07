"""DICOM TLS Security Testing Package.

Comprehensive TLS security testing for DICOM endpoints including:
- TLS version and cipher testing
- Certificate validation bypass
- Authentication testing
- PACS query injection
"""

from .auth import DICOMAuthTester
from .fuzzer import DICOMTLSFuzzer
from .query import INJECTION_PAYLOADS, PACSQueryInjector
from .security import SSL_VERSIONS, WEAK_CIPHERS, TLSSecurityTester
from .types import (
    COMMON_AE_TITLES,
    SOP_CLASS_UIDS,
    AuthBypassType,
    DICOMTLSFuzzerConfig,
    QueryInjectionType,
    TLSFuzzResult,
    TLSVulnerability,
)

__all__ = [
    # Main fuzzer
    "DICOMTLSFuzzer",
    # Testers
    "TLSSecurityTester",
    "DICOMAuthTester",
    "PACSQueryInjector",
    # Types
    "TLSVulnerability",
    "AuthBypassType",
    "QueryInjectionType",
    "TLSFuzzResult",
    "DICOMTLSFuzzerConfig",
    # Constants
    "COMMON_AE_TITLES",
    "SOP_CLASS_UIDS",
    "SSL_VERSIONS",
    "WEAK_CIPHERS",
    "INJECTION_PAYLOADS",
]
