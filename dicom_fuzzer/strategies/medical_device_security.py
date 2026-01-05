"""Medical Device Security Patterns for DICOM Fuzzing.

This module provides security-focused mutation patterns targeting common
vulnerabilities in medical device DICOM implementations, based on:

2025 CVEs (Latest Threats):
- CVE-2025-35975: MicroDicom out-of-bounds write (CVSS 8.8)
- CVE-2025-36521: MicroDicom out-of-bounds read (CVSS 8.8)
- CVE-2025-5943: MicroDicom additional vulnerability (June 2025)
- CVE-2025-1001: RadiAnt DICOM Viewer MitM vulnerability (CVSS 5.7)
- CVE-2025-1002: MicroDicom certificate verification bypass (CVSS 5.7)

Historical CVEs (Still Relevant):
- CVE-2022-2119, CVE-2022-2120: DICOM server DoS and RCE vulnerabilities

References:
    - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01
    - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-160-01
    - https://nvd.nist.gov/vuln/detail/cve-2025-35975
    - https://nvd.nist.gov/vuln/detail/CVE-2025-36521
    - https://nvd.nist.gov/vuln/detail/CVE-2025-5943
    - https://digital.nhs.uk/cyber-alerts/2025/cc-4650
    - https://digital.nhs.uk/cyber-alerts/2025/cc-4667

SECURITY NOTE: This module is intended for authorized security testing only.
Use only on systems you own or have explicit permission to test.

Note: This module re-exports from the `medical_device` subpackage for backward
compatibility. New code should import directly from the subpackage modules.

"""

# Re-export all public symbols from the medical_device subpackage
from dicom_fuzzer.strategies.medical_device import (
    CVEPattern,
    MedicalDeviceSecurityConfig,
    MedicalDeviceSecurityFuzzer,
    SecurityMutation,
    VulnerabilityClass,
)

__all__ = [
    "VulnerabilityClass",
    "CVEPattern",
    "SecurityMutation",
    "MedicalDeviceSecurityConfig",
    "MedicalDeviceSecurityFuzzer",
]
