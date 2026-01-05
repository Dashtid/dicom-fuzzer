"""Medical Device Security Package.

Provides security-focused mutation patterns targeting common vulnerabilities
in medical device DICOM implementations.

Example usage:
    from dicom_fuzzer.strategies.medical_device import (
        MedicalDeviceSecurityFuzzer,
        MedicalDeviceSecurityConfig,
    )

    config = MedicalDeviceSecurityConfig()
    fuzzer = MedicalDeviceSecurityFuzzer(config)
    mutations = fuzzer.generate_mutations(dataset)
"""

from dicom_fuzzer.strategies.medical_device.fuzzer import MedicalDeviceSecurityFuzzer
from dicom_fuzzer.strategies.medical_device.types import (
    CVEPattern,
    MedicalDeviceSecurityConfig,
    SecurityMutation,
    VulnerabilityClass,
)

__all__ = [
    # Main class
    "MedicalDeviceSecurityFuzzer",
    # Types
    "VulnerabilityClass",
    "CVEPattern",
    "SecurityMutation",
    "MedicalDeviceSecurityConfig",
]
