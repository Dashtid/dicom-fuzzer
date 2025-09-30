"""DICOM-Fuzzer: Professional-grade DICOM fuzzing tool for healthcare security testing.

This package provides comprehensive fuzzing capabilities for DICOM implementations,
focusing on identifying vulnerabilities in medical imaging systems, PACS, and
medical device software.

Copyright (c) 2024 David Dashti
License: MIT
"""

__version__ = "1.0.0"
__author__ = "David Dashti"
__email__ = "david@dashti.se"
__license__ = "MIT"

# Security warning for production use
import warnings

warnings.warn(
    "DICOM-Fuzzer generates potentially malicious DICOM data for security testing. "
    "Only use in isolated testing environments with proper authorization.",
    UserWarning,
    stacklevel=2,
)
