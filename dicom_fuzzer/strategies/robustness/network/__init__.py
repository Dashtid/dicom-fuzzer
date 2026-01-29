"""DICOM Network Protocol Fuzzing Package.

Network-level fuzzing for DICOM protocol implementations including:
- PDU (Protocol Data Unit) fuzzing
- TLS security testing
- DIMSE protocol layer fuzzing
- Stateful protocol fuzzing
"""

# Main network fuzzer
from .fuzzer import DICOMNetworkFuzzer

# Base types and config
from .base import (
    DICOMCommand,
    DICOMNetworkConfig,
    FuzzingStrategy,
    NetworkFuzzResult,
    PDUType,
)

# Builder
from .builder import DICOMProtocolBuilder

# Mixins
from .pdu_mixin import PDUFuzzingMixin
from .tls_mixin import TLSFuzzingMixin

# TLS subpackage
from .tls import (
    DICOMAuthTester,
    DICOMTLSFuzzer,
    PACSQueryInjector,
    TLSSecurityTester,
)

# DIMSE subpackage
from .dimse import DIMSECommandBuilder, DIMSEFuzzer

# Stateful subpackage
from .stateful import (
    DICOMStateMachine,
    SequenceGenerator,
    StatefulFuzzer,
)

__all__ = [
    # Main fuzzer
    "DICOMNetworkFuzzer",
    # Types
    "DICOMCommand",
    "PDUType",
    "FuzzingStrategy",
    "NetworkFuzzResult",
    "DICOMNetworkConfig",
    # Builder
    "DICOMProtocolBuilder",
    # Mixins
    "PDUFuzzingMixin",
    "TLSFuzzingMixin",
    # TLS
    "DICOMTLSFuzzer",
    "TLSSecurityTester",
    "DICOMAuthTester",
    "PACSQueryInjector",
    # DIMSE
    "DIMSEFuzzer",
    "DIMSECommandBuilder",
    # Stateful
    "StatefulFuzzer",
    "DICOMStateMachine",
    "SequenceGenerator",
]
