"""DICOM Network Protocol Fuzzing Package.

Network-level fuzzing for DICOM protocol implementations including:
- PDU (Protocol Data Unit) fuzzing
- TLS security testing
- DIMSE protocol layer fuzzing
- Stateful protocol fuzzing
"""

# Main network fuzzer
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

# DIMSE subpackage
from .dimse import DIMSECommandBuilder, DIMSEFuzzer
from .fuzzer import DICOMNetworkFuzzer

# Mixins
from .pdu_mixin import PDUFuzzingMixin

# Stateful subpackage
from .stateful import (
    DICOMStateMachine,
    SequenceGenerator,
    StatefulFuzzer,
)

# TLS subpackage
from .tls import (
    DICOMAuthTester,
    DICOMTLSFuzzer,
    PACSQueryInjector,
    TLSSecurityTester,
)
from .tls_mixin import TLSFuzzingMixin

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
