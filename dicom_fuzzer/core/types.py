"""DICOM Fuzzer Type Definitions.

Shared type definitions used across the fuzzing framework to avoid circular imports.
Contains protocol enums, severity levels, and other types needed by multiple modules.
"""

from __future__ import annotations

from enum import Enum

# =============================================================================
# Mutation Severity
# =============================================================================


class MutationSeverity(Enum):
    """Mutation severity levels controlling how aggressive mutations are.

    Used to control the intensity of fuzzing operations across the framework.
    """

    MINIMAL = "minimal"  # Very small changes, unlikely to break anything
    MODERATE = "moderate"  # Medium changes, might cause some issues
    AGGRESSIVE = "aggressive"  # Large changes, likely to break things
    EXTREME = "extreme"  # Maximum changes, definitely will break things


# =============================================================================
# DICOM Protocol Enums (Consolidated from network_fuzzer_base.py and dimse_fuzzer.py)
# =============================================================================


class DICOMCommand(Enum):
    """DICOM Command Field values for DIMSE messages.

    These values are used in the Command Field (0000,0100) of DIMSE messages.
    Consolidates duplicate definitions from network_fuzzer_base.py and dimse_fuzzer.py.
    """

    # Composite commands (C-DIMSE)
    C_STORE_RQ = 0x0001
    C_STORE_RSP = 0x8001
    C_GET_RQ = 0x0010
    C_GET_RSP = 0x8010
    C_FIND_RQ = 0x0020
    C_FIND_RSP = 0x8020
    C_MOVE_RQ = 0x0021
    C_MOVE_RSP = 0x8021
    C_ECHO_RQ = 0x0030
    C_ECHO_RSP = 0x8030
    C_CANCEL_RQ = 0x0FFF

    # Normalized commands (N-DIMSE)
    N_EVENT_REPORT_RQ = 0x0100
    N_EVENT_REPORT_RSP = 0x8100
    N_GET_RQ = 0x0110
    N_GET_RSP = 0x8110
    N_SET_RQ = 0x0120
    N_SET_RSP = 0x8120
    N_ACTION_RQ = 0x0130
    N_ACTION_RSP = 0x8130
    N_CREATE_RQ = 0x0140
    N_CREATE_RSP = 0x8140
    N_DELETE_RQ = 0x0150
    N_DELETE_RSP = 0x8150


# Backward compatibility alias for dimse_fuzzer.py
DIMSECommand = DICOMCommand


class PDUType(Enum):
    """DICOM PDU (Protocol Data Unit) types.

    Used in the PDU header to identify the type of protocol data unit.
    Consolidates duplicate definitions from network_fuzzer_base.py and dicom_tls_fuzzer.py.
    """

    A_ASSOCIATE_RQ = 0x01  # Association request
    A_ASSOCIATE_AC = 0x02  # Association accept
    A_ASSOCIATE_RJ = 0x03  # Association reject
    P_DATA_TF = 0x04  # Data transfer
    A_RELEASE_RQ = 0x05  # Release request
    A_RELEASE_RP = 0x06  # Release response
    A_ABORT = 0x07  # Abort
