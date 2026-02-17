"""Shared constants for DICOM fuzzing operations.

AFL-inspired boundary values and fuzzing parameters used across
multiple mutator implementations. These values are proven effective
at triggering boundary conditions and edge cases in parsers.

References:
- AFL whitepaper: https://lcamtuf.coredump.cx/afl/technical_details.txt
- AFL++ documentation: https://aflplus.plus/docs/fuzzing_in_depth/

"""

from __future__ import annotations

from enum import Enum, auto
from typing import Final

# =============================================================================
# Arithmetic Mutation Constants
# =============================================================================

#: Maximum delta for arithmetic mutations (AFL default)
ARITH_MAX: Final[int] = 35

# =============================================================================
# Interesting Values for Boundary Testing
# Based on AFL/AFL++ fuzzer - boundary conditions that often trigger bugs
# =============================================================================

#: 8-bit interesting values (signed, includes INT8_MIN/MAX)
INTERESTING_8: Final[list[int]] = [
    -128,  # INT8_MIN
    -1,  # All bits set
    0,  # Zero
    1,  # One
    16,  # Power of 2
    32,  # Power of 2
    64,  # Power of 2
    100,  # Common boundary
    127,  # INT8_MAX
]

#: 16-bit interesting values (signed, includes INT16_MIN/MAX)
INTERESTING_16: Final[list[int]] = [
    -32768,  # INT16_MIN
    -129,  # Below INT8_MIN
    -1,  # All bits set
    0,  # Zero
    1,  # One
    128,  # Above INT8_MAX
    255,  # UINT8_MAX
    256,  # Above UINT8_MAX
    512,  # Power of 2
    1000,  # Common boundary
    1024,  # Power of 2
    4096,  # Power of 2
    32767,  # INT16_MAX
    65535,  # UINT16_MAX
]

#: 32-bit interesting values (signed, includes INT32_MIN/MAX)
INTERESTING_32: Final[list[int]] = [
    -2147483648,  # INT32_MIN
    -100663046,  # Large negative
    -32769,  # Below INT16_MIN
    -1,  # All bits set
    0,  # Zero
    1,  # One
    32768,  # Above INT16_MAX
    65535,  # UINT16_MAX
    65536,  # Above UINT16_MAX
    100663045,  # Large positive
    2147483647,  # INT32_MAX
    4294967295,  # UINT32_MAX (as signed: -1)
]

# =============================================================================
# Mutation Type Enum
# Unified enum consolidating ByteMutationType, MutationType from multiple modules
# =============================================================================


class MutationType(str, Enum):
    """Mutation type labels used by ByteMutator.

    Inherits from str for easy serialization and logging.
    """

    # AFL-style bit/byte mutations
    BIT_FLIP_1 = "bit_flip_1"
    BIT_FLIP_2 = "bit_flip_2"
    BIT_FLIP_4 = "bit_flip_4"
    BYTE_FLIP_1 = "byte_flip_1"
    BYTE_FLIP_2 = "byte_flip_2"
    BYTE_FLIP_4 = "byte_flip_4"

    # Arithmetic mutations
    ARITH_8 = "arith_8"
    ARITH_16 = "arith_16"
    ARITH_32 = "arith_32"

    # Interesting value mutations
    INTEREST_8 = "interest_8"
    INTEREST_16 = "interest_16"
    INTEREST_32 = "interest_32"

    # Splice
    SPLICE = "splice"


# Backward compatibility alias
ByteMutationType = MutationType


# =============================================================================
# Severity Enum
# Unified severity levels for crashes, issues, and findings
# =============================================================================


class Severity(str, Enum):
    """Unified severity levels for issues, crashes, and findings.

    Consolidates CrashSeverity, BugSeverity, SeverityLevel from multiple modules.
    Inherits from str for easy serialization and logging.

    Severity Levels:
        CRITICAL: Remote code execution, memory corruption, exploitable
        HIGH: Security-relevant, denial of service, data corruption
        MEDIUM: Functional issues, recoverable errors
        LOW: Minor issues, limited impact
        INFO: Informational, non-security
        UNKNOWN: Cannot determine severity
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


# Backward compatibility aliases
CrashSeverity = Severity
BugSeverity = Severity
SeverityLevel = Severity


# =============================================================================
# Coverage Type Enum
# Types of coverage tracking for unified coverage API
# =============================================================================


class CoverageType(str, Enum):
    """Types of coverage tracking.

    Used to categorize different coverage tracking approaches:
        EDGE: Control-flow edge coverage (AFL-style)
        BRANCH: Branch coverage with direction
        PATH: Full execution path coverage
        FUNCTION: Function-level coverage
        LINE: Line-level source coverage
        STATE: Protocol/GUI state coverage
    """

    EDGE = "edge"
    BRANCH = "branch"
    PATH = "path"
    FUNCTION = "function"
    LINE = "line"
    STATE = "state"


# =============================================================================
# DICOM Protocol State Enums
# State machine types for protocol-aware fuzzing
# =============================================================================


class DICOMState(Enum):
    """DICOM protocol states based on DIMSE state machine.

    Represents the states in the DICOM Upper Layer State Machine
    used for state-aware protocol fuzzing.

    States:
        IDLE: No association, waiting for connection
        ASSOCIATION_REQUESTED: A-ASSOCIATE-RQ sent, waiting for response
        ASSOCIATION_ESTABLISHED: Association active, ready for data transfer
        ASSOCIATION_REJECTED: A-ASSOCIATE-RJ received
        DATA_TRANSFER: DIMSE operations in progress
        RELEASE_REQUESTED: A-RELEASE-RQ sent, waiting for response
        RELEASE_COMPLETED: Association released normally
        ABORT: Association aborted (A-ABORT or A-P-ABORT)
        C_*_PENDING: DIMSE C-Service operation in progress
        N_*_PENDING: DIMSE N-Service operation in progress
    """

    IDLE = auto()
    ASSOCIATION_REQUESTED = auto()
    ASSOCIATION_ESTABLISHED = auto()
    ASSOCIATION_REJECTED = auto()
    DATA_TRANSFER = auto()
    RELEASE_REQUESTED = auto()
    RELEASE_COMPLETED = auto()
    ABORT = auto()
    # Extended states for sub-operations
    C_STORE_PENDING = auto()
    C_FIND_PENDING = auto()
    C_MOVE_PENDING = auto()
    C_GET_PENDING = auto()
    N_CREATE_PENDING = auto()
    N_SET_PENDING = auto()
    N_DELETE_PENDING = auto()
    N_ACTION_PENDING = auto()
    N_EVENT_PENDING = auto()


class StateTransitionType(str, Enum):
    """Types of state transitions in protocol fuzzing.

    Categorizes how transitions between states occurred:
        VALID: Normal, expected transition
        INVALID: Unexpected but handled transition
        TIMEOUT: Transition due to timeout
        ERROR: Transition due to error response
        CRASH: Transition due to target crash
    """

    VALID = "valid"
    INVALID = "invalid"
    TIMEOUT = "timeout"
    ERROR = "error"
    CRASH = "crash"
