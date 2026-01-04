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
# Coverage Tracking Constants
# =============================================================================

#: Coverage bitmap size (matches AFL default)
MAP_SIZE: Final[int] = 65536

#: log2(MAP_SIZE) for bit operations
MAP_SIZE_POW2: Final[int] = 16

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
# Unsigned Variants for VR Encoding
# Some DICOM Value Representations reject negative values, use these instead
# =============================================================================

#: 8-bit unsigned interesting values
INTERESTING_8_UNSIGNED: Final[list[int]] = [
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    128,
    255,
]

#: 16-bit unsigned interesting values
INTERESTING_16_UNSIGNED: Final[list[int]] = [
    0,
    1,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
]

#: 32-bit unsigned interesting values
INTERESTING_32_UNSIGNED: Final[list[int]] = [
    0,
    1,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
    4294967295,
]


# =============================================================================
# Mutation Type Enum
# Unified enum consolidating ByteMutationType, MutationType from multiple modules
# =============================================================================


class MutationType(str, Enum):
    """Unified mutation type enum for all fuzzing operations.

    Inherits from str for easy serialization and logging.
    Consolidates definitions from byte_mutator, persistent_fuzzer,
    and coverage_guided_mutator into a single source of truth.

    Categories:
    - AFL-style bit/byte mutations
    - Arithmetic mutations
    - Interesting value mutations
    - Havoc/Splice mutations
    - Extended byte mutations
    - Block mutations
    - DICOM-specific mutations
    - Grammar/Dictionary mutations
    - CVE-based security mutations
    """

    # -------------------------------------------------------------------------
    # AFL-style bit/byte mutations - general (6)
    # -------------------------------------------------------------------------
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    TWO_BYTE_FLIP = "two_byte_flip"
    FOUR_BYTE_FLIP = "four_byte_flip"
    WALKING_BIT = "walking_bit"
    WALKING_BYTE = "walking_byte"

    # -------------------------------------------------------------------------
    # AFL-style bit/byte mutations - specific sizes (6)
    # Used by ByteMutator for granular tracking
    # -------------------------------------------------------------------------
    BIT_FLIP_1 = "bit_flip_1"
    BIT_FLIP_2 = "bit_flip_2"
    BIT_FLIP_4 = "bit_flip_4"
    BYTE_FLIP_1 = "byte_flip_1"
    BYTE_FLIP_2 = "byte_flip_2"
    BYTE_FLIP_4 = "byte_flip_4"

    # -------------------------------------------------------------------------
    # Arithmetic mutations (3)
    # -------------------------------------------------------------------------
    ARITH_8 = "arith_8"
    ARITH_16 = "arith_16"
    ARITH_32 = "arith_32"

    # -------------------------------------------------------------------------
    # Interesting value mutations (3)
    # Standardized naming: INTERESTING_* for new code
    # -------------------------------------------------------------------------
    INTERESTING_8 = "interesting_8"
    INTERESTING_16 = "interesting_16"
    INTERESTING_32 = "interesting_32"

    # -------------------------------------------------------------------------
    # Interesting value mutations - legacy naming (3)
    # Used by ByteMutator for backward compatibility
    # -------------------------------------------------------------------------
    INTEREST_8 = "interest_8"
    INTEREST_16 = "interest_16"
    INTEREST_32 = "interest_32"

    # -------------------------------------------------------------------------
    # Havoc/Splice mutations (2)
    # -------------------------------------------------------------------------
    HAVOC = "havoc"
    SPLICE = "splice"

    # -------------------------------------------------------------------------
    # Extended byte mutations (10)
    # -------------------------------------------------------------------------
    RANDOM_BYTE = "random_byte"
    DELETE_BYTES = "delete_bytes"
    INSERT_BYTES = "insert_bytes"
    CLONE_BYTES = "clone_bytes"
    OVERWRITE_BYTES = "overwrite_bytes"
    SWAP_BYTES = "swap_bytes"
    CROSS_OVER = "cross_over"
    INSERT_CONSTANT = "insert_constant"
    BYTE_INSERT = "byte_insert"
    BYTE_DELETE = "byte_delete"

    # -------------------------------------------------------------------------
    # Arithmetic mutations - directional (3)
    # Used by CoverageGuidedMutator
    # -------------------------------------------------------------------------
    ARITHMETIC_INC = "arithmetic_inc"
    ARITHMETIC_DEC = "arithmetic_dec"
    ARITHMETIC_RANDOM = "arithmetic_random"

    # -------------------------------------------------------------------------
    # Block mutations (6)
    # -------------------------------------------------------------------------
    BLOCK_DELETE = "block_delete"
    BLOCK_INSERT = "block_insert"
    BLOCK_OVERWRITE = "block_overwrite"
    BLOCK_REMOVE = "block_remove"
    BLOCK_DUPLICATE = "block_duplicate"
    BLOCK_SHUFFLE = "block_shuffle"

    # -------------------------------------------------------------------------
    # Interesting value mutations - named (3)
    # Used by CoverageGuidedMutator
    # -------------------------------------------------------------------------
    INTERESTING_BYTES = "interesting_bytes"
    INTERESTING_INTS = "interesting_ints"
    BOUNDARY_VALUES = "boundary_values"

    # -------------------------------------------------------------------------
    # DICOM-specific mutations (14)
    # -------------------------------------------------------------------------
    TAG_MUTATION = "tag_mutation"
    VR_MUTATION = "vr_mutation"
    LENGTH_MUTATION = "length_mutation"
    VALUE_MUTATION = "value_mutation"
    SEQUENCE_MUTATION = "sequence_mutation"
    UID_MUTATION = "uid_mutation"
    TRANSFER_SYNTAX_MUTATION = "transfer_syntax_mutation"
    DICOM_STRUCTURE = "dicom_structure"
    DICOM_VR = "dicom_vr"
    # CoverageGuidedMutator DICOM mutations
    DICOM_TAG_CORRUPT = "dicom_tag_corrupt"
    DICOM_VR_MISMATCH = "dicom_vr_mismatch"
    DICOM_LENGTH_OVERFLOW = "dicom_length_overflow"
    DICOM_SEQUENCE_NEST = "dicom_sequence_nest"
    DICOM_TRANSFER_SYNTAX = "dicom_transfer_syntax"

    # -------------------------------------------------------------------------
    # Grammar/Dictionary mutations (4)
    # -------------------------------------------------------------------------
    DICTIONARY = "dictionary"
    GRAMMAR = "grammar"
    GRAMMAR_MUTATE = "grammar_mutate"
    DICTIONARY_REPLACE = "dictionary_replace"

    # -------------------------------------------------------------------------
    # CVE-based security mutations (17)
    # -------------------------------------------------------------------------
    CVE_INFINITE_LOOP = "cve_infinite_loop"
    CVE_BUFFER_OVERFLOW = "cve_buffer_overflow"
    CVE_INTEGER_OVERFLOW = "cve_integer_overflow"
    CVE_NULL_DEREF = "cve_null_deref"
    CVE_FORMAT_STRING = "cve_format_string"
    CVE_PATH_TRAVERSAL = "cve_path_traversal"
    CVE_MEMORY_EXHAUSTION = "cve_memory_exhaustion"
    CVE_TYPE_CONFUSION = "cve_type_confusion"
    CVE_USE_AFTER_FREE = "cve_use_after_free"
    # CoverageGuidedMutator CVE mutations
    CVE_HEAP_OVERFLOW = "cve_heap_overflow"
    CVE_MALFORMED_LENGTH = "cve_malformed_length"
    CVE_DEEP_NESTING = "cve_deep_nesting"
    CVE_POLYGLOT = "cve_polyglot"
    CVE_ENCAPSULATED_PIXEL = "cve_encapsulated_pixel"
    CVE_JPEG_CODEC = "cve_jpeg_codec"
    CVE_RANDOM = "cve_random"


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


# Severity scores for numeric comparisons (used by semantic_bucketer.py)
SEVERITY_SCORES: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}

# Backward compatibility aliases
CrashSeverity = Severity
BugSeverity = Severity
SeverityLevel = Severity


# =============================================================================
# Response Type Enums
# Unified response types for GUI and protocol monitoring
# =============================================================================


class GUIResponseType(str, Enum):
    """Response types from GUI application monitoring.

    Used to classify responses detected during GUI fuzzing and monitoring.
    """

    NORMAL = "normal"
    ERROR_DIALOG = "error_dialog"
    WARNING_DIALOG = "warning_dialog"
    CRASH = "crash"
    HANG = "hang"
    MEMORY_SPIKE = "memory_spike"
    RENDER_ANOMALY = "render_anomaly"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


class ProtocolResponseType(str, Enum):
    """Response types from DICOM protocol communication.

    Used to classify responses from DICOM network protocol interactions.
    """

    ACCEPT = "accept"
    REJECT = "reject"
    ABORT = "abort"
    DATA = "data"
    RELEASE = "release"
    TIMEOUT = "timeout"
    DISCONNECT = "disconnect"
    MALFORMED = "malformed"
    CRASH = "crash"
    HANG = "hang"
    ERROR = "error"


# Default ResponseType alias for backward compatibility
ResponseType = GUIResponseType


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
