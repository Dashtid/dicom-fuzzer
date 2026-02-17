"""Shared constants for DICOM fuzzing operations."""

from __future__ import annotations

from enum import Enum, auto

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
