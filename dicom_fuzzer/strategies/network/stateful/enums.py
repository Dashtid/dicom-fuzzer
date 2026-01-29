"""DICOM Protocol State Machine Enums.

Defines the states, events, and transition types for DICOM
association state machine modeling per PS3.8.
"""

from enum import Enum, auto


class AssociationState(Enum):
    """DICOM Association states per PS3.8."""

    # Initial state
    STA1 = auto()  # Idle

    # Association establishment
    STA2 = auto()  # Transport connection open, Awaiting A-ASSOCIATE-RQ
    STA3 = auto()  # Awaiting local A-ASSOCIATE response primitive
    STA4 = auto()  # Awaiting transport connection open to complete
    STA5 = auto()  # Awaiting A-ASSOCIATE-AC or A-ASSOCIATE-RJ

    # Data transfer
    STA6 = auto()  # Association established, ready for data

    # Release collision states
    STA7 = auto()  # Awaiting A-RELEASE-RP
    STA8 = auto()  # Awaiting local A-RELEASE response primitive, release collision
    STA9 = auto()  # Release collision requestor side
    STA10 = auto()  # Release collision acceptor side

    # Abort states
    STA11 = auto()  # Awaiting A-RELEASE-RP, abort sent
    STA12 = auto()  # Release collision, abort received
    STA13 = auto()  # Awaiting transport connection close


class ProtocolEvent(Enum):
    """DICOM Protocol events that trigger state transitions."""

    # Association events
    A_ASSOCIATE_RQ = auto()
    A_ASSOCIATE_AC = auto()
    A_ASSOCIATE_RJ = auto()

    # Release events
    A_RELEASE_RQ = auto()
    A_RELEASE_RP = auto()

    # Abort events
    A_ABORT = auto()
    A_P_ABORT = auto()

    # Data transfer events
    P_DATA_TF = auto()

    # Transport events
    TRANSPORT_CONNECT = auto()
    TRANSPORT_CONNECT_CONFIRM = auto()
    TRANSPORT_CLOSE = auto()

    # Timer events
    ARTIM_TIMEOUT = auto()


class TransitionType(Enum):
    """Type of state transition."""

    VALID = auto()  # Valid protocol transition
    INVALID = auto()  # Protocol violation
    UNEXPECTED = auto()  # Out of order message
    MALFORMED = auto()  # Malformed message
    DUPLICATE = auto()  # Duplicate message


__all__ = ["AssociationState", "ProtocolEvent", "TransitionType"]
