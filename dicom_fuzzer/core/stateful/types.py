"""State Machine Data Types.

Dataclasses for state transitions, results, and fuzzing sequences.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from dicom_fuzzer.core.stateful.enums import (
    AssociationState,
    ProtocolEvent,
    TransitionType,
)


@dataclass
class StateTransition:
    """A state machine transition.

    Attributes:
        from_state: Source state
        to_state: Destination state
        event: Triggering event
        transition_type: Type of transition
        action: Optional action to execute
        description: Human-readable description

    """

    from_state: AssociationState
    to_state: AssociationState
    event: ProtocolEvent
    transition_type: TransitionType = TransitionType.VALID
    action: Callable[[], Any] | None = None
    description: str = ""


@dataclass
class TransitionResult:
    """Result of executing a state transition.

    Attributes:
        success: Whether transition succeeded
        from_state: Starting state
        to_state: Ending state
        event: Event that was sent
        response: Response received (if any)
        error: Error message (if failed)
        duration_ms: Time taken in milliseconds

    """

    success: bool
    from_state: AssociationState
    to_state: AssociationState
    event: ProtocolEvent
    response: bytes | None = None
    error: str | None = None
    duration_ms: float = 0.0


@dataclass
class FuzzSequence:
    """A sequence of events for stateful fuzzing.

    Attributes:
        events: List of events to send
        expected_states: Expected states after each event
        description: Description of what this sequence tests
        attack_type: Type of attack this sequence represents

    """

    events: list[ProtocolEvent]
    expected_states: list[AssociationState] = field(default_factory=list)
    description: str = ""
    attack_type: str = "generic"


__all__ = ["StateTransition", "TransitionResult", "FuzzSequence"]
