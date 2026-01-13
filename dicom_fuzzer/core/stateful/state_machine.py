"""DICOM Association State Machine.

Models the DICOM Upper Layer state machine as defined in PS3.8,
including valid and invalid transitions for fuzzing.
"""

from dicom_fuzzer.core.stateful.enums import (
    AssociationState,
    ProtocolEvent,
    TransitionType,
)
from dicom_fuzzer.core.stateful.types import StateTransition


class DICOMStateMachine:
    """DICOM Association state machine.

    Models the DICOM Upper Layer state machine as defined in PS3.8,
    including valid and invalid transitions for fuzzing.
    """

    def __init__(self) -> None:
        """Initialize the state machine."""
        self._build_valid_transitions()
        self._build_invalid_transitions()

    def _build_valid_transitions(self) -> None:
        """Build the valid transition table."""
        self.valid_transitions: dict[
            tuple[AssociationState, ProtocolEvent], StateTransition
        ] = {}

        # From STA1 (Idle)
        self._add_valid(
            AssociationState.STA1,
            ProtocolEvent.A_ASSOCIATE_RQ,
            AssociationState.STA4,
            "AE-1: Issue transport connect",
        )
        self._add_valid(
            AssociationState.STA1,
            ProtocolEvent.TRANSPORT_CONNECT,
            AssociationState.STA2,
            "AE-5: Awaiting A-ASSOCIATE-RQ",
        )

        # From STA2 (Awaiting A-ASSOCIATE-RQ)
        self._add_valid(
            AssociationState.STA2,
            ProtocolEvent.A_ASSOCIATE_RQ,
            AssociationState.STA3,
            "AE-6: Issue A-ASSOCIATE indication",
        )

        # From STA3 (Awaiting local response)
        self._add_valid(
            AssociationState.STA3,
            ProtocolEvent.A_ASSOCIATE_AC,
            AssociationState.STA6,
            "AE-7: Send A-ASSOCIATE-AC",
        )
        self._add_valid(
            AssociationState.STA3,
            ProtocolEvent.A_ASSOCIATE_RJ,
            AssociationState.STA1,
            "AE-8: Send A-ASSOCIATE-RJ",
        )

        # From STA4 (Awaiting transport connect)
        self._add_valid(
            AssociationState.STA4,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            AssociationState.STA5,
            "AE-2: Send A-ASSOCIATE-RQ",
        )

        # From STA5 (Awaiting A-ASSOCIATE-AC/RJ)
        self._add_valid(
            AssociationState.STA5,
            ProtocolEvent.A_ASSOCIATE_AC,
            AssociationState.STA6,
            "AE-3: Association established",
        )
        self._add_valid(
            AssociationState.STA5,
            ProtocolEvent.A_ASSOCIATE_RJ,
            AssociationState.STA1,
            "AE-4: Association rejected",
        )

        # From STA6 (Association established)
        self._add_valid(
            AssociationState.STA6,
            ProtocolEvent.P_DATA_TF,
            AssociationState.STA6,
            "DT-1/DT-2: Data transfer",
        )
        self._add_valid(
            AssociationState.STA6,
            ProtocolEvent.A_RELEASE_RQ,
            AssociationState.STA7,
            "AR-1: Send A-RELEASE-RQ",
        )
        self._add_valid(
            AssociationState.STA6,
            ProtocolEvent.A_ABORT,
            AssociationState.STA13,
            "AA-1: Send A-ABORT",
        )

        # From STA7 (Awaiting A-RELEASE-RP)
        self._add_valid(
            AssociationState.STA7,
            ProtocolEvent.A_RELEASE_RP,
            AssociationState.STA1,
            "AR-3: Release complete",
        )
        self._add_valid(
            AssociationState.STA7,
            ProtocolEvent.A_RELEASE_RQ,
            AssociationState.STA9,
            "AR-8: Release collision",
        )

        # From STA9 (Release collision requestor)
        self._add_valid(
            AssociationState.STA9,
            ProtocolEvent.A_RELEASE_RP,
            AssociationState.STA11,
            "AR-9: Send A-RELEASE-RP",
        )

        # From STA13 (Awaiting transport close)
        self._add_valid(
            AssociationState.STA13,
            ProtocolEvent.TRANSPORT_CLOSE,
            AssociationState.STA1,
            "AA-4: Return to idle",
        )

    def _add_valid(
        self,
        from_state: AssociationState,
        event: ProtocolEvent,
        to_state: AssociationState,
        description: str,
    ) -> None:
        """Add a valid transition."""
        key = (from_state, event)
        self.valid_transitions[key] = StateTransition(
            from_state=from_state,
            to_state=to_state,
            event=event,
            transition_type=TransitionType.VALID,
            description=description,
        )

    def _build_invalid_transitions(self) -> None:
        """Build invalid transitions for fuzzing.

        Invalid transitions are those not defined in the protocol,
        which should trigger error handling in the target.
        """
        self.invalid_transitions: dict[
            tuple[AssociationState, ProtocolEvent], StateTransition
        ] = {}

        all_states = list(AssociationState)
        all_events = list(ProtocolEvent)

        # Generate all invalid combinations
        for state in all_states:
            for event in all_events:
                key = (state, event)
                if key not in self.valid_transitions:
                    self.invalid_transitions[key] = StateTransition(
                        from_state=state,
                        to_state=state,  # Invalid transitions don't change state
                        event=event,
                        transition_type=TransitionType.INVALID,
                        description=f"Invalid: {event.name} in {state.name}",
                    )

    def get_valid_events(self, state: AssociationState) -> list[ProtocolEvent]:
        """Get valid events for a state.

        Args:
            state: Current state.

        Returns:
            List of valid events.

        """
        return [event for (s, event) in self.valid_transitions.keys() if s == state]

    def get_invalid_events(self, state: AssociationState) -> list[ProtocolEvent]:
        """Get invalid events for a state.

        Args:
            state: Current state.

        Returns:
            List of invalid events.

        """
        return [event for (s, event) in self.invalid_transitions.keys() if s == state]

    def get_transition(
        self,
        state: AssociationState,
        event: ProtocolEvent,
    ) -> StateTransition | None:
        """Get transition for state and event.

        Args:
            state: Current state.
            event: Event to process.

        Returns:
            Transition if found, None otherwise.

        """
        key = (state, event)
        return self.valid_transitions.get(key) or self.invalid_transitions.get(key)

    def get_all_transitions(self) -> list[StateTransition]:
        """Get all transitions (valid and invalid).

        Returns:
            List of all transitions.

        """
        return list(self.valid_transitions.values()) + list(
            self.invalid_transitions.values()
        )


__all__ = ["DICOMStateMachine"]
