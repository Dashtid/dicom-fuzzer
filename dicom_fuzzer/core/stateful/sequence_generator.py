"""Sequence Generator for Stateful Fuzzing.

Generates various attack sequences for protocol state machine fuzzing.
"""

import random
from dataclasses import dataclass, field

from dicom_fuzzer.core.stateful.config import StateMachineConfig
from dicom_fuzzer.core.stateful.enums import AssociationState, ProtocolEvent
from dicom_fuzzer.core.stateful.state_machine import DICOMStateMachine
from dicom_fuzzer.core.stateful.types import FuzzSequence


@dataclass
class CoverageStats:
    """Coverage statistics for stateful fuzzing.

    Attributes:
        states_visited: Set of visited states
        transitions_executed: Set of executed transitions
        invalid_transitions_tested: Set of tested invalid transitions
        sequences_executed: Number of sequences executed

    """

    states_visited: set[AssociationState] = field(default_factory=set)
    transitions_executed: set[tuple[AssociationState, ProtocolEvent]] = field(
        default_factory=set
    )
    invalid_transitions_tested: set[tuple[AssociationState, ProtocolEvent]] = field(
        default_factory=set
    )
    sequences_executed: int = 0

    @property
    def state_coverage(self) -> float:
        """Calculate state coverage percentage."""
        total_states = len(AssociationState)
        return len(self.states_visited) / total_states * 100

    @property
    def transition_coverage(self) -> float:
        """Calculate valid transition coverage percentage."""
        # This would need to know total valid transitions
        # For now, use a placeholder
        return len(self.transitions_executed) / 20 * 100  # Approximate


class SequenceGenerator:
    """Generator for fuzzing event sequences."""

    def __init__(
        self,
        state_machine: DICOMStateMachine,
        config: StateMachineConfig | None = None,
    ):
        """Initialize the sequence generator.

        Args:
            state_machine: State machine to use.
            config: Configuration options.

        """
        self.sm = state_machine
        self.config = config or StateMachineConfig()

    def generate_valid_sequence(
        self,
        start_state: AssociationState = AssociationState.STA1,
        target_state: AssociationState | None = None,
        max_length: int = 10,
    ) -> FuzzSequence:
        """Generate a valid event sequence.

        Args:
            start_state: Starting state.
            target_state: Target state to reach (optional).
            max_length: Maximum sequence length.

        Returns:
            Valid event sequence.

        """
        events = []
        states = [start_state]
        current = start_state

        for _ in range(max_length):
            valid_events = self.sm.get_valid_events(current)
            if not valid_events:
                break

            event = random.choice(valid_events)
            events.append(event)

            transition = self.sm.get_transition(current, event)
            if transition:
                current = transition.to_state
                states.append(current)

            if target_state and current == target_state:
                break

        return FuzzSequence(
            events=events,
            expected_states=states,
            description="Valid protocol sequence",
            attack_type="baseline",
        )

    def generate_invalid_transition_sequence(
        self,
        target_state: AssociationState = AssociationState.STA6,
    ) -> FuzzSequence:
        """Generate sequence with invalid transition at end.

        First reaches a valid state, then sends an invalid event.

        Args:
            target_state: State to reach before invalid event.

        Returns:
            Sequence with invalid transition.

        """
        # Get to target state
        valid_seq = self.generate_valid_sequence(
            target_state=target_state,
            max_length=5,
        )

        # Add invalid event
        invalid_events = self.sm.get_invalid_events(target_state)
        if invalid_events:
            invalid_event = random.choice(invalid_events)
            valid_seq.events.append(invalid_event)
            valid_seq.attack_type = "invalid_transition"
            valid_seq.description = (
                f"Invalid {invalid_event.name} in {target_state.name}"
            )

        return valid_seq

    def generate_out_of_order_sequence(self) -> FuzzSequence:
        """Generate out-of-order event sequence.

        Returns:
            Sequence with events in wrong order.

        """
        # Start with valid sequence to STA6
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        # Insert out-of-order events
        out_of_order_events = [
            ProtocolEvent.P_DATA_TF,  # Data before association complete
            ProtocolEvent.A_RELEASE_RQ,
            ProtocolEvent.P_DATA_TF,
        ]

        # Shuffle to create chaos
        all_events = events + out_of_order_events
        random.shuffle(all_events)

        return FuzzSequence(
            events=all_events,
            description="Out-of-order protocol sequence",
            attack_type="out_of_order",
        )

    def generate_state_confusion_sequence(self) -> FuzzSequence:
        """Generate state confusion attack sequence.

        Attempts to confuse the state machine by rapid state changes.

        Returns:
            State confusion sequence.

        """
        events = []

        # Rapid associate/release cycles
        for _ in range(self.config.confusion_depth):
            events.extend(
                [
                    ProtocolEvent.A_ASSOCIATE_RQ,
                    ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
                    ProtocolEvent.A_ASSOCIATE_AC,
                    ProtocolEvent.A_RELEASE_RQ,
                    ProtocolEvent.A_RELEASE_RP,
                ]
            )

        # End with abort
        events.append(ProtocolEvent.A_ABORT)

        return FuzzSequence(
            events=events,
            description="Rapid state changes for confusion",
            attack_type="state_confusion",
        )

    def generate_duplicate_sequence(self) -> FuzzSequence:
        """Generate sequence with duplicate messages.

        Returns:
            Sequence with duplicate events.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.A_ASSOCIATE_RQ,  # Duplicate
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
            ProtocolEvent.A_ASSOCIATE_AC,  # Duplicate
            ProtocolEvent.P_DATA_TF,
            ProtocolEvent.P_DATA_TF,  # Duplicate
            ProtocolEvent.P_DATA_TF,  # Duplicate
        ]

        return FuzzSequence(
            events=events,
            description="Duplicate protocol messages",
            attack_type="duplicate",
        )

    def generate_release_collision_sequence(self) -> FuzzSequence:
        """Generate release collision attack sequence.

        Tests handling of simultaneous release requests.

        Returns:
            Release collision sequence.

        """
        # Get to established state
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        # Trigger release collision
        events.extend(
            [
                ProtocolEvent.A_RELEASE_RQ,  # Our release
                ProtocolEvent.A_RELEASE_RQ,  # Their release (collision)
                ProtocolEvent.A_RELEASE_RP,
                ProtocolEvent.A_RELEASE_RP,
            ]
        )

        return FuzzSequence(
            events=events,
            description="Release collision handling",
            attack_type="release_collision",
        )

    def generate_abort_recovery_sequence(self) -> FuzzSequence:
        """Generate abort and recovery sequence.

        Tests proper cleanup after abort.

        Returns:
            Abort recovery sequence.

        """
        events = [
            # First association
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
            ProtocolEvent.P_DATA_TF,
            # Abort
            ProtocolEvent.A_ABORT,
            ProtocolEvent.TRANSPORT_CLOSE,
            # Second association (tests cleanup)
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        return FuzzSequence(
            events=events,
            description="Abort and new association",
            attack_type="abort_recovery",
        )


__all__ = ["SequenceGenerator", "CoverageStats"]
