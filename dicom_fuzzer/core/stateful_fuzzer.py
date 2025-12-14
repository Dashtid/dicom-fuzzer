"""Stateful Protocol Fuzzer for DICOM Network Services.

This module implements state machine-based fuzzing for DICOM protocols,
enabling discovery of state-dependent vulnerabilities and protocol
implementation errors.

Key concepts:
- Protocol state machine modeling
- Valid and invalid state transitions
- Out-of-order message attacks
- State confusion attacks
- Association state tracking
"""

import logging
import random
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


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
    action: Callable | None = None
    description: str = ""


@dataclass
class StateMachineConfig:
    """Configuration for the state machine."""

    # Fuzzing parameters
    probability_invalid_transition: float = 0.2
    probability_out_of_order: float = 0.1
    probability_duplicate: float = 0.05

    # Timing attacks
    enable_timing_attacks: bool = True
    min_delay_ms: int = 0
    max_delay_ms: int = 5000

    # State confusion
    enable_state_confusion: bool = True
    confusion_depth: int = 3

    # Coverage tracking
    track_state_coverage: bool = True
    track_transition_coverage: bool = True


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


class StatefulFuzzer:
    """High-level stateful protocol fuzzer.

    Coordinates state machine-based fuzzing with various
    attack strategies and coverage tracking.
    """

    def __init__(self, config: StateMachineConfig | None = None):
        """Initialize the stateful fuzzer.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or StateMachineConfig()
        self.state_machine = DICOMStateMachine()
        self.sequence_gen = SequenceGenerator(self.state_machine, self.config)
        self.coverage = CoverageStats()

        # Current state tracking
        self.current_state = AssociationState.STA1

    def reset(self) -> None:
        """Reset the fuzzer to initial state."""
        self.current_state = AssociationState.STA1

    def generate_fuzz_sequences(
        self,
        count: int = 100,
    ) -> Generator[FuzzSequence, None, None]:
        """Generate a collection of fuzz sequences.

        Args:
            count: Number of sequences to generate.

        Yields:
            Fuzz sequences.

        """
        generators = [
            self.sequence_gen.generate_valid_sequence,
            self.sequence_gen.generate_invalid_transition_sequence,
            self.sequence_gen.generate_out_of_order_sequence,
            self.sequence_gen.generate_state_confusion_sequence,
            self.sequence_gen.generate_duplicate_sequence,
            self.sequence_gen.generate_release_collision_sequence,
            self.sequence_gen.generate_abort_recovery_sequence,
        ]

        for _ in range(count):
            gen = random.choice(generators)
            yield gen()  # type: ignore[operator]

    def execute_event(
        self,
        event: ProtocolEvent,
        message_generator: Callable[[ProtocolEvent], bytes] | None = None,
    ) -> TransitionResult:
        """Execute a single protocol event.

        Args:
            event: Event to execute.
            message_generator: Optional function to generate message bytes.

        Returns:
            Result of the transition.

        """
        start_time = time.time()
        from_state = self.current_state

        # Get transition
        transition = self.state_machine.get_transition(from_state, event)

        if transition is None:
            return TransitionResult(
                success=False,
                from_state=from_state,
                to_state=from_state,
                event=event,
                error="No transition defined",
                duration_ms=(time.time() - start_time) * 1000,
            )

        # Update coverage
        self.coverage.states_visited.add(from_state)
        if transition.transition_type == TransitionType.VALID:
            self.coverage.transitions_executed.add((from_state, event))
        else:
            self.coverage.invalid_transitions_tested.add((from_state, event))

        # Update state for valid transitions
        if transition.transition_type == TransitionType.VALID:
            self.current_state = transition.to_state
            self.coverage.states_visited.add(transition.to_state)

        return TransitionResult(
            success=True,
            from_state=from_state,
            to_state=transition.to_state,
            event=event,
            duration_ms=(time.time() - start_time) * 1000,
        )

    def execute_sequence(
        self,
        sequence: FuzzSequence,
        message_generator: Callable[[ProtocolEvent], bytes] | None = None,
        delay_between_events_ms: int = 0,
    ) -> list[TransitionResult]:
        """Execute a sequence of events.

        Args:
            sequence: Sequence to execute.
            message_generator: Optional message generator.
            delay_between_events_ms: Delay between events.

        Returns:
            List of results for each event.

        """
        self.reset()
        results = []

        for event in sequence.events:
            result = self.execute_event(event, message_generator)
            results.append(result)

            if delay_between_events_ms > 0:
                time.sleep(delay_between_events_ms / 1000)

        self.coverage.sequences_executed += 1
        return results

    def get_coverage_stats(self) -> dict:
        """Get current coverage statistics.

        Returns:
            Dictionary with coverage information.

        """
        return {
            "states_visited": len(self.coverage.states_visited),
            "total_states": len(AssociationState),
            "state_coverage_pct": self.coverage.state_coverage,
            "transitions_executed": len(self.coverage.transitions_executed),
            "invalid_transitions_tested": len(self.coverage.invalid_transitions_tested),
            "sequences_executed": self.coverage.sequences_executed,
        }

    def get_untested_transitions(self) -> list[tuple[AssociationState, ProtocolEvent]]:
        """Get transitions that haven't been tested.

        Returns:
            List of untested (state, event) pairs.

        """
        all_valid = set(self.state_machine.valid_transitions.keys())
        tested = self.coverage.transitions_executed
        return list(all_valid - tested)

    def generate_targeted_sequences(
        self,
        target_transitions: list[tuple[AssociationState, ProtocolEvent]],
    ) -> Generator[FuzzSequence, None, None]:
        """Generate sequences targeting specific transitions.

        Args:
            target_transitions: Transitions to target.

        Yields:
            Targeted fuzz sequences.

        """
        for from_state, event in target_transitions:
            # Generate sequence that reaches the target state
            preamble = self.sequence_gen.generate_valid_sequence(
                target_state=from_state,
                max_length=5,
            )

            # Add the target event
            preamble.events.append(event)
            preamble.description = f"Target: {event.name} in {from_state.name}"
            preamble.attack_type = "targeted"

            yield preamble


class TimingAttackGenerator:
    """Generator for timing-based attacks."""

    def __init__(self, config: StateMachineConfig | None = None):
        """Initialize the timing attack generator.

        Args:
            config: Configuration options.

        """
        self.config = config or StateMachineConfig()

    def generate_timeout_attack(self) -> FuzzSequence:
        """Generate timeout attack sequence.

        Sends partial association then waits for timeout.

        Returns:
            Timeout attack sequence.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            # No response - wait for ARTIM timeout
        ]

        return FuzzSequence(
            events=events,
            description="ARTIM timeout attack",
            attack_type="timeout",
        )

    def generate_slow_data_attack(self) -> FuzzSequence:
        """Generate slow data transfer attack.

        Sends data very slowly to test timeout handling.

        Returns:
            Slow data sequence.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        # Many small data transfers
        for _ in range(100):
            events.append(ProtocolEvent.P_DATA_TF)

        return FuzzSequence(
            events=events,
            description="Slow/fragmented data transfer",
            attack_type="slow_data",
        )

    def generate_rapid_reconnect_attack(self) -> FuzzSequence:
        """Generate rapid reconnection attack.

        Rapidly connects and disconnects.

        Returns:
            Rapid reconnect sequence.

        """
        events = []

        for _ in range(50):
            events.extend(
                [
                    ProtocolEvent.A_ASSOCIATE_RQ,
                    ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
                    ProtocolEvent.A_ABORT,
                    ProtocolEvent.TRANSPORT_CLOSE,
                ]
            )

        return FuzzSequence(
            events=events,
            description="Rapid connect/disconnect",
            attack_type="rapid_reconnect",
        )


class ResourceExhaustionGenerator:
    """Generator for resource exhaustion attacks."""

    def generate_connection_exhaustion(
        self,
        num_connections: int = 1000,
    ) -> list[FuzzSequence]:
        """Generate connection exhaustion attack.

        Creates many associations without releasing.

        Args:
            num_connections: Number of connections to create.

        Returns:
            List of sequences (one per connection).

        """
        sequences = []

        for i in range(num_connections):
            events = [
                ProtocolEvent.A_ASSOCIATE_RQ,
                ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
                ProtocolEvent.A_ASSOCIATE_AC,
                # No release - hold connection open
            ]

            sequences.append(
                FuzzSequence(
                    events=events,
                    description=f"Connection exhaustion {i}",
                    attack_type="connection_exhaustion",
                )
            )

        return sequences

    def generate_pending_release_exhaustion(self) -> FuzzSequence:
        """Generate pending release exhaustion.

        Creates many pending releases.

        Returns:
            Pending release exhaustion sequence.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        # Many release requests without completions
        for _ in range(100):
            events.append(ProtocolEvent.A_RELEASE_RQ)

        return FuzzSequence(
            events=events,
            description="Pending release exhaustion",
            attack_type="pending_release",
        )
