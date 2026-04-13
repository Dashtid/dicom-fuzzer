"""Stateful Protocol Fuzzer.

High-level orchestrator for state machine-based fuzzing.
"""

import random
import time
from collections.abc import Callable, Generator
from typing import Any

from dicom_fuzzer.attacks.network.builder import DICOMProtocolBuilder
from dicom_fuzzer.utils.logger import get_logger

from .config import StateMachineConfig
from .enums import (
    AssociationState,
    ProtocolEvent,
    TransitionType,
)
from .sequence_generator import (
    CoverageStats,
    SequenceGenerator,
)
from .state_machine import DICOMStateMachine
from .types import FuzzSequence, TransitionResult

logger = get_logger(__name__)

# PDU builder mapped to each sendable ProtocolEvent (PS3.8 Section 7)
_PDU_BUILDERS: dict[ProtocolEvent, Callable[[], bytes]] = {
    ProtocolEvent.A_ASSOCIATE_RQ: DICOMProtocolBuilder.build_a_associate_rq,
    ProtocolEvent.A_ASSOCIATE_AC: DICOMProtocolBuilder.build_a_associate_ac,
    ProtocolEvent.A_ASSOCIATE_RJ: DICOMProtocolBuilder.build_a_associate_rj,
    ProtocolEvent.A_RELEASE_RQ: DICOMProtocolBuilder.build_a_release_rq,
    ProtocolEvent.A_RELEASE_RP: DICOMProtocolBuilder.build_a_release_rp,
    ProtocolEvent.A_ABORT: DICOMProtocolBuilder.build_a_abort,
    ProtocolEvent.P_DATA_TF: lambda: DICOMProtocolBuilder.build_p_data_tf(b"FUZZ"),
}


def build_pdu_for_event(event: ProtocolEvent) -> bytes:
    """Return a valid PDU for the given protocol event.

    Uses the DICOMProtocolBuilder to construct a well-formed PDU so that
    the fuzzer can send concrete bytes even when no custom message_generator
    is provided.  Events that have no corresponding PDU (e.g. timer events,
    transport events) return an empty byte string.

    Args:
        event: Protocol event to build a PDU for.

    Returns:
        PDU bytes (possibly empty for non-PDU events).

    """
    builder = _PDU_BUILDERS.get(event)
    if builder is None:
        return b""
    try:
        return builder()
    except Exception as exc:  # pragma: no cover
        logger.debug("PDU builder failed for %s: %s", event, exc)
        return b""


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
        """Execute a single protocol event and build the corresponding PDU.

        Calls *message_generator* (or the built-in PDU builder) to produce
        outgoing bytes for the event, then records them in
        ``TransitionResult.message_sent``.  No network I/O is performed here;
        the caller is responsible for transmitting the bytes.

        Args:
            event: Event to execute.
            message_generator: Callable that takes a ProtocolEvent and returns
                PDU bytes.  Defaults to the built-in PDU builder which maps
                each event to the corresponding PS3.8 PDU type.

        Returns:
            Result of the transition including ``message_sent`` bytes.

        """
        start_time = time.time()
        from_state = self.current_state

        # Build outgoing bytes (default builder or caller-supplied generator)
        generator = message_generator or build_pdu_for_event
        try:
            message_sent: bytes | None = (
                generator(event)
                if callable(generator) and generator is not build_pdu_for_event
                else build_pdu_for_event(event)
                if message_generator is None
                else generator(event)
            )
        except Exception as exc:
            logger.debug("message_generator raised for %s: %s", event, exc)
            message_sent = None

        # Get transition
        transition = self.state_machine.get_transition(from_state, event)

        if transition is None:
            return TransitionResult(
                success=False,
                from_state=from_state,
                to_state=from_state,
                event=event,
                message_sent=message_sent,
                error="No transition defined",
                duration_ms=(time.time() - start_time) * 1000,
            )

        is_invalid = transition.transition_type != TransitionType.VALID

        # Update coverage
        self.coverage.states_visited.add(from_state)
        if transition.transition_type == TransitionType.VALID:
            self.coverage.transitions_executed.add((from_state, event))
        else:
            self.coverage.invalid_transitions_tested.add((from_state, event))

        # Update state only for valid transitions
        if transition.transition_type == TransitionType.VALID:
            self.current_state = transition.to_state
            self.coverage.states_visited.add(transition.to_state)

        return TransitionResult(
            success=True,
            from_state=from_state,
            to_state=transition.to_state,
            event=event,
            message_sent=message_sent,
            duration_ms=(time.time() - start_time) * 1000,
            is_invalid_transition=is_invalid,
        )

    def fuzz(
        self,
        count: int = 100,
        invalid_only: bool = True,
        message_generator: Callable[[ProtocolEvent], bytes] | None = None,
    ) -> Generator[list[TransitionResult], None, None]:
        """Generate and execute fuzz sequences, yielding results per sequence.

        Focuses on invalid state transitions by default: sequences that send
        PDUs in states where those PDUs are protocol violations (e.g. sending
        A-ASSOCIATE-RQ while already in an established association).

        Uses the built-in PDU builder so each event produces real bytes even
        without a custom *message_generator*.

        Args:
            count: Total number of sequences to generate and execute.
            invalid_only: When True (default) skip sequences whose attack_type
                is ``"valid"`` — only test protocol violation sequences.
            message_generator: Optional callable(ProtocolEvent) → bytes to
                override the default PDU builder.

        Yields:
            List of ``TransitionResult`` objects for each executed sequence,
            one list per sequence.  Each result includes ``message_sent``
            bytes and ``is_invalid_transition`` flag.

        """
        _invalid_attack_types = frozenset(
            {
                "invalid_transition",
                "out_of_order",
                "state_confusion",
                "duplicate",
                "release_collision",
                "abort_recovery",
            }
        )

        for seq in self.generate_fuzz_sequences(count=count):
            if invalid_only and seq.attack_type not in _invalid_attack_types:
                continue
            results = self.execute_sequence(seq, message_generator=message_generator)
            yield results

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

    def get_coverage_stats(self) -> dict[str, Any]:
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

    def get_untested_transitions(
        self,
    ) -> list[tuple[AssociationState, ProtocolEvent]]:
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


__all__ = ["StatefulFuzzer"]
