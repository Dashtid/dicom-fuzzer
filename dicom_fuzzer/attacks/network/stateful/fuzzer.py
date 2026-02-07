"""Stateful Protocol Fuzzer.

High-level orchestrator for state machine-based fuzzing.
"""

import random
import time
from collections.abc import Callable, Generator
from typing import Any

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
