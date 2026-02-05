"""State coverage tracking for response-aware fuzzing.

This module provides AFLNet-style state tracking for GUI applications:
- StateTransition: Represents a state transition
- StateCoverageTracker: Tracks unique states and transitions

References:
- AFLNet: A Greybox Fuzzer for Network Protocols (ICST 2020)
- StateAFL: Greybox Fuzzing Stateful Network Services (ICSE 2022)

"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

# Import unified state transition type
from dicom_fuzzer.core.corpus.coverage_types import GUIStateTransition

# Backward compatibility alias
StateTransition = GUIStateTransition


class StateCoverageTracker:
    """Track state coverage for response-aware fuzzing.

    Inspired by AFLNet's state-aware fuzzing, this tracks:
    - Unique application states visited
    - State transitions observed
    - Coverage-based prioritization of inputs

    This allows for more intelligent fuzzing by:
    1. Identifying inputs that reach new states
    2. Tracking state transition sequences
    3. Prioritizing inputs that explore new paths

    References:
    - AFLNet: A Greybox Fuzzer for Network Protocols (ICST 2020)
    - StateAFL: Greybox Fuzzing Stateful Network Services (ICSE 2022)

    """

    # Pre-defined states for GUI applications
    STATE_INITIAL = "initial"
    STATE_LOADING = "loading"
    STATE_NORMAL = "normal"
    STATE_ERROR_DIALOG = "error_dialog"
    STATE_WARNING_DIALOG = "warning_dialog"
    STATE_CRASH = "crash"
    STATE_HANG = "hang"
    STATE_MEMORY_ISSUE = "memory_issue"

    def __init__(self) -> None:
        self._states_visited: set[str] = set()
        self._transitions: set[StateTransition] = set()
        self._state_sequences: list[list[str]] = []
        self._current_sequence: list[str] = []
        self._interesting_inputs: dict[Path, set[str]] = {}  # file -> states it reached
        self._lock = threading.Lock()

    def start_execution(self) -> None:
        """Start tracking a new execution."""
        with self._lock:
            self._current_sequence = [self.STATE_INITIAL]
            self._states_visited.add(self.STATE_INITIAL)

    def record_state(
        self, state: str, trigger: str = "", test_file: Path | None = None
    ) -> bool:
        """Record a state transition.

        Args:
            state: New state reached
            trigger: What triggered this state
            test_file: File being tested

        Returns:
            True if this is a new state (not seen before)

        """
        with self._lock:
            is_new = state not in self._states_visited
            self._states_visited.add(state)

            if self._current_sequence:
                from_state = self._current_sequence[-1]
                transition = StateTransition(
                    from_state=from_state,
                    to_state=state,
                    trigger=trigger,
                    timestamp=time.time(),
                    test_file=test_file,
                )
                self._transitions.add(transition)

            self._current_sequence.append(state)

            # Track which inputs reached which states
            if test_file:
                if test_file not in self._interesting_inputs:
                    self._interesting_inputs[test_file] = set()
                self._interesting_inputs[test_file].add(state)

            return is_new

    def end_execution(self) -> list[str]:
        """End tracking current execution and return the sequence."""
        with self._lock:
            sequence = self._current_sequence.copy()
            if sequence:
                self._state_sequences.append(sequence)
            self._current_sequence = []
            return sequence

    def get_state_coverage(self) -> dict[str, Any]:
        """Get current state coverage statistics.

        Returns:
            Dictionary with coverage metrics

        """
        with self._lock:
            return {
                "unique_states": len(self._states_visited),
                "states_visited": list(self._states_visited),
                "unique_transitions": len(self._transitions),
                "total_executions": len(self._state_sequences),
                "transition_details": [
                    {
                        "from": t.from_state,
                        "to": t.to_state,
                        "trigger": t.trigger,
                    }
                    for t in self._transitions
                ],
            }

    def get_interesting_inputs(self) -> list[Path]:
        """Get inputs that reached unique states.

        Returns:
            List of file paths that discovered new states

        """
        with self._lock:
            # Rank by number of unique states reached
            ranked = sorted(
                self._interesting_inputs.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            )
            return [path for path, _ in ranked]

    def is_interesting(self, test_file: Path) -> bool:
        """Check if an input discovered new states.

        Args:
            test_file: File to check

        Returns:
            True if this file discovered at least one new state

        """
        with self._lock:
            if test_file not in self._interesting_inputs:
                return False
            # Check if any states were first discovered by this file
            states = self._interesting_inputs[test_file]
            for other_file, other_states in self._interesting_inputs.items():
                if other_file != test_file:
                    states = states - other_states
            return len(states) > 0


# Re-export all public symbols
__all__ = [
    "StateTransition",
    "StateCoverageTracker",
]
