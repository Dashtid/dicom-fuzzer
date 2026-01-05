"""State Machine Configuration.

Configuration options for stateful protocol fuzzing.
"""

from dataclasses import dataclass


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


__all__ = ["StateMachineConfig"]
