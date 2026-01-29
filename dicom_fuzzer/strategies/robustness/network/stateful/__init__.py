"""Stateful Protocol Fuzzing Package.

This package provides state machine-based fuzzing for DICOM protocol testing,
including attack sequence generation and coverage tracking.
"""

from .config import StateMachineConfig
from .enums import (
    AssociationState,
    ProtocolEvent,
    TransitionType,
)
from .fuzzer import StatefulFuzzer
from .resource_attacks import ResourceExhaustionGenerator
from .sequence_generator import (
    CoverageStats,
    SequenceGenerator,
)
from .state_machine import DICOMStateMachine
from .timing_attacks import TimingAttackGenerator
from .types import (
    FuzzSequence,
    StateTransition,
    TransitionResult,
)

__all__ = [
    # Enums
    "AssociationState",
    "ProtocolEvent",
    "TransitionType",
    # Config
    "StateMachineConfig",
    # Types
    "StateTransition",
    "TransitionResult",
    "FuzzSequence",
    # State Machine
    "DICOMStateMachine",
    # Generators
    "SequenceGenerator",
    "CoverageStats",
    "TimingAttackGenerator",
    "ResourceExhaustionGenerator",
    # Main Fuzzer
    "StatefulFuzzer",
]
