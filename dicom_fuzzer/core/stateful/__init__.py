"""Stateful Protocol Fuzzing Package.

This package provides state machine-based fuzzing for DICOM protocol testing,
including attack sequence generation and coverage tracking.
"""

from dicom_fuzzer.core.stateful.config import StateMachineConfig
from dicom_fuzzer.core.stateful.enums import (
    AssociationState,
    ProtocolEvent,
    TransitionType,
)
from dicom_fuzzer.core.stateful.fuzzer import StatefulFuzzer
from dicom_fuzzer.core.stateful.resource_attacks import ResourceExhaustionGenerator
from dicom_fuzzer.core.stateful.sequence_generator import (
    CoverageStats,
    SequenceGenerator,
)
from dicom_fuzzer.core.stateful.state_machine import DICOMStateMachine
from dicom_fuzzer.core.stateful.timing_attacks import TimingAttackGenerator
from dicom_fuzzer.core.stateful.types import (
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
