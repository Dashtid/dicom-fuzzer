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

Note: This module re-exports from the `stateful` subpackage for backward
compatibility. New code should import directly from the subpackage modules.
"""

# Re-export all public symbols from the stateful subpackage
from dicom_fuzzer.core.stateful import (
    AssociationState,
    CoverageStats,
    DICOMStateMachine,
    FuzzSequence,
    ProtocolEvent,
    ResourceExhaustionGenerator,
    SequenceGenerator,
    StatefulFuzzer,
    StateMachineConfig,
    StateTransition,
    TimingAttackGenerator,
    TransitionResult,
    TransitionType,
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
