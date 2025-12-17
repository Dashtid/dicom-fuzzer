"""DICOM Fuzzer Type Definitions

LEARNING OBJECTIVE: This module contains shared type definitions used across
the fuzzing framework to avoid circular imports.

CONCEPT: By placing shared types in a separate module, we allow different
components to import them without creating circular dependencies.
"""

from enum import Enum


# LEARNING: This is an Enum - a way to define a set of named constants
class MutationSeverity(Enum):
    """CONCEPT: Enums are like a list of predefined choices that can't be changed.
    They're useful when you have a fixed set of options.

    WHY: We want to control how aggressive our mutations are.
    """

    MINIMAL = "minimal"  # Very small changes, unlikely to break anything
    MODERATE = "moderate"  # Medium changes, might cause some issues
    AGGRESSIVE = "aggressive"  # Large changes, likely to break things
    EXTREME = "extreme"  # Maximum changes, definitely will break things
