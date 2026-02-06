"""Mutation primitives -- byte, multiframe, and orchestration."""

from .byte_mutator import ByteMutator, DICOMByteMutator
from .multiframe_handler import (
    FrameInfo,
    MultiFrameHandler,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
    create_multiframe_mutator,
)
from .mutator import DicomMutator

__all__ = [
    "ByteMutator",
    "DICOMByteMutator",
    "DicomMutator",
    "FrameInfo",
    "MultiFrameHandler",
    "MultiFrameMutationRecord",
    "MultiFrameMutationStrategy",
    "create_multiframe_mutator",
]
