"""Multi-frame DICOM types and enums.

This module contains the type definitions for multi-frame DICOM handling:
- MultiFrameMutationStrategy: Available mutation strategies
- FrameInfo: Information about a single frame
- MultiFrameMutationRecord: Record of a mutation

"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MultiFrameMutationStrategy(Enum):
    """Available multi-frame mutation strategies.

    Each strategy targets different vulnerabilities in multi-frame parsing:
    - FRAME_COUNT_MISMATCH: NumberOfFrames != actual pixel data frames
    - FRAME_TIME_CORRUPTION: Invalid temporal information
    - PER_FRAME_DIMENSION_MISMATCH: Inconsistent frame dimensions
    - SHARED_GROUP_CORRUPTION: Corrupt SharedFunctionalGroupsSequence
    - FRAME_INCREMENT_INVALID: Invalid FrameIncrementPointer
    - DIMENSION_OVERFLOW: Frames x Rows x Columns integer overflow
    - FUNCTIONAL_GROUP_ATTACK: Missing/extra/corrupt per-frame groups
    - PIXEL_DATA_TRUNCATION: Truncate pixel data
    - ENCAPSULATED_PIXEL_DATA: BOT/EOT/fragment encapsulation attacks
    - DIMENSION_INDEX_ATTACK: Dimension index module corruption

    """

    FRAME_COUNT_MISMATCH = "frame_count_mismatch"
    FRAME_TIME_CORRUPTION = "frame_time_corruption"
    PER_FRAME_DIMENSION_MISMATCH = "per_frame_dimension_mismatch"
    SHARED_GROUP_CORRUPTION = "shared_group_corruption"
    FRAME_INCREMENT_INVALID = "frame_increment_invalid"
    DIMENSION_OVERFLOW = "dimension_overflow"
    FUNCTIONAL_GROUP_ATTACK = "functional_group_attack"
    PIXEL_DATA_TRUNCATION = "pixel_data_truncation"
    ENCAPSULATED_PIXEL_DATA = "encapsulated_pixel_data"
    DIMENSION_INDEX_ATTACK = "dimension_index_attack"


@dataclass
class FrameInfo:
    """Information about a single frame in a multi-frame instance.

    Attributes:
        frame_number: 1-indexed frame number per DICOM standard
        position: Image Position Patient (x, y, z) coordinates
        orientation: Image Orientation Patient (6 direction cosines)
        acquisition_time: Frame acquisition datetime
        pixel_offset: Byte offset in PixelData
        frame_size_bytes: Size of this frame in bytes

    """

    frame_number: int  # 1-indexed per DICOM standard
    position: tuple[float, ...] | None = None
    orientation: tuple[float, ...] | None = None
    acquisition_time: str | None = None
    pixel_offset: int = 0  # Byte offset in PixelData
    frame_size_bytes: int = 0


@dataclass
class MultiFrameMutationRecord:
    """Record of a multi-frame mutation.

    Attributes:
        strategy: Name of the mutation strategy applied
        frame_number: Which frame was mutated (None = all/dataset-level)
        tag: DICOM tag that was mutated
        original_value: Value before mutation
        mutated_value: Value after mutation
        severity: Mutation severity level
        details: Additional mutation details

    """

    strategy: str
    frame_number: int | None = (
        None  # Which frame was mutated (None = all/dataset-level)
    )
    tag: str | None = None
    original_value: str | None = None
    mutated_value: str | None = None
    severity: str = "moderate"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary for serialization.

        Returns:
            Dictionary representation of the record

        """
        data = {
            "strategy": self.strategy,
            "frame_number": self.frame_number,
            "tag": self.tag,
            "original_value": str(self.original_value)
            if self.original_value is not None
            else None,
            "mutated_value": str(self.mutated_value)
            if self.mutated_value is not None
            else None,
            "severity": self.severity,
            "details": self.details,
        }
        return data


__all__ = [
    "MultiFrameMutationStrategy",
    "FrameInfo",
    "MultiFrameMutationRecord",
]
