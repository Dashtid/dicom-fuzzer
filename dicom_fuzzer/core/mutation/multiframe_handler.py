"""Multi-Frame DICOM Handler and Mutator.

This module provides specialized handling for multi-frame DICOM instances
(NumberOfFrames > 1), including Enhanced CT, Enhanced MR, and 4D data.

MULTI-FRAME DICOM CONCEPTS:
- Single DICOM instance contains multiple frames (images)
- PixelData contains concatenated frames
- Frame-specific metadata in Per-Frame Functional Groups Sequence
- Shared metadata in Shared Functional Groups Sequence

MUTATION STRATEGIES:
1. Frame Count Mismatch - NumberOfFrames != actual pixel data frames
2. Frame Time Corruption - Invalid temporal information
3. Per-Frame Dimension Mismatch - Inconsistent frame dimensions
4. Shared Group Corruption - Corrupt SharedFunctionalGroupsSequence
5. Frame Increment Invalid - Invalid FrameIncrementPointer
6. Dimension Overflow - Frames x Rows x Columns integer overflow
7. Functional Group Attack - Missing/extra/corrupt per-frame groups
8. Pixel Data Truncation - Truncate pixel data

SECURITY RATIONALE:
Based on CVE research, multi-frame DICOM parsing is vulnerable to:
- Buffer overflows from frame count mismatches
- Integer overflows from dimension calculations
- Memory exhaustion from extreme frame counts
- Null pointer dereferences from missing functional groups

USAGE:
    handler = MultiFrameHandler(severity="aggressive")
    dataset, records = handler.mutate(dataset, strategy="frame_count_mismatch")
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from pydicom.dataset import Dataset

# Import types from multiframe_types
from dicom_fuzzer.core.mutation.multiframe_types import (
    FrameInfo,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
)

# Import strategies from multiframe_strategies
from dicom_fuzzer.attacks.multiframe import (
    DimensionOverflowStrategy,
    FrameCountMismatchStrategy,
    FrameIncrementStrategy,
    FrameTimeCorruptionStrategy,
    FunctionalGroupStrategy,
    MutationStrategyBase,
    PerFrameDimensionStrategy,
    PixelDataTruncationStrategy,
    SharedGroupStrategy,
)
from dicom_fuzzer.utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class MultiFrameHandler:
    """Handler for multi-frame DICOM mutation.

    Provides specialized mutation strategies targeting multi-frame
    DICOM vulnerabilities not covered by single-frame or series-level fuzzing.
    """

    def __init__(self, severity: str = "moderate", seed: int | None = None):
        """Initialize MultiFrameHandler.

        Args:
            severity: Mutation severity (minimal, moderate, aggressive, extreme)
            seed: Random seed for reproducibility

        """
        if severity not in ["minimal", "moderate", "aggressive", "extreme"]:
            raise ValueError(f"Invalid severity: {severity}")

        self.severity = severity
        self.seed = seed
        if seed is not None:
            random.seed(seed)

        self._mutation_counts = {
            "minimal": (1, 2),
            "moderate": (2, 4),
            "aggressive": (4, 8),
            "extreme": (8, 16),
        }

        # Initialize strategy instances
        self._strategies: dict[str, MutationStrategyBase] = {
            MultiFrameMutationStrategy.FRAME_COUNT_MISMATCH.value: FrameCountMismatchStrategy(
                severity
            ),
            MultiFrameMutationStrategy.FRAME_TIME_CORRUPTION.value: FrameTimeCorruptionStrategy(
                severity
            ),
            MultiFrameMutationStrategy.PER_FRAME_DIMENSION_MISMATCH.value: PerFrameDimensionStrategy(
                severity
            ),
            MultiFrameMutationStrategy.SHARED_GROUP_CORRUPTION.value: SharedGroupStrategy(
                severity
            ),
            MultiFrameMutationStrategy.FRAME_INCREMENT_INVALID.value: FrameIncrementStrategy(
                severity
            ),
            MultiFrameMutationStrategy.DIMENSION_OVERFLOW.value: DimensionOverflowStrategy(
                severity
            ),
            MultiFrameMutationStrategy.FUNCTIONAL_GROUP_ATTACK.value: FunctionalGroupStrategy(
                severity
            ),
            MultiFrameMutationStrategy.PIXEL_DATA_TRUNCATION.value: PixelDataTruncationStrategy(
                severity
            ),
        }

        logger.info(f"MultiFrameHandler initialized (severity={severity})")

    def is_multiframe(self, dataset: Dataset) -> bool:
        """Check if dataset is a multi-frame instance.

        Args:
            dataset: pydicom Dataset

        Returns:
            True if NumberOfFrames > 1

        """
        if not hasattr(dataset, "NumberOfFrames"):
            return False
        try:
            return int(dataset.NumberOfFrames) > 1
        except (ValueError, TypeError):
            return False

    def get_frame_count(self, dataset: Dataset) -> int:
        """Get number of frames in dataset.

        Args:
            dataset: pydicom Dataset

        Returns:
            Number of frames (1 if not multi-frame)

        """
        if not hasattr(dataset, "NumberOfFrames"):
            return 1
        try:
            return int(dataset.NumberOfFrames)
        except (ValueError, TypeError):
            return 1

    def calculate_frame_size(self, dataset: Dataset) -> int:
        """Calculate expected size of one frame in bytes.

        Args:
            dataset: pydicom Dataset

        Returns:
            Size of one frame in bytes

        """
        rows = getattr(dataset, "Rows", 0)
        cols = getattr(dataset, "Columns", 0)
        bits_allocated = getattr(dataset, "BitsAllocated", 8)
        samples_per_pixel = getattr(dataset, "SamplesPerPixel", 1)

        bytes_per_pixel = bits_allocated // 8
        return rows * cols * bytes_per_pixel * samples_per_pixel

    def extract_frame_info(self, dataset: Dataset) -> list[FrameInfo]:
        """Extract information about each frame.

        Args:
            dataset: pydicom Dataset

        Returns:
            List of FrameInfo objects

        """
        frame_count = self.get_frame_count(dataset)
        frame_size = self.calculate_frame_size(dataset)
        frames: list[FrameInfo] = []

        # Try to get per-frame functional groups
        per_frame_groups = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)

        for i in range(frame_count):
            frame_num = i + 1  # 1-indexed

            position = None
            orientation = None
            acquisition_time = None

            # Extract from per-frame functional groups if available
            if per_frame_groups and i < len(per_frame_groups):
                frame_group = per_frame_groups[i]

                # Plane Position Sequence
                plane_pos_seq = getattr(frame_group, "PlanePositionSequence", None)
                if plane_pos_seq and len(plane_pos_seq) > 0:
                    ipp = getattr(plane_pos_seq[0], "ImagePositionPatient", None)
                    if ipp:
                        position = tuple(float(x) for x in ipp)

                # Plane Orientation Sequence
                plane_orient_seq = getattr(
                    frame_group, "PlaneOrientationSequence", None
                )
                if plane_orient_seq and len(plane_orient_seq) > 0:
                    iop = getattr(plane_orient_seq[0], "ImageOrientationPatient", None)
                    if iop:
                        orientation = tuple(float(x) for x in iop)

                # Frame Content Sequence (for acquisition time)
                frame_content_seq = getattr(frame_group, "FrameContentSequence", None)
                if frame_content_seq and len(frame_content_seq) > 0:
                    acquisition_time = getattr(
                        frame_content_seq[0], "FrameAcquisitionDateTime", None
                    )

            frames.append(
                FrameInfo(
                    frame_number=frame_num,
                    position=position,
                    orientation=orientation,
                    acquisition_time=acquisition_time,
                    pixel_offset=i * frame_size,
                    frame_size_bytes=frame_size,
                )
            )

        return frames

    def mutate(
        self,
        dataset: Dataset,
        strategy: str | MultiFrameMutationStrategy | None = None,
        mutation_count: int | None = None,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply multi-frame mutation to dataset.

        Args:
            dataset: pydicom Dataset to mutate
            strategy: Mutation strategy (random if None)
            mutation_count: Number of mutations (severity-based if None)

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        # Select strategy
        if strategy is None:
            strategy = random.choice(list(MultiFrameMutationStrategy)).value
        elif not isinstance(strategy, str):
            strategy = strategy.value

        if strategy not in [s.value for s in MultiFrameMutationStrategy]:
            raise ValueError(f"Invalid strategy: {strategy}")

        # Determine mutation count
        if mutation_count is None:
            min_count, max_count = self._mutation_counts[self.severity]
            mutation_count = random.randint(min_count, max_count)

        logger.info(
            f"Mutating multi-frame with {mutation_count} mutations "
            f"(strategy={strategy}, severity={self.severity})"
        )

        # Dispatch to strategy
        strategy_impl = self._strategies[strategy]
        return strategy_impl.mutate(dataset, mutation_count)


def create_multiframe_mutator(
    severity: str = "moderate",
    seed: int | None = None,
) -> MultiFrameHandler:
    """Factory function to create a MultiFrameHandler.

    Args:
        severity: Mutation severity level
        seed: Random seed for reproducibility

    Returns:
        Configured MultiFrameHandler instance

    """
    return MultiFrameHandler(severity=severity, seed=seed)


# Re-export types for backward compatibility
__all__ = [
    # Main class
    "MultiFrameHandler",
    # Factory function
    "create_multiframe_mutator",
    # Types (re-exported from multiframe_types)
    "MultiFrameMutationStrategy",
    "FrameInfo",
    "MultiFrameMutationRecord",
]
