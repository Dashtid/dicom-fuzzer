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
from dataclasses import dataclass, field
from enum import Enum

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class MultiFrameMutationStrategy(Enum):
    """Available multi-frame mutation strategies."""

    FRAME_COUNT_MISMATCH = "frame_count_mismatch"
    FRAME_TIME_CORRUPTION = "frame_time_corruption"
    PER_FRAME_DIMENSION_MISMATCH = "per_frame_dimension_mismatch"
    SHARED_GROUP_CORRUPTION = "shared_group_corruption"
    FRAME_INCREMENT_INVALID = "frame_increment_invalid"
    DIMENSION_OVERFLOW = "dimension_overflow"
    FUNCTIONAL_GROUP_ATTACK = "functional_group_attack"
    PIXEL_DATA_TRUNCATION = "pixel_data_truncation"


@dataclass
class FrameInfo:
    """Information about a single frame in a multi-frame instance."""

    frame_number: int  # 1-indexed per DICOM standard
    position: tuple[float, ...] | None = None
    orientation: tuple[float, ...] | None = None
    acquisition_time: str | None = None
    pixel_offset: int = 0  # Byte offset in PixelData
    frame_size_bytes: int = 0


@dataclass
class MultiFrameMutationRecord(SerializableMixin):
    """Record of a multi-frame mutation."""

    strategy: str
    frame_number: int | None = (
        None  # Which frame was mutated (None = all/dataset-level)
    )
    tag: str | None = None
    original_value: str | None = None
    mutated_value: str | None = None
    severity: str = "moderate"
    details: dict = field(default_factory=dict)

    def _custom_serialization(self, data: dict) -> dict:
        """Ensure values are converted to strings for JSON serialization."""
        if data.get("original_value") is not None:
            data["original_value"] = str(data["original_value"])
        if data.get("mutated_value") is not None:
            data["mutated_value"] = str(data["mutated_value"])
        return data


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

        # Apply strategy
        strategy_methods = {
            MultiFrameMutationStrategy.FRAME_COUNT_MISMATCH.value: self._mutate_frame_count_mismatch,
            MultiFrameMutationStrategy.FRAME_TIME_CORRUPTION.value: self._mutate_frame_time_corruption,
            MultiFrameMutationStrategy.PER_FRAME_DIMENSION_MISMATCH.value: self._mutate_per_frame_dimension,
            MultiFrameMutationStrategy.SHARED_GROUP_CORRUPTION.value: self._mutate_shared_group,
            MultiFrameMutationStrategy.FRAME_INCREMENT_INVALID.value: self._mutate_frame_increment,
            MultiFrameMutationStrategy.DIMENSION_OVERFLOW.value: self._mutate_dimension_overflow,
            MultiFrameMutationStrategy.FUNCTIONAL_GROUP_ATTACK.value: self._mutate_functional_group,
            MultiFrameMutationStrategy.PIXEL_DATA_TRUNCATION.value: self._mutate_pixel_data_truncation,
        }

        method = strategy_methods[strategy]
        return method(dataset, mutation_count)

    def _mutate_frame_count_mismatch(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 1: Frame Count Mismatch.

        NumberOfFrames tag doesn't match actual pixel data:
        - NumberOfFrames > actual frames (buffer over-read)
        - NumberOfFrames < actual frames (data ignored/truncated)
        - NumberOfFrames = 0 (edge case)
        - NumberOfFrames = -1 (signed/unsigned confusion)
        - NumberOfFrames = 2^31 (integer overflow)

        Targets: Frame indexing, buffer allocation, loop bounds
        """
        records: list[MultiFrameMutationRecord] = []
        original = getattr(dataset, "NumberOfFrames", 1)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "too_large",
                    "too_small",
                    "zero",
                    "negative",
                    "overflow_32bit",
                    "extreme",
                ]
            )

            if attack_type == "too_large":
                # Claim more frames than pixel data contains
                actual_frames = self._calculate_actual_frames(dataset)
                dataset.NumberOfFrames = actual_frames * 10

            elif attack_type == "too_small":
                # Claim fewer frames than pixel data contains
                actual_frames = self._calculate_actual_frames(dataset)
                dataset.NumberOfFrames = max(1, actual_frames // 2)

            elif attack_type == "zero":
                dataset.NumberOfFrames = 0

            elif attack_type == "negative":
                # Store as string to bypass pydicom validation
                # Some parsers may interpret as signed int
                dataset.NumberOfFrames = -1

            elif attack_type == "overflow_32bit":
                # 2^31 - 1 (max signed 32-bit)
                dataset.NumberOfFrames = 2147483647

            elif attack_type == "extreme":
                # Very large but not overflow
                dataset.NumberOfFrames = 999999999

            records.append(
                MultiFrameMutationRecord(
                    strategy="frame_count_mismatch",
                    frame_number=None,
                    tag="NumberOfFrames",
                    original_value=str(original),
                    mutated_value=str(dataset.NumberOfFrames),
                    severity=self.severity,
                    details={"attack_type": attack_type},
                )
            )

        return dataset, records

    def _mutate_frame_time_corruption(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 2: Frame Time Corruption.

        Corrupt temporal information in multi-frame:
        - Invalid FrameTime (negative, zero, NaN)
        - Corrupt FrameTimeVector (wrong length, invalid values)
        - Invalid FrameDelay
        - Corrupt TemporalPositionIndex

        Targets: 4D viewers, cine playback, temporal interpolation
        """
        records: list[MultiFrameMutationRecord] = []
        frame_count = self.get_frame_count(dataset)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "negative_frame_time",
                    "zero_frame_time",
                    "nan_frame_time",
                    "invalid_time_vector_length",
                    "extreme_time_values",
                    "corrupt_temporal_index",
                ]
            )

            if attack_type == "negative_frame_time":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = -33.33  # Negative ms per frame

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_time_corruption",
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="-33.33",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "zero_frame_time":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = 0.0

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_time_corruption",
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="0.0",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "nan_frame_time":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = float("nan")

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_time_corruption",
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="NaN",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_time_vector_length":
                # FrameTimeVector should have NumberOfFrames-1 elements
                original = getattr(dataset, "FrameTimeVector", None)
                # Create wrong-length vector
                wrong_length = random.choice([0, 1, frame_count + 10, frame_count * 2])
                dataset.FrameTimeVector = [33.33] * wrong_length

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_time_corruption",
                        tag="FrameTimeVector",
                        original_value=f"length={len(original) if original else 0}",
                        mutated_value=f"length={wrong_length}",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "expected_length": frame_count - 1,
                        },
                    )
                )

            elif attack_type == "extreme_time_values":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = 1e308  # Near max float

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_time_corruption",
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="1e308",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "corrupt_temporal_index":
                # Add invalid TemporalPositionIndex to per-frame groups
                per_frame_groups = getattr(
                    dataset, "PerFrameFunctionalGroupsSequence", None
                )
                if per_frame_groups:
                    for fg in per_frame_groups:
                        frame_content_seq = getattr(fg, "FrameContentSequence", None)
                        if frame_content_seq and len(frame_content_seq) > 0:
                            frame_content_seq[0].TemporalPositionIndex = random.choice(
                                [0, -1, 999999, frame_count + 100]
                            )

                    records.append(
                        MultiFrameMutationRecord(
                            strategy="frame_time_corruption",
                            tag="TemporalPositionIndex",
                            original_value="<sequential>",
                            mutated_value="<random_invalid>",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

        return dataset, records

    def _mutate_per_frame_dimension(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 3: Per-Frame Dimension Mismatch.

        Create inconsistent dimensions across frames:
        - Different pixel matrices per frame
        - Inconsistent Rows/Columns in functional groups
        - Varying bits allocated per frame

        Targets: Frame extraction, buffer allocation per frame
        """
        records: list[MultiFrameMutationRecord] = []
        per_frame_groups = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)

        if not per_frame_groups:
            # Create corrupt per-frame groups
            frame_count = self.get_frame_count(dataset)
            per_frame_groups = Sequence([Dataset() for _ in range(frame_count)])
            dataset.PerFrameFunctionalGroupsSequence = per_frame_groups

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "varying_matrix_size",
                    "zero_dimensions",
                    "extreme_dimensions",
                    "negative_dimensions",
                ]
            )

            if attack_type == "varying_matrix_size":
                # Different dimensions for different frames
                for _i, fg in enumerate(per_frame_groups):
                    if not hasattr(fg, "PixelMeasuresSequence"):
                        fg.PixelMeasuresSequence = Sequence([Dataset()])
                    pm = fg.PixelMeasuresSequence[0]

                    # Vary dimensions per frame
                    pm.Rows = random.choice([128, 256, 512, 1024])
                    pm.Columns = random.choice([128, 256, 512, 1024])

                records.append(
                    MultiFrameMutationRecord(
                        strategy="per_frame_dimension_mismatch",
                        tag="Rows/Columns",
                        original_value="<consistent>",
                        mutated_value="<varying_per_frame>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "zero_dimensions":
                frame_idx = random.randint(0, len(per_frame_groups) - 1)
                fg = per_frame_groups[frame_idx]
                if not hasattr(fg, "PixelMeasuresSequence"):
                    fg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = fg.PixelMeasuresSequence[0]
                pm.Rows = 0
                pm.Columns = 0

                records.append(
                    MultiFrameMutationRecord(
                        strategy="per_frame_dimension_mismatch",
                        frame_number=frame_idx + 1,
                        tag="Rows/Columns",
                        original_value="<valid>",
                        mutated_value="0x0",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_dimensions":
                frame_idx = random.randint(0, len(per_frame_groups) - 1)
                fg = per_frame_groups[frame_idx]
                if not hasattr(fg, "PixelMeasuresSequence"):
                    fg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = fg.PixelMeasuresSequence[0]
                pm.Rows = 65535
                pm.Columns = 65535

                records.append(
                    MultiFrameMutationRecord(
                        strategy="per_frame_dimension_mismatch",
                        frame_number=frame_idx + 1,
                        tag="Rows/Columns",
                        original_value="<valid>",
                        mutated_value="65535x65535",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "negative_dimensions":
                frame_idx = random.randint(0, len(per_frame_groups) - 1)
                fg = per_frame_groups[frame_idx]
                if not hasattr(fg, "PixelMeasuresSequence"):
                    fg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = fg.PixelMeasuresSequence[0]
                pm.Rows = -1
                pm.Columns = -1

                records.append(
                    MultiFrameMutationRecord(
                        strategy="per_frame_dimension_mismatch",
                        frame_number=frame_idx + 1,
                        tag="Rows/Columns",
                        original_value="<valid>",
                        mutated_value="-1x-1",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records

    def _mutate_shared_group(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 4: Shared Functional Groups Corruption.

        Corrupt SharedFunctionalGroupsSequence:
        - Missing required sequences
        - Corrupt pixel measures
        - Invalid orientations
        - Conflicting with per-frame groups

        Targets: Enhanced multi-frame parsers, DICOM conformance
        """
        records: list[MultiFrameMutationRecord] = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "delete_shared_groups",
                    "empty_shared_groups",
                    "corrupt_pixel_measures",
                    "invalid_orientation",
                    "conflict_with_per_frame",
                ]
            )

            if attack_type == "delete_shared_groups":
                original = hasattr(dataset, "SharedFunctionalGroupsSequence")
                if original:
                    del dataset.SharedFunctionalGroupsSequence

                records.append(
                    MultiFrameMutationRecord(
                        strategy="shared_group_corruption",
                        tag="SharedFunctionalGroupsSequence",
                        original_value="<present>" if original else "<none>",
                        mutated_value="<deleted>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_shared_groups":
                dataset.SharedFunctionalGroupsSequence = Sequence([])

                records.append(
                    MultiFrameMutationRecord(
                        strategy="shared_group_corruption",
                        tag="SharedFunctionalGroupsSequence",
                        original_value="<has_items>",
                        mutated_value="<empty_sequence>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "corrupt_pixel_measures":
                if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
                    dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
                sfg = dataset.SharedFunctionalGroupsSequence[0]

                if not hasattr(sfg, "PixelMeasuresSequence"):
                    sfg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = sfg.PixelMeasuresSequence[0]

                # Invalid pixel spacing
                pm.PixelSpacing = [0.0, 0.0]
                pm.SliceThickness = -1.0

                records.append(
                    MultiFrameMutationRecord(
                        strategy="shared_group_corruption",
                        tag="PixelMeasuresSequence",
                        original_value="<valid>",
                        mutated_value="PixelSpacing=[0,0], SliceThickness=-1",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_orientation":
                if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
                    dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
                sfg = dataset.SharedFunctionalGroupsSequence[0]

                if not hasattr(sfg, "PlaneOrientationSequence"):
                    sfg.PlaneOrientationSequence = Sequence([Dataset()])
                po = sfg.PlaneOrientationSequence[0]

                # Non-orthogonal, non-unit orientation
                po.ImageOrientationPatient = [
                    float("nan"),
                    0.0,
                    0.0,
                    0.0,
                    float("nan"),
                    0.0,
                ]

                records.append(
                    MultiFrameMutationRecord(
                        strategy="shared_group_corruption",
                        tag="ImageOrientationPatient",
                        original_value="<valid>",
                        mutated_value="[NaN, 0, 0, 0, NaN, 0]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "conflict_with_per_frame":
                # Create conflicting info in shared vs per-frame
                if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
                    dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
                sfg = dataset.SharedFunctionalGroupsSequence[0]

                if not hasattr(sfg, "PixelMeasuresSequence"):
                    sfg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = sfg.PixelMeasuresSequence[0]
                pm.PixelSpacing = [1.0, 1.0]

                # Now set different per-frame
                per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
                if per_frame and len(per_frame) > 0:
                    if not hasattr(per_frame[0], "PixelMeasuresSequence"):
                        per_frame[0].PixelMeasuresSequence = Sequence([Dataset()])
                    per_frame[0].PixelMeasuresSequence[0].PixelSpacing = [2.0, 2.0]

                records.append(
                    MultiFrameMutationRecord(
                        strategy="shared_group_corruption",
                        tag="PixelSpacing",
                        original_value="<consistent>",
                        mutated_value="shared=[1,1], per_frame[0]=[2,2]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records

    def _mutate_frame_increment(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 5: Frame Increment Pointer Invalid.

        Corrupt FrameIncrementPointer:
        - Point to non-existent tag
        - Invalid tag format
        - Circular references
        - Point to PixelData itself

        Targets: Temporal/spatial navigation, frame ordering
        """
        records: list[MultiFrameMutationRecord] = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "nonexistent_tag",
                    "invalid_format",
                    "point_to_pixel_data",
                    "multiple_invalid",
                ]
            )

            original = getattr(dataset, "FrameIncrementPointer", None)

            if attack_type == "nonexistent_tag":
                # Point to tag that doesn't exist
                dataset.FrameIncrementPointer = (0x9999, 0x9999)

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_increment_invalid",
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="(9999,9999)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_format":
                # Use invalid format (should be tag tuple/list)
                # Store as string which is invalid
                dataset.add_new((0x0028, 0x0009), "AT", b"\xff\xff\xff\xff")

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_increment_invalid",
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="<invalid_bytes>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "point_to_pixel_data":
                # Point to PixelData tag itself (circular)
                dataset.FrameIncrementPointer = (0x7FE0, 0x0010)

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_increment_invalid",
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="(7FE0,0010) [PixelData]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "multiple_invalid":
                # Multiple invalid pointers
                dataset.FrameIncrementPointer = [
                    (0x0000, 0x0000),
                    (0xFFFF, 0xFFFF),
                    (0x7FE0, 0x0010),
                ]

                records.append(
                    MultiFrameMutationRecord(
                        strategy="frame_increment_invalid",
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="[(0,0), (FFFF,FFFF), (7FE0,0010)]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records

    def _mutate_dimension_overflow(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 6: Dimension Overflow.

        Create dimension values that cause integer overflow:
        - Frames x Rows x Columns > 2^31 or 2^63
        - BitsAllocated combined with dimensions
        - SamplesPerPixel multiplier

        Targets: Buffer allocation, size calculations
        """
        records: list[MultiFrameMutationRecord] = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "frame_dimension_overflow",
                    "total_pixel_overflow",
                    "bits_multiplier_overflow",
                    "samples_multiplier_overflow",
                ]
            )

            if attack_type == "frame_dimension_overflow":
                # NumberOfFrames * Rows * Columns > 2^31
                original_frames = getattr(dataset, "NumberOfFrames", 1)
                dataset.NumberOfFrames = 50000
                dataset.Rows = 10000
                dataset.Columns = 10000
                # 50000 * 10000 * 10000 = 5 trillion > 2^32

                records.append(
                    MultiFrameMutationRecord(
                        strategy="dimension_overflow",
                        tag="NumberOfFrames/Rows/Columns",
                        original_value=f"frames={original_frames}",
                        mutated_value="50000x10000x10000 (5T pixels)",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "total_pixels": 5_000_000_000_000,
                        },
                    )
                )

            elif attack_type == "total_pixel_overflow":
                # Max 16-bit values
                dataset.NumberOfFrames = 65535
                dataset.Rows = 65535
                dataset.Columns = 65535

                records.append(
                    MultiFrameMutationRecord(
                        strategy="dimension_overflow",
                        tag="NumberOfFrames/Rows/Columns",
                        original_value="<original>",
                        mutated_value="65535x65535x65535",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "bits_multiplier_overflow":
                # BitsAllocated = 64 multiplies buffer size by 8
                original_bits = getattr(dataset, "BitsAllocated", 16)
                dataset.BitsAllocated = 64
                dataset.BitsStored = 64
                dataset.HighBit = 63

                records.append(
                    MultiFrameMutationRecord(
                        strategy="dimension_overflow",
                        tag="BitsAllocated",
                        original_value=str(original_bits),
                        mutated_value="64",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "samples_multiplier_overflow":
                # SamplesPerPixel = 4 (RGBA) multiplies size
                original_samples = getattr(dataset, "SamplesPerPixel", 1)
                dataset.SamplesPerPixel = 255  # Max uint8

                records.append(
                    MultiFrameMutationRecord(
                        strategy="dimension_overflow",
                        tag="SamplesPerPixel",
                        original_value=str(original_samples),
                        mutated_value="255",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records

    def _mutate_functional_group(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 7: Functional Group Attack.

        Corrupt per-frame and shared functional groups:
        - Missing per-frame groups for some frames
        - Extra per-frame groups beyond NumberOfFrames
        - Empty functional group items
        - Nested sequence corruption

        Targets: Enhanced multi-frame parsing, per-frame indexing
        """
        records: list[MultiFrameMutationRecord] = []
        frame_count = self.get_frame_count(dataset)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "missing_per_frame_groups",
                    "extra_per_frame_groups",
                    "empty_group_items",
                    "null_sequence_items",
                    "deeply_nested_corruption",
                ]
            )

            if attack_type == "missing_per_frame_groups":
                # Create fewer per-frame groups than frames
                fewer_count = max(1, frame_count // 2)
                dataset.PerFrameFunctionalGroupsSequence = Sequence(
                    [Dataset() for _ in range(fewer_count)]
                )

                records.append(
                    MultiFrameMutationRecord(
                        strategy="functional_group_attack",
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value=f"{frame_count} items",
                        mutated_value=f"{fewer_count} items (missing)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extra_per_frame_groups":
                # Create more per-frame groups than frames
                extra_count = frame_count * 2
                dataset.PerFrameFunctionalGroupsSequence = Sequence(
                    [Dataset() for _ in range(extra_count)]
                )

                records.append(
                    MultiFrameMutationRecord(
                        strategy="functional_group_attack",
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value=f"{frame_count} items",
                        mutated_value=f"{extra_count} items (extra)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_group_items":
                # Some items in sequence are empty
                per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
                if per_frame:
                    # Replace random items with empty datasets
                    for i in random.sample(
                        range(len(per_frame)), min(3, len(per_frame))
                    ):
                        per_frame[i] = Dataset()

                records.append(
                    MultiFrameMutationRecord(
                        strategy="functional_group_attack",
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value="<populated>",
                        mutated_value="<some_items_empty>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "null_sequence_items":
                # Try to inject None/null into sequence (may fail with pydicom)
                per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
                if per_frame and len(per_frame) > 0:
                    # Create "corrupt" dataset with invalid data
                    corrupt_ds = Dataset()
                    corrupt_ds.add_new((0xFFFF, 0xFFFF), "UN", b"\x00" * 100)
                    per_frame[0] = corrupt_ds

                records.append(
                    MultiFrameMutationRecord(
                        strategy="functional_group_attack",
                        tag="PerFrameFunctionalGroupsSequence[0]",
                        original_value="<valid>",
                        mutated_value="<corrupt_unknown_tag>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "deeply_nested_corruption":
                # Create deeply nested sequences
                if not hasattr(dataset, "PerFrameFunctionalGroupsSequence"):
                    dataset.PerFrameFunctionalGroupsSequence = Sequence([Dataset()])

                fg = dataset.PerFrameFunctionalGroupsSequence[0]

                # Create 10-level deep nesting
                current = fg
                for depth in range(10):
                    nested_seq = Sequence([Dataset()])
                    current.add_new((0x0040, 0x9096 + depth), "SQ", nested_seq)
                    current = nested_seq[0]

                records.append(
                    MultiFrameMutationRecord(
                        strategy="functional_group_attack",
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value="<normal_depth>",
                        mutated_value="<10_levels_deep>",
                        severity=self.severity,
                        details={"attack_type": attack_type, "nesting_depth": 10},
                    )
                )

        return dataset, records

    def _mutate_pixel_data_truncation(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Strategy 8: Pixel Data Truncation.

        Mismatch between declared frame count and actual pixel data:
        - Truncate PixelData mid-frame
        - Extra bytes after declared frames
        - Empty PixelData with NumberOfFrames > 0

        Targets: Frame extraction, buffer handling
        """
        records: list[MultiFrameMutationRecord] = []

        if not hasattr(dataset, "PixelData"):
            return dataset, records

        original_size = len(dataset.PixelData)
        frame_size = self.calculate_frame_size(dataset)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "truncate_mid_frame",
                    "truncate_partial",
                    "extra_bytes",
                    "empty_pixel_data",
                    "single_byte",
                ]
            )

            if attack_type == "truncate_mid_frame":
                # Cut pixel data in the middle of a frame
                if frame_size > 0 and original_size > frame_size:
                    cut_point = frame_size + (frame_size // 2)
                    dataset.PixelData = dataset.PixelData[:cut_point]

                    records.append(
                        MultiFrameMutationRecord(
                            strategy="pixel_data_truncation",
                            tag="PixelData",
                            original_value=f"{original_size} bytes",
                            mutated_value=f"{cut_point} bytes (mid-frame)",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "truncate_partial":
                # Leave only partial first frame
                partial_size = frame_size // 4 if frame_size > 0 else 100
                dataset.PixelData = dataset.PixelData[:partial_size]

                records.append(
                    MultiFrameMutationRecord(
                        strategy="pixel_data_truncation",
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value=f"{partial_size} bytes (partial frame)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extra_bytes":
                # Add random bytes after declared data
                extra = bytes(random.getrandbits(8) for _ in range(1000))
                dataset.PixelData = dataset.PixelData + extra

                records.append(
                    MultiFrameMutationRecord(
                        strategy="pixel_data_truncation",
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value=f"{original_size + 1000} bytes (extra)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_pixel_data":
                # Empty pixel data but NumberOfFrames > 0
                dataset.PixelData = b""

                records.append(
                    MultiFrameMutationRecord(
                        strategy="pixel_data_truncation",
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value="0 bytes (empty)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "single_byte":
                # Only one byte of pixel data
                dataset.PixelData = b"\x00"

                records.append(
                    MultiFrameMutationRecord(
                        strategy="pixel_data_truncation",
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value="1 byte",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records

    def _calculate_actual_frames(self, dataset: Dataset) -> int:
        """Calculate actual number of frames based on PixelData size.

        Args:
            dataset: pydicom Dataset

        Returns:
            Estimated number of frames in PixelData

        """
        if not hasattr(dataset, "PixelData"):
            return 0

        frame_size = self.calculate_frame_size(dataset)
        if frame_size == 0:
            return 0

        return len(dataset.PixelData) // frame_size


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
