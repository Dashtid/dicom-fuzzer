"""Segmentation Fuzzer - DICOM Segmentation Object Mutations.

Category: modality-specific (SEG)

Attacks:
- Segment sequence item count and numbering mismatches
- Segment cross-reference integrity violations
- SegmentationType vs BitsAllocated pixel encoding mismatches
- Referenced series link corruption
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_SEG_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.66.4"


class SegmentationFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Segmentation objects to test segment handling robustness.

    Targets the SegmentSequence / PerFrameFunctionalGroupsSequence
    relationship and binary/fractional pixel mask encoding that are
    unique to Segmentation IOD.
    """

    def __init__(self) -> None:
        """Initialize the segmentation fuzzer with attack strategies."""
        super().__init__()
        self.mutation_strategies = [
            self._segment_sequence_corruption,
            self._segment_frame_mapping_attack,
            self._binary_pixel_type_mismatch,
            self._referenced_series_corruption,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "segmentation"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate Segmentation Storage datasets."""
        sop_class = getattr(dataset, "SOPClassUID", None)
        return str(sop_class) == _SEG_SOP_CLASS_UID

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply segmentation-specific mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with segmentation corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("Segmentation mutation failed: %s", e)

        return dataset

    def _segment_sequence_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt SegmentSequence item count, numbering, or content."""
        attack = random.choice(
            [
                "duplicate_numbers",
                "gap_in_numbers",
                "zero_segment_number",
                "empty_sequence",
                "remove_sequence",
                "invalid_algorithm_type",
            ]
        )

        try:
            if attack == "duplicate_numbers":
                item1 = Dataset()
                item1.SegmentNumber = 1
                item1.SegmentLabel = "Segment A"
                item1.SegmentAlgorithmType = "AUTOMATIC"
                item2 = Dataset()
                item2.SegmentNumber = 1  # duplicate
                item2.SegmentLabel = "Segment B"
                item2.SegmentAlgorithmType = "AUTOMATIC"
                dataset.SegmentSequence = Sequence([item1, item2])
            elif attack == "gap_in_numbers":
                items = []
                for n in [1, 2, 5, 8]:  # gaps at 3-4, 6-7
                    item = Dataset()
                    item.SegmentNumber = n
                    item.SegmentLabel = f"Segment {n}"
                    item.SegmentAlgorithmType = "AUTOMATIC"
                    items.append(item)
                dataset.SegmentSequence = Sequence(items)
            elif attack == "zero_segment_number":
                item = Dataset()
                item.SegmentNumber = 0  # invalid per DICOM (must be >= 1)
                item.SegmentLabel = "Invalid"
                item.SegmentAlgorithmType = "AUTOMATIC"
                dataset.SegmentSequence = Sequence([item])
            elif attack == "empty_sequence":
                dataset.SegmentSequence = Sequence([])
            elif attack == "remove_sequence":
                if "SegmentSequence" in dataset:
                    del dataset.SegmentSequence
            elif attack == "invalid_algorithm_type":
                item = Dataset()
                item.SegmentNumber = 1
                item.SegmentLabel = "Bad Algorithm"
                item.SegmentAlgorithmType = random.choice(
                    [
                        "",
                        "INVALID",
                        "MANUAL\x00AUTO",
                        "A" * 10000,
                    ]
                )
                dataset.SegmentSequence = Sequence([item])
        except Exception as e:
            logger.debug("Segment sequence corruption failed: %s", e)

        return dataset

    def _segment_frame_mapping_attack(self, dataset: Dataset) -> Dataset:
        """Break SegmentIdentificationSequence cross-references."""
        attack = random.choice(
            [
                "orphan_reference",
                "zero_reference",
                "remove_identification",
                "conflicting_frames",
            ]
        )

        try:
            if attack == "orphan_reference":
                # Reference a segment number that doesn't exist
                frame_item = Dataset()
                seg_id = Dataset()
                seg_id.ReferencedSegmentNumber = 999
                frame_item.SegmentIdentificationSequence = Sequence([seg_id])
                dataset.PerFrameFunctionalGroupsSequence = Sequence([frame_item])
            elif attack == "zero_reference":
                frame_item = Dataset()
                seg_id = Dataset()
                seg_id.ReferencedSegmentNumber = 0  # invalid
                frame_item.SegmentIdentificationSequence = Sequence([seg_id])
                dataset.PerFrameFunctionalGroupsSequence = Sequence([frame_item])
            elif attack == "remove_identification":
                # PerFrameFunctionalGroups with no SegmentIdentificationSequence
                frame_item = Dataset()
                dataset.PerFrameFunctionalGroupsSequence = Sequence([frame_item])
            elif attack == "conflicting_frames":
                # Two frames claiming to be the same segment
                frames = []
                for _ in range(3):
                    frame_item = Dataset()
                    seg_id = Dataset()
                    seg_id.ReferencedSegmentNumber = 1  # all reference same segment
                    frame_item.SegmentIdentificationSequence = Sequence([seg_id])
                    frames.append(frame_item)
                dataset.PerFrameFunctionalGroupsSequence = Sequence(frames)
                dataset.NumberOfFrames = 3
        except Exception as e:
            logger.debug("Segment frame mapping attack failed: %s", e)

        return dataset

    def _binary_pixel_type_mismatch(self, dataset: Dataset) -> Dataset:
        """Create SegmentationType vs BitsAllocated inconsistencies."""
        attack = random.choice(
            [
                "binary_with_8bit",
                "fractional_with_1bit",
                "invalid_type",
                "fractional_value_mismatch",
            ]
        )

        try:
            if attack == "binary_with_8bit":
                dataset.SegmentationType = "BINARY"
                dataset.BitsAllocated = 8  # should be 1 for BINARY
                dataset.BitsStored = 8
                dataset.HighBit = 7
            elif attack == "fractional_with_1bit":
                dataset.SegmentationType = "FRACTIONAL"
                dataset.BitsAllocated = 1  # should be 8 for FRACTIONAL
                dataset.BitsStored = 1
                dataset.HighBit = 0
            elif attack == "invalid_type":
                dataset.SegmentationType = random.choice(
                    [
                        "",
                        "INVALID",
                        "BINARY\x00FRACTIONAL",
                        "A" * 5000,
                    ]
                )
            elif attack == "fractional_value_mismatch":
                dataset.SegmentationType = "FRACTIONAL"
                dataset.MaximumFractionalValue = random.choice(
                    [
                        0,
                        -1,
                        65535,
                        0,
                    ]
                )
        except Exception as e:
            logger.debug("Binary pixel type mismatch failed: %s", e)

        return dataset

    def _referenced_series_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt ReferencedSeriesSequence links to source images."""
        attack = random.choice(
            [
                "invalid_uid",
                "empty_sequence",
                "remove_instances",
                "self_reference",
            ]
        )

        try:
            if attack == "invalid_uid":
                ref_series = Dataset()
                ref_series.SeriesInstanceUID = "999.999.999.INVALID"
                ref_instance = Dataset()
                ref_instance.ReferencedSOPClassUID = "1.2.3.4.5"
                ref_instance.ReferencedSOPInstanceUID = generate_uid()
                ref_series.ReferencedInstanceSequence = Sequence([ref_instance])
                dataset.ReferencedSeriesSequence = Sequence([ref_series])
            elif attack == "empty_sequence":
                dataset.ReferencedSeriesSequence = Sequence([])
            elif attack == "remove_instances":
                ref_series = Dataset()
                ref_series.SeriesInstanceUID = generate_uid()
                ref_series.ReferencedInstanceSequence = Sequence([])  # no instances
                dataset.ReferencedSeriesSequence = Sequence([ref_series])
            elif attack == "self_reference":
                series_uid = getattr(dataset, "SeriesInstanceUID", generate_uid())
                sop_uid = getattr(dataset, "SOPInstanceUID", generate_uid())
                ref_series = Dataset()
                ref_series.SeriesInstanceUID = series_uid  # self-reference
                ref_instance = Dataset()
                ref_instance.ReferencedSOPClassUID = _SEG_SOP_CLASS_UID
                ref_instance.ReferencedSOPInstanceUID = sop_uid  # self-reference
                ref_series.ReferencedInstanceSequence = Sequence([ref_instance])
                dataset.ReferencedSeriesSequence = Sequence([ref_series])
        except Exception as e:
            logger.debug("Referenced series corruption failed: %s", e)

        return dataset


__all__ = ["SegmentationFuzzer"]
