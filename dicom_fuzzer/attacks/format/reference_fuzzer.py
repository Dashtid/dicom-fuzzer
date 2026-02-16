"""Reference Fuzzer - DICOM Reference and Link Integrity Mutations.

Category: generic

Attacks:
- Orphan references to nonexistent SOP instances, series, studies
- Circular and self-referencing UIDs
- Invalid frame number references
- Mismatched study/series cross-references
- Frame of Reference UID corruption
- Duplicate reference entries
- Massive reference chain (memory exhaustion)
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)


class ReferenceFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM object references and links.

    Targets the relationships between DICOM objects that applications
    must resolve to provide complete clinical context.
    """

    def __init__(self) -> None:
        """Initialize the reference fuzzer."""
        super().__init__()
        self.mutation_strategies = [
            self._orphan_reference,
            self._circular_reference,
            self._self_reference,
            self._invalid_frame_reference,
            self._mismatched_study_reference,
            self._broken_series_reference,
            self._frame_of_reference_attack,
            self._duplicate_references,
            self._massive_reference_chain,
            self._reference_type_mismatch,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "reference"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply reference-related mutations.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with reference corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug(f"Reference mutation failed: {e}")

        return dataset

    def _orphan_reference(self, dataset: Dataset) -> Dataset:
        """Create references to non-existent objects.

        Orphan references test error handling when referenced
        objects cannot be found.
        """
        attack = random.choice(
            [
                "nonexistent_sop_instance",
                "nonexistent_series",
                "nonexistent_study",
                "nonexistent_frame_of_reference",
            ]
        )

        try:
            if attack == "nonexistent_sop_instance":
                # Reference a SOP Instance that doesn't exist
                ref_item = Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT
                ref_item.ReferencedSOPInstanceUID = "1.2.3.4.5.6.7.8.9.NONEXISTENT"
                dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([ref_item]))

            elif attack == "nonexistent_series":
                ref_item = Dataset()
                ref_item.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9.NOSERIES"
                dataset.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([ref_item]))

            elif attack == "nonexistent_study":
                dataset.add_new(
                    Tag(0x0008, 0x1110),
                    "SQ",  # ReferencedStudySequence
                    Sequence([]),
                )
                ref_item = Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.3.1.2.3.1"  # Study
                ref_item.ReferencedSOPInstanceUID = "1.2.3.4.5.NOSTUDY"
                dataset[Tag(0x0008, 0x1110)].value.append(ref_item)

            elif attack == "nonexistent_frame_of_reference":
                # Frame of Reference that doesn't exist
                dataset.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.9.NOFRAME"

        except Exception as e:
            logger.debug(f"Orphan reference attack failed: {e}")

        return dataset

    def _circular_reference(self, dataset: Dataset) -> Dataset:
        """Create circular reference chains.

        Circular references can cause infinite loops in applications
        that follow reference chains.
        """
        try:
            # Get or create UIDs
            if hasattr(dataset, "SOPInstanceUID"):
                self_uid = dataset.SOPInstanceUID
            else:
                self_uid = generate_uid()
                dataset.SOPInstanceUID = self_uid

            attack = random.choice(
                [
                    "direct_self_ref",
                    "two_hop_cycle",
                    "reference_chain_to_self",
                ]
            )

            if attack == "direct_self_ref":
                # Object references itself
                ref_item = Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_item.ReferencedSOPInstanceUID = self_uid
                dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([ref_item]))

            elif attack == "two_hop_cycle":
                # Create two items that reference each other
                uid_a = self_uid
                uid_b = generate_uid()

                # This object references uid_b
                ref_b = Dataset()
                ref_b.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_b.ReferencedSOPInstanceUID = uid_b

                # And claims uid_b references us (uid_a)
                ref_a = Dataset()
                ref_a.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_a.ReferencedSOPInstanceUID = uid_a

                # Nested reference chain
                ref_b_with_back_ref = Dataset()
                ref_b_with_back_ref.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_b_with_back_ref.ReferencedSOPInstanceUID = uid_b
                ref_b_with_back_ref.add_new(
                    Tag(0x0008, 0x1140), "SQ", Sequence([ref_a])
                )

                dataset.add_new(
                    Tag(0x0008, 0x1140), "SQ", Sequence([ref_b_with_back_ref])
                )

            elif attack == "reference_chain_to_self":
                # Long chain that eventually references self
                current = Dataset()
                current.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                current.ReferencedSOPInstanceUID = self_uid

                for _ in range(10):
                    wrapper = Dataset()
                    wrapper.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    wrapper.ReferencedSOPInstanceUID = generate_uid()
                    wrapper.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([current]))
                    current = wrapper

                dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([current]))

        except Exception as e:
            logger.debug(f"Circular reference attack failed: {e}")

        return dataset

    def _self_reference(self, dataset: Dataset) -> Dataset:
        """Create direct self-references in various contexts.

        Self-references are a special case of circular references
        that may not be properly handled.
        """
        try:
            # Ensure we have UIDs to reference
            if not hasattr(dataset, "StudyInstanceUID"):
                dataset.StudyInstanceUID = generate_uid()
            if not hasattr(dataset, "SeriesInstanceUID"):
                dataset.SeriesInstanceUID = generate_uid()
            if not hasattr(dataset, "SOPInstanceUID"):
                dataset.SOPInstanceUID = generate_uid()

            attack = random.choice(
                [
                    "study_refs_self",
                    "series_refs_self",
                    "source_image_is_self",
                ]
            )

            if attack == "study_refs_self":
                ref_item = Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.3.1.2.3.1"
                ref_item.ReferencedSOPInstanceUID = dataset.StudyInstanceUID
                dataset.add_new(
                    Tag(0x0008, 0x1110),
                    "SQ",  # ReferencedStudySequence
                    Sequence([ref_item]),
                )

            elif attack == "series_refs_self":
                ref_item = Dataset()
                ref_item.SeriesInstanceUID = dataset.SeriesInstanceUID
                dataset.add_new(
                    Tag(0x0008, 0x1115),
                    "SQ",  # ReferencedSeriesSequence
                    Sequence([ref_item]),
                )

            elif attack == "source_image_is_self":
                ref_item = Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_item.ReferencedSOPInstanceUID = dataset.SOPInstanceUID
                dataset.add_new(
                    Tag(0x0008, 0x2112),
                    "SQ",  # SourceImageSequence
                    Sequence([ref_item]),
                )

        except Exception as e:
            logger.debug(f"Self reference attack failed: {e}")

        return dataset

    def _invalid_frame_reference(self, dataset: Dataset) -> Dataset:
        """Create invalid frame number references.

        References to non-existent frames or invalid frame numbers
        can cause out-of-bounds access.
        """
        try:
            attack = random.choice(
                [
                    "frame_beyond_count",
                    "negative_frame",
                    "zero_frame",
                    "massive_frame_number",
                ]
            )

            # Set a reasonable NumberOfFrames
            if not hasattr(dataset, "NumberOfFrames"):
                dataset.NumberOfFrames = 10

            ref_item = Dataset()
            ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ref_item.ReferencedSOPInstanceUID = generate_uid()

            if attack == "frame_beyond_count":
                # Reference frame 100 when only 10 exist
                ref_item.ReferencedFrameNumber = 100

            elif attack == "negative_frame":
                # Negative frame number
                ref_item.ReferencedFrameNumber = -1

            elif attack == "zero_frame":
                # Frame 0 (DICOM frames are 1-indexed)
                ref_item.ReferencedFrameNumber = 0

            elif attack == "massive_frame_number":
                # Very large frame number
                ref_item.ReferencedFrameNumber = 2147483647

            dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([ref_item]))

        except Exception as e:
            logger.debug(f"Invalid frame reference attack failed: {e}")

        return dataset

    def _mismatched_study_reference(self, dataset: Dataset) -> Dataset:
        """Create study/series/instance UID mismatches.

        The hierarchy Study > Series > Instance should be consistent.
        Mismatches test validation logic.
        """
        try:
            attack = random.choice(
                [
                    "series_different_study",
                    "instance_different_series",
                    "multiple_studies_same_series",
                ]
            )

            if attack == "series_different_study":
                # Set series that claims different study
                dataset.StudyInstanceUID = generate_uid()
                ref_item = Dataset()
                ref_item.StudyInstanceUID = generate_uid()  # Different!
                ref_item.SeriesInstanceUID = generate_uid()
                dataset.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([ref_item]))

            elif attack == "instance_different_series":
                # Referenced instance from different series
                dataset.SeriesInstanceUID = generate_uid()
                ref_item = Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_item.ReferencedSOPInstanceUID = generate_uid()
                ref_item.SeriesInstanceUID = generate_uid()  # Different!
                dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([ref_item]))

            elif attack == "multiple_studies_same_series":
                # Same series UID in different studies (invalid)
                shared_series_uid = generate_uid()
                dataset.SeriesInstanceUID = shared_series_uid

                ref_items = []
                for _i in range(3):
                    ref_item = Dataset()
                    ref_item.StudyInstanceUID = generate_uid()
                    ref_item.SeriesInstanceUID = shared_series_uid
                    ref_items.append(ref_item)
                dataset.add_new(Tag(0x0008, 0x1115), "SQ", Sequence(ref_items))

        except Exception as e:
            logger.debug(f"Mismatched study reference attack failed: {e}")

        return dataset

    def _broken_series_reference(self, dataset: Dataset) -> Dataset:
        """Create broken series references.

        Series references that point to wrong or missing series.
        """
        try:
            # Create referenced series sequence with problems
            ref_series = []
            for _i in range(5):
                item = Dataset()
                item.SeriesInstanceUID = generate_uid()

                # Add some referenced instances
                instances = []
                for _j in range(3):
                    inst = Dataset()
                    inst.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    inst.ReferencedSOPInstanceUID = generate_uid()
                    instances.append(inst)

                item.add_new(
                    Tag(0x0008, 0x1199),
                    "SQ",  # ReferencedSOPSequence
                    Sequence(instances),
                )
                ref_series.append(item)

            # Make some references broken
            if ref_series:
                # Empty the instance list for one series
                ref_series[0][Tag(0x0008, 0x1199)].value = Sequence([])

                # Set duplicate series UID
                if len(ref_series) > 1:
                    ref_series[1].SeriesInstanceUID = ref_series[0].SeriesInstanceUID

            dataset.add_new(Tag(0x0008, 0x1115), "SQ", Sequence(ref_series))

        except Exception as e:
            logger.debug(f"Broken series reference attack failed: {e}")

        return dataset

    def _frame_of_reference_attack(self, dataset: Dataset) -> Dataset:
        """Attack Frame of Reference relationships.

        Frame of Reference is used for spatial registration.
        Corrupted FoR can cause wrong image alignment.
        """
        try:
            attack = random.choice(
                [
                    "conflicting_for",
                    "missing_for_with_position",
                    "for_uid_mismatch",
                ]
            )

            if attack == "conflicting_for":
                # Set FrameOfReferenceUID but reference different one
                dataset.FrameOfReferenceUID = generate_uid()

                ref_item = Dataset()
                ref_item.FrameOfReferenceUID = generate_uid()  # Different!
                ref_item.FrameOfReferenceRelationship = "DERIVED"
                dataset.add_new(
                    Tag(0x3006, 0x0080),
                    "SQ",  # ReferencedFrameOfReferenceSequence
                    Sequence([ref_item]),
                )

            elif attack == "missing_for_with_position":
                # Has position data but no Frame of Reference
                if hasattr(dataset, "FrameOfReferenceUID"):
                    del dataset.FrameOfReferenceUID
                dataset.ImagePositionPatient = [0.0, 0.0, 0.0]
                dataset.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]

            elif attack == "for_uid_mismatch":
                # Referenced FoR doesn't match any in sequence
                dataset.FrameOfReferenceUID = generate_uid()

                ref_items = []
                for _ in range(3):
                    item = Dataset()
                    item.FrameOfReferenceUID = generate_uid()  # All different
                    ref_items.append(item)

                dataset.add_new(Tag(0x3006, 0x0080), "SQ", Sequence(ref_items))

        except Exception as e:
            logger.debug(f"Frame of reference attack failed: {e}")

        return dataset

    def _duplicate_references(self, dataset: Dataset) -> Dataset:
        """Create duplicate references to the same object.

        Duplicates may cause issues in reference counting or
        double-processing.
        """
        try:
            # Create same reference multiple times
            uid = generate_uid()

            ref_items = []
            for _ in range(10):  # 10 identical references
                item = Dataset()
                item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                item.ReferencedSOPInstanceUID = uid  # Same UID!
                ref_items.append(item)

            dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence(ref_items))

        except Exception as e:
            logger.debug(f"Duplicate reference attack failed: {e}")

        return dataset

    def _massive_reference_chain(self, dataset: Dataset) -> Dataset:
        """Create very long reference chains.

        Long chains can cause stack overflow or memory exhaustion
        when applications try to resolve them.
        """
        try:
            chain_length = random.choice([100, 500, 1000])

            # Build nested reference chain
            current = Dataset()
            current.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            current.ReferencedSOPInstanceUID = generate_uid()

            for _ in range(chain_length):
                wrapper = Dataset()
                wrapper.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                wrapper.ReferencedSOPInstanceUID = generate_uid()
                wrapper.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([current]))
                current = wrapper

            dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([current]))

        except Exception as e:
            logger.debug(f"Massive reference chain attack failed: {e}")

        return dataset

    def _reference_type_mismatch(self, dataset: Dataset) -> Dataset:
        """Reference objects of wrong type.

        Reference a CT when expecting MR, or SR when expecting image.
        """
        try:
            # Claim to be CT but reference MR images
            dataset.Modality = "CT"
            dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT

            ref_item = Dataset()
            ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.4"  # MR!
            ref_item.ReferencedSOPInstanceUID = generate_uid()

            dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([ref_item]))

            # Also add a non-image reference where image expected
            non_image_ref = Dataset()
            non_image_ref.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.88.11"  # SR!
            non_image_ref.ReferencedSOPInstanceUID = generate_uid()

            dataset[Tag(0x0008, 0x1140)].value.append(non_image_ref)

        except Exception as e:
            logger.debug(f"Reference type mismatch attack failed: {e}")

        return dataset
