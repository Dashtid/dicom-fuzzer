"""RT Structure Set Fuzzer - DICOM RT Structure Set Mutations.

Category: modality-specific (RTSS)

Attacks:
- ContourData float array corruption (NaN, Inf, truncated triplets)
- Contour point count vs actual data length mismatches
- ROI cross-reference integrity violations
- ContourGeometricType mismatches with actual geometry
- Frame of Reference corruption
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_RTSS_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.481.3"


class RTStructureSetFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM RT Structure Set objects to test contour handling robustness.

    RT Structure Sets contain no pixel data. Their entire payload is
    deeply nested sequences: StructureSetROISequence ->
    ROIContourSequence -> ContourSequence -> ContourData. Corrupting
    these structures tests the viewer's geometric processing pipeline.
    """

    def __init__(self) -> None:
        """Initialize the RT structure set fuzzer with attack strategies."""
        super().__init__()
        self.mutation_strategies = [
            self._contour_data_corruption,
            self._contour_point_count_mismatch,
            self._roi_cross_reference_attack,
            self._contour_geometric_type_mismatch,
            self._frame_of_reference_corruption,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "rt_structure_set"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate RT Structure Set Storage datasets."""
        sop_class = getattr(dataset, "SOPClassUID", None)
        return str(sop_class) == _RTSS_SOP_CLASS_UID

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply RT structure set mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with contour/ROI corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("RT structure set mutation failed: %s", e)

        return dataset

    def _get_first_contour(self, dataset: Dataset) -> Dataset | None:
        """Walk ROIContourSequence > ContourSequence to find first contour item."""
        roi_contour_seq = getattr(dataset, "ROIContourSequence", None)
        if not roi_contour_seq or len(roi_contour_seq) == 0:
            return None
        contour_seq = getattr(roi_contour_seq[0], "ContourSequence", None)
        if not contour_seq or len(contour_seq) == 0:
            return None
        return contour_seq[0]

    def _ensure_contour(self, dataset: Dataset) -> Dataset:
        """Ensure dataset has ROIContourSequence > ContourSequence with one contour."""
        contour = self._get_first_contour(dataset)
        if contour is not None:
            return contour

        contour_item = Dataset()
        contour_item.ContourGeometricType = "CLOSED_PLANAR"
        contour_item.NumberOfContourPoints = 3
        contour_item.ContourData = [
            "0.0",
            "0.0",
            "0.0",
            "10.0",
            "0.0",
            "0.0",
            "10.0",
            "10.0",
            "0.0",
        ]

        roi_contour_item = Dataset()
        roi_contour_item.ReferencedROINumber = 1
        roi_contour_item.ContourSequence = Sequence([contour_item])
        dataset.ROIContourSequence = Sequence([roi_contour_item])
        return contour_item

    def _contour_data_corruption(self, dataset: Dataset) -> Dataset:
        """Inject malformed float triplets, NaN, Inf, or truncated arrays into ContourData."""
        attack = random.choice(
            [
                "nan_coordinates",
                "truncated_triplet",
                "empty_contour",
                "extreme_values",
                "remove_contour_data",
            ]
        )

        try:
            if attack == "nan_coordinates":
                contour = self._ensure_contour(dataset)
                contour.ContourData = ["NaN", "Inf", "-Inf", "1.0", "2.0", "3.0"]
                contour.NumberOfContourPoints = 2
            elif attack == "truncated_triplet":
                contour = self._ensure_contour(dataset)
                contour.ContourData = ["1.0", "2.0"]  # not a triplet
                contour.NumberOfContourPoints = 1
            elif attack == "empty_contour":
                contour = self._ensure_contour(dataset)
                contour.ContourData = []
                contour.NumberOfContourPoints = 0
            elif attack == "extreme_values":
                contour = self._ensure_contour(dataset)
                contour.ContourData = [
                    "1e308",
                    "-1e308",
                    "1e308",
                    "1e-308",
                    "1e-308",
                    "1e-308",
                ]
                contour.NumberOfContourPoints = 2
            elif attack == "remove_contour_data":
                contour = self._get_first_contour(dataset)
                if contour is not None and "ContourData" in contour:
                    del contour.ContourData
        except Exception as e:
            logger.debug("Contour data corruption failed: %s", e)

        return dataset

    def _contour_point_count_mismatch(self, dataset: Dataset) -> Dataset:
        """Create mismatches between NumberOfContourPoints and actual ContourData length."""
        attack = random.choice(
            [
                "inflated_count",
                "zero_with_data",
                "negative_count",
                "deflated_count",
                "remove_count",
            ]
        )

        try:
            if attack == "inflated_count":
                contour = self._ensure_contour(dataset)
                contour.ContourData = ["1.0", "2.0", "3.0"]
                contour.NumberOfContourPoints = 999  # says 999, only 1 triplet
            elif attack == "zero_with_data":
                contour = self._ensure_contour(dataset)
                contour.ContourData = [
                    "1.0",
                    "2.0",
                    "3.0",
                    "4.0",
                    "5.0",
                    "6.0",
                ]
                contour.NumberOfContourPoints = 0  # says 0, has 2 triplets
            elif attack == "negative_count":
                contour = self._ensure_contour(dataset)
                contour.NumberOfContourPoints = "-5"
            elif attack == "deflated_count":
                contour = self._ensure_contour(dataset)
                contour.ContourData = [
                    "1.0",
                    "2.0",
                    "3.0",
                    "4.0",
                    "5.0",
                    "6.0",
                    "7.0",
                    "8.0",
                    "9.0",
                ]
                contour.NumberOfContourPoints = 1  # says 1, has 3 triplets
            elif attack == "remove_count":
                contour = self._get_first_contour(dataset)
                if contour is not None and "NumberOfContourPoints" in contour:
                    del contour.NumberOfContourPoints
        except Exception as e:
            logger.debug("Contour point count mismatch failed: %s", e)

        return dataset

    def _roi_cross_reference_attack(self, dataset: Dataset) -> Dataset:
        """Break ROINumber / ReferencedROINumber consistency across sequences."""
        attack = random.choice(
            [
                "orphan_contour_ref",
                "orphan_observation_ref",
                "duplicate_roi_numbers",
                "missing_roi_sequence",
                "remove_observations",
            ]
        )

        try:
            if attack == "orphan_contour_ref":
                roi_contour_seq = getattr(dataset, "ROIContourSequence", None)
                if roi_contour_seq and len(roi_contour_seq) > 0:
                    roi_contour_seq[0].ReferencedROINumber = 9999
                else:
                    item = Dataset()
                    item.ReferencedROINumber = 9999
                    dataset.ROIContourSequence = Sequence([item])
            elif attack == "orphan_observation_ref":
                obs_seq = getattr(dataset, "RTROIObservationsSequence", None)
                if obs_seq and len(obs_seq) > 0:
                    obs_seq[0].ReferencedROINumber = 9999
                else:
                    item = Dataset()
                    item.ObservationNumber = 1
                    item.ReferencedROINumber = 9999
                    item.RTROIInterpretedType = "ORGAN"
                    dataset.RTROIObservationsSequence = Sequence([item])
            elif attack == "duplicate_roi_numbers":
                roi_seq = getattr(dataset, "StructureSetROISequence", None)
                if roi_seq and len(roi_seq) > 0:
                    for item in roi_seq:
                        item.ROINumber = 1  # all same number
                else:
                    item1 = Dataset()
                    item1.ROINumber = 1
                    item1.ROIName = "ROI_A"
                    item2 = Dataset()
                    item2.ROINumber = 1  # duplicate
                    item2.ROIName = "ROI_B"
                    dataset.StructureSetROISequence = Sequence([item1, item2])
            elif attack == "missing_roi_sequence":
                if "StructureSetROISequence" in dataset:
                    del dataset.StructureSetROISequence
            elif attack == "remove_observations":
                if "RTROIObservationsSequence" in dataset:
                    del dataset.RTROIObservationsSequence
        except Exception as e:
            logger.debug("ROI cross-reference attack failed: %s", e)

        return dataset

    def _contour_geometric_type_mismatch(self, dataset: Dataset) -> Dataset:
        """Set ContourGeometricType to values inconsistent with actual geometry."""
        attack = random.choice(
            [
                "point_with_many_coords",
                "invalid_type",
                "empty_type",
                "type_case_mismatch",
                "remove_type",
            ]
        )

        try:
            if attack == "point_with_many_coords":
                contour = self._ensure_contour(dataset)
                contour.ContourGeometricType = "POINT"
                contour.ContourData = [
                    str(float(i)) for i in range(300)
                ]  # 100 triplets for a "POINT"
                contour.NumberOfContourPoints = 100
            elif attack == "invalid_type":
                contour = self._ensure_contour(dataset)
                contour.ContourGeometricType = random.choice(
                    ["INVALID", "SPIRAL", "HELIX", "A" * 5000]
                )
            elif attack == "empty_type":
                contour = self._ensure_contour(dataset)
                contour.ContourGeometricType = ""
            elif attack == "type_case_mismatch":
                contour = self._ensure_contour(dataset)
                contour.ContourGeometricType = "closed_planar"  # lowercase
            elif attack == "remove_type":
                contour = self._get_first_contour(dataset)
                if contour is not None and "ContourGeometricType" in contour:
                    del contour.ContourGeometricType
        except Exception as e:
            logger.debug("Contour geometric type mismatch failed: %s", e)

        return dataset

    def _frame_of_reference_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt ReferencedFrameOfReferenceSequence spatial references."""
        attack = random.choice(
            [
                "invalid_uid",
                "empty_sequence",
                "missing_study_ref",
                "duplicate_frames",
                "remove_frame_ref",
            ]
        )

        try:
            if attack == "invalid_uid":
                ref_seq = getattr(dataset, "ReferencedFrameOfReferenceSequence", None)
                if ref_seq and len(ref_seq) > 0:
                    ref_seq[0].FrameOfReferenceUID = "INVALID_UID"
                else:
                    item = Dataset()
                    item.FrameOfReferenceUID = "INVALID_UID"
                    dataset.ReferencedFrameOfReferenceSequence = Sequence([item])
            elif attack == "empty_sequence":
                dataset.ReferencedFrameOfReferenceSequence = Sequence([])
            elif attack == "missing_study_ref":
                ref_seq = getattr(dataset, "ReferencedFrameOfReferenceSequence", None)
                if ref_seq and len(ref_seq) > 0:
                    if "RTReferencedStudySequence" in ref_seq[0]:
                        del ref_seq[0].RTReferencedStudySequence
                else:
                    item = Dataset()
                    item.FrameOfReferenceUID = generate_uid()
                    dataset.ReferencedFrameOfReferenceSequence = Sequence([item])
            elif attack == "duplicate_frames":
                item1 = Dataset()
                item1.FrameOfReferenceUID = generate_uid()
                item2 = Dataset()
                item2.FrameOfReferenceUID = item1.FrameOfReferenceUID
                dataset.ReferencedFrameOfReferenceSequence = Sequence([item1, item2])
            elif attack == "remove_frame_ref":
                if "ReferencedFrameOfReferenceSequence" in dataset:
                    del dataset.ReferencedFrameOfReferenceSequence
        except Exception as e:
            logger.debug("Frame of reference corruption failed: %s", e)

        return dataset


__all__ = ["RTStructureSetFuzzer"]
