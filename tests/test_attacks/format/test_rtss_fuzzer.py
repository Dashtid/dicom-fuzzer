"""Tests for RTStructureSetFuzzer -- RT Structure Set DICOM mutations.

Covers all 5 attack strategies:
- ContourData float array corruption
- Contour point count vs actual data length mismatches
- ROI cross-reference integrity violations
- ContourGeometricType mismatches
- Frame of Reference corruption
"""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.format.rtss_fuzzer import (
    _RTSS_SOP_CLASS_UID,
    RTStructureSetFuzzer,
)


@pytest.fixture
def fuzzer() -> RTStructureSetFuzzer:
    return RTStructureSetFuzzer()


@pytest.fixture
def rtss_dataset() -> Dataset:
    """Realistic RT Structure Set dataset with 2 ROIs."""
    ds = Dataset()
    ds.SOPClassUID = _RTSS_SOP_CLASS_UID
    ds.Modality = "RTSTRUCT"
    ds.FrameOfReferenceUID = generate_uid()

    # StructureSetROISequence -- 2 ROIs
    roi1 = Dataset()
    roi1.ROINumber = 1
    roi1.ROIName = "Body"
    roi1.ROIGenerationAlgorithm = "AUTOMATIC"

    roi2 = Dataset()
    roi2.ROINumber = 2
    roi2.ROIName = "PTV"
    roi2.ROIGenerationAlgorithm = "MANUAL"

    ds.StructureSetROISequence = Sequence([roi1, roi2])

    # ROIContourSequence -- contours for each ROI
    contour1 = Dataset()
    contour1.ContourGeometricType = "CLOSED_PLANAR"
    contour1.NumberOfContourPoints = 4
    contour1.ContourData = [
        "0.0",
        "0.0",
        "0.0",
        "10.0",
        "0.0",
        "0.0",
        "10.0",
        "10.0",
        "0.0",
        "0.0",
        "10.0",
        "0.0",
    ]

    roi_contour1 = Dataset()
    roi_contour1.ReferencedROINumber = 1
    roi_contour1.ContourSequence = Sequence([contour1])

    contour2 = Dataset()
    contour2.ContourGeometricType = "CLOSED_PLANAR"
    contour2.NumberOfContourPoints = 4
    contour2.ContourData = [
        "2.0",
        "2.0",
        "0.0",
        "8.0",
        "2.0",
        "0.0",
        "8.0",
        "8.0",
        "0.0",
        "2.0",
        "8.0",
        "0.0",
    ]

    roi_contour2 = Dataset()
    roi_contour2.ReferencedROINumber = 2
    roi_contour2.ContourSequence = Sequence([contour2])

    ds.ROIContourSequence = Sequence([roi_contour1, roi_contour2])

    # RTROIObservationsSequence
    obs1 = Dataset()
    obs1.ObservationNumber = 1
    obs1.ReferencedROINumber = 1
    obs1.RTROIInterpretedType = "EXTERNAL"

    obs2 = Dataset()
    obs2.ObservationNumber = 2
    obs2.ReferencedROINumber = 2
    obs2.RTROIInterpretedType = "PTV"

    ds.RTROIObservationsSequence = Sequence([obs1, obs2])

    # ReferencedFrameOfReferenceSequence
    study_ref = Dataset()
    study_ref.ReferencedSOPClassUID = "1.2.840.10008.3.1.2.3.1"
    study_ref.ReferencedSOPInstanceUID = generate_uid()

    frame_ref = Dataset()
    frame_ref.FrameOfReferenceUID = ds.FrameOfReferenceUID
    frame_ref.RTReferencedStudySequence = Sequence([study_ref])

    ds.ReferencedFrameOfReferenceSequence = Sequence([frame_ref])

    return ds


class TestCanMutate:
    def test_accepts_rtss_sop(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        assert fuzzer.can_mutate(rtss_dataset) is True

    def test_rejects_ct_sop(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_rejects_missing_sop(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False


class TestContourDataCorruption:
    def test_nan_coordinates(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_data_corruption(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cd = getattr(contour, "ContourData", None)
                if cd is not None and len(cd) > 0 and "NaN" in str(cd[0]):
                    return
        pytest.fail("nan_coordinates attack never triggered")

    def test_truncated_triplet(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_data_corruption(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cd = getattr(contour, "ContourData", None)
                if cd is not None and len(cd) == 2:
                    return
        pytest.fail("truncated_triplet attack never triggered")

    def test_empty_contour(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_data_corruption(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cd = getattr(contour, "ContourData", None)
                if cd is not None and len(cd) == 0:
                    return
        pytest.fail("empty_contour attack never triggered")

    def test_extreme_values(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_data_corruption(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cd = getattr(contour, "ContourData", None)
                if cd is not None and len(cd) > 0 and "1e308" in str(cd[0]):
                    return
        pytest.fail("extreme_values attack never triggered")

    def test_remove_contour_data(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_data_corruption(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None and "ContourData" not in contour:
                return
        pytest.fail("remove_contour_data attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RTSS_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._contour_data_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestContourPointCountMismatch:
    def test_inflated_count(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_point_count_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                ncp = getattr(contour, "NumberOfContourPoints", None)
                if ncp is not None and int(ncp) == 999:
                    return
        pytest.fail("inflated_count attack never triggered")

    def test_zero_with_data(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_point_count_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                ncp = getattr(contour, "NumberOfContourPoints", None)
                cd = getattr(contour, "ContourData", None)
                if ncp is not None and int(ncp) == 0 and cd is not None and len(cd) > 0:
                    return
        pytest.fail("zero_with_data attack never triggered")

    def test_negative_count(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_point_count_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                ncp = getattr(contour, "NumberOfContourPoints", None)
                if ncp is not None and int(ncp) < 0:
                    return
        pytest.fail("negative_count attack never triggered")

    def test_deflated_count(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_point_count_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                ncp = getattr(contour, "NumberOfContourPoints", None)
                cd = getattr(contour, "ContourData", None)
                if (
                    ncp is not None
                    and cd is not None
                    and int(ncp) == 1
                    and len(cd) == 9
                ):
                    return
        pytest.fail("deflated_count attack never triggered")

    def test_remove_count(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_point_count_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None and "NumberOfContourPoints" not in contour:
                return
        pytest.fail("remove_count attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RTSS_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._contour_point_count_mismatch(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestRoiCrossReferenceAttack:
    def test_orphan_contour_ref(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._roi_cross_reference_attack(ds)
            roi_contour_seq = getattr(result, "ROIContourSequence", None)
            if roi_contour_seq and len(roi_contour_seq) > 0:
                ref = getattr(roi_contour_seq[0], "ReferencedROINumber", None)
                if ref is not None and int(ref) == 9999:
                    return
        pytest.fail("orphan_contour_ref attack never triggered")

    def test_orphan_observation_ref(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._roi_cross_reference_attack(ds)
            obs_seq = getattr(result, "RTROIObservationsSequence", None)
            if obs_seq and len(obs_seq) > 0:
                ref = getattr(obs_seq[0], "ReferencedROINumber", None)
                if ref is not None and int(ref) == 9999:
                    return
        pytest.fail("orphan_observation_ref attack never triggered")

    def test_duplicate_roi_numbers(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._roi_cross_reference_attack(ds)
            roi_seq = getattr(result, "StructureSetROISequence", None)
            if roi_seq and len(roi_seq) > 1:
                numbers = [int(item.ROINumber) for item in roi_seq]
                if len(numbers) != len(set(numbers)):
                    return
        pytest.fail("duplicate_roi_numbers attack never triggered")

    def test_missing_roi_sequence(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._roi_cross_reference_attack(ds)
            if "StructureSetROISequence" not in result:
                return
        pytest.fail("missing_roi_sequence attack never triggered")

    def test_remove_observations(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._roi_cross_reference_attack(ds)
            if "RTROIObservationsSequence" not in result:
                return
        pytest.fail("remove_observations attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RTSS_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._roi_cross_reference_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestContourGeometricTypeMismatch:
    def test_point_with_many_coords(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_geometric_type_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cgt = getattr(contour, "ContourGeometricType", None)
                ncp = getattr(contour, "NumberOfContourPoints", None)
                if (
                    cgt is not None
                    and str(cgt) == "POINT"
                    and ncp is not None
                    and int(ncp) == 100
                ):
                    return
        pytest.fail("point_with_many_coords attack never triggered")

    def test_invalid_type(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_geometric_type_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cgt = getattr(contour, "ContourGeometricType", None)
                if cgt is not None and str(cgt) not in (
                    "POINT",
                    "OPEN_PLANAR",
                    "CLOSED_PLANAR",
                    "",
                    "closed_planar",
                ):
                    return
        pytest.fail("invalid_type attack never triggered")

    def test_empty_type(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_geometric_type_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cgt = getattr(contour, "ContourGeometricType", None)
                if cgt is not None and str(cgt) == "":
                    return
        pytest.fail("empty_type attack never triggered")

    def test_type_case_mismatch(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_geometric_type_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None:
                cgt = getattr(contour, "ContourGeometricType", None)
                if cgt is not None and str(cgt) == "closed_planar":
                    return
        pytest.fail("type_case_mismatch attack never triggered")

    def test_remove_type(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._contour_geometric_type_mismatch(ds)
            contour = fuzzer._get_first_contour(result)
            if contour is not None and "ContourGeometricType" not in contour:
                return
        pytest.fail("remove_type attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RTSS_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._contour_geometric_type_mismatch(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestFrameOfReferenceCorruption:
    def test_invalid_uid(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._frame_of_reference_corruption(ds)
            ref_seq = getattr(result, "ReferencedFrameOfReferenceSequence", None)
            if ref_seq and len(ref_seq) > 0:
                uid = getattr(ref_seq[0], "FrameOfReferenceUID", None)
                if uid is not None and str(uid) == "INVALID_UID":
                    return
        pytest.fail("invalid_uid attack never triggered")

    def test_empty_sequence(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._frame_of_reference_corruption(ds)
            ref_seq = getattr(result, "ReferencedFrameOfReferenceSequence", None)
            if ref_seq is not None and len(ref_seq) == 0:
                return
        pytest.fail("empty_sequence attack never triggered")

    def test_missing_study_ref(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._frame_of_reference_corruption(ds)
            ref_seq = getattr(result, "ReferencedFrameOfReferenceSequence", None)
            if ref_seq and len(ref_seq) > 0:
                if not hasattr(ref_seq[0], "RTReferencedStudySequence"):
                    return
        pytest.fail("missing_study_ref attack never triggered")

    def test_duplicate_frames(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._frame_of_reference_corruption(ds)
            ref_seq = getattr(result, "ReferencedFrameOfReferenceSequence", None)
            if ref_seq and len(ref_seq) == 2:
                uid0 = str(getattr(ref_seq[0], "FrameOfReferenceUID", ""))
                uid1 = str(getattr(ref_seq[1], "FrameOfReferenceUID", ""))
                if uid0 == uid1 and uid0 != "":
                    return
        pytest.fail("duplicate_frames attack never triggered")

    def test_remove_frame_ref(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rtss_dataset)
            result = fuzzer._frame_of_reference_corruption(ds)
            if "ReferencedFrameOfReferenceSequence" not in result:
                return
        pytest.fail("remove_frame_ref attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RTSS_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._frame_of_reference_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestMutateIntegration:
    def test_returns_dataset(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        result = fuzzer.mutate(copy.deepcopy(rtss_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        for _ in range(10):
            fuzzer.mutate(copy.deepcopy(rtss_dataset))

    def test_modifies_dataset(
        self, fuzzer: RTStructureSetFuzzer, rtss_dataset: Dataset
    ) -> None:
        original = copy.deepcopy(rtss_dataset)
        for _ in range(10):
            result = fuzzer.mutate(copy.deepcopy(rtss_dataset))
            if result != original:
                return
        pytest.fail("mutate() never modified the dataset")

    def test_handles_empty_dataset(self, fuzzer: RTStructureSetFuzzer) -> None:
        ds = Dataset()
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
