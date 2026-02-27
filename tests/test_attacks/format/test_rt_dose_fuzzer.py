"""Tests for RTDoseFuzzer - RT Dose specific mutations.

Covers all 5 attack methods with 5 variants each, plus integration tests.
Uses retry-loop pattern with random.seed() to exercise all random branches.
"""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.format.rt_dose_fuzzer import (
    _RT_DOSE_SOP_CLASS_UID,
    RTDoseFuzzer,
)


@pytest.fixture
def fuzzer() -> RTDoseFuzzer:
    return RTDoseFuzzer()


@pytest.fixture
def rt_dose_dataset() -> Dataset:
    """Rich RT Dose dataset with all attackable structures populated."""
    ds = Dataset()
    ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
    ds.Modality = "RTDOSE"
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.FrameOfReferenceUID = generate_uid()

    # Dose grid parameters
    ds.DoseGridScaling = "0.001"
    ds.DoseUnits = "GY"
    ds.DoseType = "PHYSICAL"
    ds.DoseSummationType = "PLAN"
    ds.TissueHeterogeneityCorrection = "IMAGE"

    # Multi-frame dose grid
    ds.NumberOfFrames = "3"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 32
    ds.BitsStored = 32
    ds.HighBit = 31
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.GridFrameOffsetVector = ["0.0", "2.5", "5.0"]
    ds.PixelData = b"\x00" * (64 * 64 * 4 * 3)

    # DVH Sequence
    dvh_item = Dataset()
    dvh_item.DVHType = "CUMULATIVE"
    dvh_item.DVHDoseScaling = "1.0"
    dvh_item.DVHVolumeUnits = "CM3"
    dvh_item.DVHNumberOfBins = 3
    dvh_item.DVHData = ["0.5", "100.0", "25.0", "60.0", "50.0", "10.0"]
    dvh_item.DVHMinimumDose = "0.5"
    dvh_item.DVHMaximumDose = "50.0"
    dvh_item.DVHMeanDose = "25.0"

    dvh_roi_ref = Dataset()
    dvh_roi_ref.ReferencedROINumber = 1
    dvh_item.DVHReferencedROISequence = Sequence([dvh_roi_ref])

    ds.DVHSequence = Sequence([dvh_item])

    # Referenced RT Plan Sequence
    fraction_item = Dataset()
    fraction_item.ReferencedFractionGroupNumber = 1

    beam_item = Dataset()
    beam_item.ReferencedBeamNumber = 1

    plan_item = Dataset()
    plan_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.481.5"
    plan_item.ReferencedSOPInstanceUID = generate_uid()
    plan_item.ReferencedFractionGroupSequence = Sequence([fraction_item])
    plan_item.ReferencedBeamSequence = Sequence([beam_item])

    ds.ReferencedRTPlanSequence = Sequence([plan_item])

    return ds


class TestCanMutate:
    def test_accepts_rt_dose_sop(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
        assert fuzzer.can_mutate(ds) is True

    def test_rejects_ct_sop(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_rejects_missing_sop(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False


class TestDoseGridScalingAttack:
    def test_zero_scaling(self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_grid_scaling_attack(ds)
            scaling = getattr(result, "DoseGridScaling", None)
            if scaling is not None and str(scaling) == "0.0":
                return
        pytest.fail("zero_scaling attack never triggered")

    def test_negative_scaling(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_grid_scaling_attack(ds)
            scaling = getattr(result, "DoseGridScaling", None)
            if scaling is not None and str(scaling) == "-0.001":
                return
        pytest.fail("negative_scaling attack never triggered")

    def test_nan_scaling(self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_grid_scaling_attack(ds)
            scaling = getattr(result, "DoseGridScaling", None)
            if scaling is not None and str(scaling) in ("NaN", "Inf", "-Inf"):
                return
        pytest.fail("nan_scaling attack never triggered")

    def test_extreme_scaling(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_grid_scaling_attack(ds)
            scaling = getattr(result, "DoseGridScaling", None)
            if scaling is not None and str(scaling) in ("1e308", "1e-308"):
                return
        pytest.fail("extreme_scaling attack never triggered")

    def test_remove_scaling(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_grid_scaling_attack(ds)
            if "DoseGridScaling" not in result:
                return
        pytest.fail("remove_scaling attack never triggered")

    def test_handles_missing_scaling(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._dose_grid_scaling_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestDvhSequenceCorruption:
    def test_truncated_dvh_data(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dvh_sequence_corruption(ds)
            dvh_seq = getattr(result, "DVHSequence", None)
            if dvh_seq and len(dvh_seq) > 0:
                dvh_data = getattr(dvh_seq[0], "DVHData", None)
                if dvh_data is not None and len(dvh_data) % 2 != 0:
                    return
        pytest.fail("truncated_dvh_data attack never triggered")

    def test_nan_dvh_values(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dvh_sequence_corruption(ds)
            dvh_seq = getattr(result, "DVHSequence", None)
            if dvh_seq and len(dvh_seq) > 0:
                dvh_data = getattr(dvh_seq[0], "DVHData", None)
                if dvh_data and "NaN" in [str(v) for v in dvh_data]:
                    return
        pytest.fail("nan_dvh_values attack never triggered")

    def test_bin_count_mismatch(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dvh_sequence_corruption(ds)
            dvh_seq = getattr(result, "DVHSequence", None)
            if dvh_seq and len(dvh_seq) > 0:
                bins = getattr(dvh_seq[0], "DVHNumberOfBins", None)
                if bins is not None and int(bins) == 999:
                    return
        pytest.fail("bin_count_mismatch attack never triggered")

    def test_inverted_statistics(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dvh_sequence_corruption(ds)
            dvh_seq = getattr(result, "DVHSequence", None)
            if dvh_seq and len(dvh_seq) > 0:
                min_dose = getattr(dvh_seq[0], "DVHMinimumDose", None)
                max_dose = getattr(dvh_seq[0], "DVHMaximumDose", None)
                if (
                    min_dose is not None
                    and max_dose is not None
                    and float(min_dose) > float(max_dose)
                ):
                    return
        pytest.fail("inverted_statistics attack never triggered")

    def test_remove_dvh_sequence(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dvh_sequence_corruption(ds)
            if "DVHSequence" not in result:
                return
        pytest.fail("remove_dvh_sequence attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._dvh_sequence_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestGridFrameOffsetAttack:
    def test_length_mismatch(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._grid_frame_offset_attack(ds)
            offsets = getattr(result, "GridFrameOffsetVector", None)
            n_frames = getattr(result, "NumberOfFrames", None)
            if offsets is not None and n_frames is not None:
                if len(offsets) != int(n_frames):
                    return
        pytest.fail("length_mismatch attack never triggered")

    def test_non_monotonic(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._grid_frame_offset_attack(ds)
            offsets = getattr(result, "GridFrameOffsetVector", None)
            if offsets is not None and len(offsets) >= 3:
                vals = [float(v) for v in offsets]
                if any(vals[j] > vals[j + 1] for j in range(len(vals) - 1)):
                    return
        pytest.fail("non_monotonic attack never triggered")

    def test_nan_offsets(self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._grid_frame_offset_attack(ds)
            offsets = getattr(result, "GridFrameOffsetVector", None)
            if offsets is not None:
                str_vals = [str(v) for v in offsets]
                if any(v in ("NaN", "Inf", "-Inf") for v in str_vals):
                    return
        pytest.fail("nan_offsets attack never triggered")

    def test_reversed_order(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._grid_frame_offset_attack(ds)
            offsets = getattr(result, "GridFrameOffsetVector", None)
            if offsets is not None and len(offsets) >= 2:
                vals = [float(v) for v in offsets]
                if vals == sorted(vals, reverse=True) and vals[0] > vals[-1]:
                    return
        pytest.fail("reversed_order attack never triggered")

    def test_remove_offsets(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._grid_frame_offset_attack(ds)
            if "GridFrameOffsetVector" not in result:
                return
        pytest.fail("remove_offsets attack never triggered")

    def test_handles_missing_offsets(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._grid_frame_offset_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestDoseTypeEnumerationAttack:
    def test_invalid_dose_type(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_type_enumeration_attack(ds)
            dose_type = getattr(result, "DoseType", None)
            if dose_type is not None and str(dose_type) not in (
                "PHYSICAL",
                "EFFECTIVE",
                "ERROR",
                "",
            ):
                return
        pytest.fail("invalid_dose_type attack never triggered")

    def test_invalid_summation_type(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_type_enumeration_attack(ds)
            summation = getattr(result, "DoseSummationType", None)
            if summation is not None and str(summation) not in (
                "PLAN",
                "MULTI_PLAN",
                "FRACTION",
                "BEAM",
                "BRACHY",
                "FRACTION_SESSION",
                "BEAM_SESSION",
                "BRACHY_SESSION",
                "CONTROL_POINT",
                "",
            ):
                return
        pytest.fail("invalid_summation_type attack never triggered")

    def test_invalid_dose_units(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_type_enumeration_attack(ds)
            units = getattr(result, "DoseUnits", None)
            if units is not None and str(units) not in ("GY", "RELATIVE", ""):
                return
        pytest.fail("invalid_dose_units attack never triggered")

    def test_empty_enums(self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_type_enumeration_attack(ds)
            dose_type = getattr(result, "DoseType", None)
            summation = getattr(result, "DoseSummationType", None)
            units = getattr(result, "DoseUnits", None)
            if (
                dose_type is not None
                and str(dose_type) == ""
                and summation is not None
                and str(summation) == ""
                and units is not None
                and str(units) == ""
            ):
                return
        pytest.fail("empty_enums attack never triggered")

    def test_remove_enums(self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._dose_type_enumeration_attack(ds)
            if (
                "DoseType" not in result
                and "DoseSummationType" not in result
                and "DoseUnits" not in result
            ):
                return
        pytest.fail("remove_enums attack never triggered")

    def test_handles_missing_enums(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._dose_type_enumeration_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestReferencedRtPlanCorruption:
    def test_invalid_plan_uid(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._referenced_rt_plan_corruption(ds)
            ref_seq = getattr(result, "ReferencedRTPlanSequence", None)
            if ref_seq and len(ref_seq) > 0:
                uid = getattr(ref_seq[0], "ReferencedSOPInstanceUID", None)
                if uid is not None and str(uid) == "INVALID_UID":
                    return
        pytest.fail("invalid_plan_uid attack never triggered")

    def test_orphan_beam_ref(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._referenced_rt_plan_corruption(ds)
            ref_seq = getattr(result, "ReferencedRTPlanSequence", None)
            if ref_seq and len(ref_seq) > 0:
                beam_seq = getattr(ref_seq[0], "ReferencedBeamSequence", None)
                if beam_seq and len(beam_seq) > 0:
                    beam_num = getattr(beam_seq[0], "ReferencedBeamNumber", None)
                    if beam_num is not None and int(beam_num) == 9999:
                        return
        pytest.fail("orphan_beam_ref attack never triggered")

    def test_missing_fraction_ref(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._referenced_rt_plan_corruption(ds)
            ref_seq = getattr(result, "ReferencedRTPlanSequence", None)
            if ref_seq and len(ref_seq) > 0:
                if not hasattr(ref_seq[0], "ReferencedFractionGroupSequence"):
                    return
        pytest.fail("missing_fraction_ref attack never triggered")

    def test_empty_plan_sequence(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._referenced_rt_plan_corruption(ds)
            ref_seq = getattr(result, "ReferencedRTPlanSequence", None)
            if ref_seq is not None and len(ref_seq) == 0:
                return
        pytest.fail("empty_plan_sequence attack never triggered")

    def test_remove_plan_ref(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(rt_dose_dataset)
            result = fuzzer._referenced_rt_plan_corruption(ds)
            if "ReferencedRTPlanSequence" not in result:
                return
        pytest.fail("remove_plan_ref attack never triggered")

    def test_handles_missing_sequences(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _RT_DOSE_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._referenced_rt_plan_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestMutateIntegration:
    def test_returns_dataset(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        result = fuzzer.mutate(copy.deepcopy(rt_dose_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        for _ in range(10):
            fuzzer.mutate(copy.deepcopy(rt_dose_dataset))

    def test_modifies_dataset(
        self, fuzzer: RTDoseFuzzer, rt_dose_dataset: Dataset
    ) -> None:
        original = copy.deepcopy(rt_dose_dataset)
        for _ in range(10):
            result = fuzzer.mutate(copy.deepcopy(rt_dose_dataset))
            if result != original:
                return
        pytest.fail("mutate() never modified the dataset")

    def test_handles_empty_dataset(self, fuzzer: RTDoseFuzzer) -> None:
        ds = Dataset()
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
