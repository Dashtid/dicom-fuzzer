"""Tests for ParametricMapFuzzer.

Verifies all 12 PM attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import math

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.parametric_map_fuzzer import ParametricMapFuzzer

_PM_SOP = "1.2.840.10008.5.1.4.1.1.30"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pm_dataset() -> Dataset:
    """Return a minimal well-formed Parametric Map dataset."""
    from dicom_fuzzer.attacks.format.parametric_map_fuzzer import (
        _MINIMAL_PIXEL_DATA_16,
        _build_rwv_item,
    )

    ds = Dataset()
    ds.SOPClassUID = _PM_SOP
    ds.Modality = "MR"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = 4
    ds.PixelSpacing = [1.0, 1.0]
    ds.SliceThickness = 5.0
    ds.PixelData = _MINIMAL_PIXEL_DATA_16 * 4
    ds.RealWorldValueMappingSequence = Sequence([_build_rwv_item()])
    ds.PerFrameFunctionalGroupsSequence = Sequence(
        [Dataset(), Dataset(), Dataset(), Dataset()]
    )
    return ds


def _bare_dataset() -> Dataset:
    ds = Dataset()
    ds.PatientName = "FUZZER^TEST"
    return ds


# ---------------------------------------------------------------------------
# can_mutate()
# ---------------------------------------------------------------------------


class TestCanMutate:
    @pytest.fixture
    def fuzzer(self) -> ParametricMapFuzzer:
        return ParametricMapFuzzer()

    def test_true_for_pm_sop_class(self, fuzzer: ParametricMapFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _PM_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_rwv_sequence(
        self, fuzzer: ParametricMapFuzzer
    ) -> None:
        ds = Dataset()
        ds.RealWorldValueMappingSequence = Sequence([])
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset(self, fuzzer: ParametricMapFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: ParametricMapFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert ParametricMapFuzzer().strategy_name == "parametric_map"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> ParametricMapFuzzer:
        return ParametricMapFuzzer()

    def test_returns_dataset(self, fuzzer: ParametricMapFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_pm_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: ParametricMapFuzzer) -> None:
        fuzzer.mutate(_pm_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: ParametricMapFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: ParametricMapFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_pm_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestRwvSlopeZero:
    def test_slope_is_zero(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._rwv_slope_zero(ds)
        assert ds.RealWorldValueMappingSequence[0].RealWorldValueSlope == 0.0


class TestRwvSlopeNan:
    def test_slope_is_nan(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._rwv_slope_nan(ds)
        assert math.isnan(ds.RealWorldValueMappingSequence[0].RealWorldValueSlope)


class TestRwvInterceptInf:
    def test_intercept_is_inf(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._rwv_intercept_inf(ds)
        assert math.isinf(ds.RealWorldValueMappingSequence[0].RealWorldValueIntercept)


class TestFrameCountOverflow:
    def test_number_of_frames_large(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._frame_count_overflow(ds)
        assert ds.NumberOfFrames == 0xFFFF

    def test_pixel_data_shorter_than_declared(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._frame_count_overflow(ds)
        declared = 2 * 2 * 2 * ds.NumberOfFrames  # rows*cols*bytes*frames
        assert len(ds.PixelData) < declared


class TestNoPixelData:
    def test_pixel_data_removed(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._no_pixel_data(ds)
        assert not hasattr(ds, "PixelData")

    def test_sop_class_is_pm(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert str(ds.SOPClassUID) == _PM_SOP

    def test_clinical_dimensions_set(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert ds.Rows == 256
        assert ds.Columns == 256
        assert ds.NumberOfFrames == 30


class TestRwvMappingEmpty:
    def test_mapping_sequence_is_empty(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._rwv_mapping_empty(ds)
        assert len(ds.RealWorldValueMappingSequence) == 0


class TestBitsAllocMismatch:
    def test_bits_allocated_32_stored_16_high_bit_11(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._bits_alloc_mismatch(ds)
        assert ds.BitsAllocated == 32
        assert ds.BitsStored == 16
        assert ds.HighBit == 11  # inconsistent: should be 15


class TestMeasurementUnitsMissing:
    def test_rwv_item_has_no_units(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._measurement_units_missing(ds)
        item = ds.RealWorldValueMappingSequence[0]
        assert not hasattr(item, "MeasurementUnitsCodeSequence")


class TestFirstValueGtLast:
    def test_first_value_greater_than_last(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._first_value_gt_last(ds)
        item = ds.RealWorldValueMappingSequence[0]
        assert item.RealWorldValueFirstValueMapped > item.RealWorldValueLastValueMapped


class TestPixelSpacingZero:
    def test_pixel_spacing_zero(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._pixel_spacing_zero(ds)
        assert ds.PixelSpacing[0] == 0.0
        assert ds.PixelSpacing[1] == 0.0


class TestSliceThicknessNegative:
    def test_slice_thickness_negative(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._slice_thickness_negative(ds)
        assert ds.SliceThickness < 0


class TestPerFrameFunctionalEmpty:
    def test_per_frame_sequence_is_empty(self) -> None:
        fuzzer = ParametricMapFuzzer()
        ds = _pm_dataset()
        fuzzer._per_frame_functional_empty(ds)
        assert len(ds.PerFrameFunctionalGroupsSequence) == 0


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_pm_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "parametric_map" in names

    def test_strategy_count_at_least_40(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 40
