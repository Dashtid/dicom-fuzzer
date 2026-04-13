"""Tests for UltrasoundFuzzer.

Verifies all 12 US attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import math

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.ultrasound_fuzzer import UltrasoundFuzzer

_US_MULTIFRAME_SOP = "1.2.840.10008.5.1.4.1.1.3.1"
_US_IMAGE_SOP = "1.2.840.10008.5.1.4.1.1.6.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _us_dataset() -> Dataset:
    """Return a minimal well-formed US multi-frame dataset."""
    from dicom_fuzzer.attacks.format.ultrasound_fuzzer import (
        _MINIMAL_PIXEL_DATA,
        _build_us_region,
    )

    ds = Dataset()
    ds.SOPClassUID = _US_MULTIFRAME_SOP
    ds.Modality = "US"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = 3
    ds.FrameIncrementPointer = 0x00181065
    ds.PixelData = _MINIMAL_PIXEL_DATA * 3
    ds.SequenceOfUltrasoundRegions = Sequence([_build_us_region()])
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
    def fuzzer(self) -> UltrasoundFuzzer:
        return UltrasoundFuzzer()

    def test_true_for_us_image_sop_class(self, fuzzer: UltrasoundFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _US_IMAGE_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_us_multiframe_sop_class(self, fuzzer: UltrasoundFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _US_MULTIFRAME_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_region_sequence(
        self, fuzzer: UltrasoundFuzzer
    ) -> None:
        ds = Dataset()
        ds.SequenceOfUltrasoundRegions = Sequence([])
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_modality_us(self, fuzzer: UltrasoundFuzzer) -> None:
        ds = Dataset()
        ds.Modality = "US"
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_without_us_tags(self, fuzzer: UltrasoundFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: UltrasoundFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert UltrasoundFuzzer().strategy_name == "ultrasound"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> UltrasoundFuzzer:
        return UltrasoundFuzzer()

    def test_returns_dataset(self, fuzzer: UltrasoundFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_us_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: UltrasoundFuzzer) -> None:
        fuzzer.mutate(_us_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: UltrasoundFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: UltrasoundFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_us_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestFrameCountOverflow:
    def test_number_of_frames_large(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._frame_count_overflow(ds)
        assert ds.NumberOfFrames == 0xFFFFFF

    def test_pixel_data_far_shorter_than_declared(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._frame_count_overflow(ds)
        # rows=2, cols=2, 8-bit => declared ~= 2*2*0xFFFFFF >> 4 bytes
        declared = 2 * 2 * ds.NumberOfFrames
        assert len(ds.PixelData) < declared


class TestFrameCountZero:
    def test_number_of_frames_zero(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._frame_count_zero(ds)
        assert ds.NumberOfFrames == 0

    def test_pixel_data_non_empty(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._frame_count_zero(ds)
        assert len(ds.PixelData) > 0


class TestRegionOverlap:
    def test_two_regions_with_identical_coords(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._region_overlap(ds)
        regions = ds.SequenceOfUltrasoundRegions
        assert len(regions) == 2
        assert regions[0].RegionLocationMinX0 == regions[1].RegionLocationMinX0
        assert regions[0].RegionLocationMaxX1 == regions[1].RegionLocationMaxX1


class TestRegionMissingCoords:
    def test_region_has_no_bounding_box(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._region_missing_coords(ds)
        region = ds.SequenceOfUltrasoundRegions[0]
        assert not hasattr(region, "RegionLocationMinX0")
        assert not hasattr(region, "RegionLocationMinY0")


class TestDopplerNan:
    def test_physical_delta_is_nan(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._doppler_nan(ds)
        region = ds.SequenceOfUltrasoundRegions[0]
        assert math.isnan(region.PhysicalDeltaX)
        assert math.isnan(region.PhysicalDeltaY)


class TestDopplerNegative:
    def test_physical_delta_negative(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._doppler_negative(ds)
        region = ds.SequenceOfUltrasoundRegions[0]
        assert region.PhysicalDeltaX == -1.0
        assert region.PhysicalDeltaY == -1.0


class TestFrameIncrementPtrBad:
    def test_frame_increment_pointer_invalid(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._frame_increment_ptr_bad(ds)
        # Should point to 0x99990001 -- clearly nonexistent tag
        assert ds.FrameIncrementPointer == 0x99990001


class TestNoPixelData:
    def test_pixel_data_removed(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        assert hasattr(ds, "PixelData")
        fuzzer._no_pixel_data(ds)
        assert not hasattr(ds, "PixelData")

    def test_sop_class_set(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert str(ds.SOPClassUID) == _US_MULTIFRAME_SOP

    def test_rows_and_columns_set(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert ds.Rows == 512
        assert ds.Columns == 512


class TestBitsAllocMismatch:
    def test_high_bit_inconsistent(self) -> None:
        """HighBit=7 but BitsStored=12 -- should be 11."""
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._bits_alloc_mismatch(ds)
        assert ds.BitsAllocated == 16
        assert ds.BitsStored == 12
        assert ds.HighBit == 7  # inconsistent: should be BitsStored-1=11

    def test_pixel_data_too_short_for_16bit(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._bits_alloc_mismatch(ds)
        # 4 bytes of pixel data is too short for rows=2, cols=2 at 16 bits
        expected_16bit_size = 2 * 2 * 2  # rows * cols * (BitsAllocated/8)
        assert len(ds.PixelData) < expected_16bit_size


class TestPhotometricMismatch:
    def test_rgb_with_samples_per_pixel_one(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._photometric_mismatch(ds)
        assert ds.PhotometricInterpretation == "RGB"
        assert ds.SamplesPerPixel == 1


class TestCineRateZero:
    def test_display_frame_rate_zero(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._cine_rate_zero(ds)
        assert ds.RecommendedDisplayFrameRate == 0


class TestEmptyRegionSequence:
    def test_sequence_exists_but_empty(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _us_dataset()
        fuzzer._empty_region_sequence(ds)
        assert hasattr(ds, "SequenceOfUltrasoundRegions")
        assert len(ds.SequenceOfUltrasoundRegions) == 0

    def test_works_on_bare_dataset(self) -> None:
        fuzzer = UltrasoundFuzzer()
        ds = _bare_dataset()
        fuzzer._empty_region_sequence(ds)
        assert len(ds.SequenceOfUltrasoundRegions) == 0


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_ultrasound_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "ultrasound" in names

    def test_strategy_count_includes_ultrasound(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 36
