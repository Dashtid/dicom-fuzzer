"""Tests for SecondaryCaptureFuzzer.

Verifies all 12 SC attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.secondary_capture_fuzzer import SecondaryCaptureFuzzer

_SC_SOP = "1.2.840.10008.5.1.4.1.1.7"
_SC_MULTIFRAME_BYTE_SOP = "1.2.840.10008.5.1.4.1.1.7.2"
_SC_MULTIFRAME_SINGLE_BIT_SOP = "1.2.840.10008.5.1.4.1.1.7.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sc_dataset() -> Dataset:
    """Return a minimal well-formed SC dataset."""
    from dicom_fuzzer.attacks.format.secondary_capture_fuzzer import _MINIMAL_PIXEL_DATA

    ds = Dataset()
    ds.SOPClassUID = _SC_SOP
    ds.Modality = "OT"
    ds.ConversionType = "WSD"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = _MINIMAL_PIXEL_DATA
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
    def fuzzer(self) -> SecondaryCaptureFuzzer:
        return SecondaryCaptureFuzzer()

    def test_true_for_sc_sop_class(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SC_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_multiframe_sc_sop_class(
        self, fuzzer: SecondaryCaptureFuzzer
    ) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SC_MULTIFRAME_BYTE_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_conversion_type_wsd(
        self, fuzzer: SecondaryCaptureFuzzer
    ) -> None:
        ds = Dataset()
        ds.ConversionType = "WSD"
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert SecondaryCaptureFuzzer().strategy_name == "secondary_capture"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> SecondaryCaptureFuzzer:
        return SecondaryCaptureFuzzer()

    def test_returns_dataset(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_sc_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        fuzzer.mutate(_sc_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: SecondaryCaptureFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_sc_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestColorSpaceMismatch:
    def test_rgb_with_samples_per_pixel_one(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._color_space_mismatch(ds)
        assert ds.PhotometricInterpretation == "RGB"
        assert ds.SamplesPerPixel == 1


class TestYcbcrNoCompression:
    def test_ycbcr_declared_on_uncompressed(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._ycbcr_no_compression(ds)
        assert ds.PhotometricInterpretation == "YBR_FULL_422"
        assert ds.SamplesPerPixel == 3


class TestFrameCountOverflow:
    def test_number_of_frames_large(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._frame_count_overflow(ds)
        assert ds.NumberOfFrames == 0xFFFF

    def test_pixel_data_shorter_than_declared(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._frame_count_overflow(ds)
        declared = 2 * 2 * ds.NumberOfFrames
        assert len(ds.PixelData) < declared


class TestMultiframeNoTiming:
    def test_number_of_frames_without_timing_attrs(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._multiframe_no_timing(ds)
        assert ds.NumberOfFrames == 10
        assert not hasattr(ds, "FrameTime")
        assert not hasattr(ds, "FrameTimeVector")


class TestBitsAllocated64:
    def test_bits_allocated_64(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._bits_allocated_64(ds)
        assert ds.BitsAllocated == 64
        assert ds.BitsStored == 64

    def test_pixel_data_too_short_for_64bit(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._bits_allocated_64(ds)
        # 2x2 at 64-bit = 32 bytes; actual is 4
        expected_64bit_size = 2 * 2 * 8
        assert len(ds.PixelData) < expected_64bit_size


class TestBitsAllocated1SizeMismatch:
    def test_bits_allocated_1(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._bits_allocated_1_size_mismatch(ds)
        assert ds.BitsAllocated == 1
        assert ds.BitsStored == 1

    def test_pixel_data_larger_than_bitpacked_size(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._bits_allocated_1_size_mismatch(ds)
        # 8x8 bitonal = 8 bytes; provided 100 bytes
        assert len(ds.PixelData) > 8


class TestNoPixelData:
    def test_pixel_data_removed(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._no_pixel_data(ds)
        assert not hasattr(ds, "PixelData")

    def test_sop_class_is_sc(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert str(ds.SOPClassUID) == _SC_SOP

    def test_large_display_dimensions(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert ds.Rows == 1920
        assert ds.Columns == 1080


class TestEmptyPixelData:
    def test_pixel_data_is_empty_bytes(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._empty_pixel_data(ds)
        assert ds.PixelData == b""

    def test_rows_and_columns_still_large(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._empty_pixel_data(ds)
        assert ds.Rows == 512
        assert ds.Columns == 512


class TestRgbaFourSamples:
    def test_rgb_with_four_samples(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._rgba_four_samples(ds)
        assert ds.PhotometricInterpretation == "RGB"
        assert ds.SamplesPerPixel == 4


class TestRowsZero:
    def test_rows_and_columns_zero(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._rows_zero(ds)
        assert ds.Rows == 0
        assert ds.Columns == 0

    def test_pixel_data_non_empty_despite_zero_dims(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._rows_zero(ds)
        assert len(ds.PixelData) > 0


class TestConversionTypeMissing:
    def test_conversion_type_removed(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._conversion_type_missing(ds)
        assert not hasattr(ds, "ConversionType")

    def test_multi_frame_sop_class_set(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        fuzzer._conversion_type_missing(ds)
        assert str(ds.SOPClassUID) == _SC_MULTIFRAME_BYTE_SOP


class TestPaletteColorMissingLut:
    def test_palette_color_without_lut_data(self) -> None:
        fuzzer = SecondaryCaptureFuzzer()
        ds = _sc_dataset()
        # Pre-set LUT to verify it gets removed
        ds.RedPaletteColorLookupTableData = bytes(512)
        fuzzer._palette_color_missing_lut(ds)
        assert ds.PhotometricInterpretation == "PALETTE COLOR"
        assert not hasattr(ds, "RedPaletteColorLookupTableData")


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_sc_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "secondary_capture" in names

    def test_strategy_count_includes_sc(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 34
