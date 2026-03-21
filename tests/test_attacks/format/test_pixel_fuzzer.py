"""Tests for pixel_fuzzer.py - Pixel Data Metadata Mutations.

Tests cover pixel metadata mutation strategies.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer


@pytest.fixture
def fuzzer() -> PixelFuzzer:
    return PixelFuzzer()


@pytest.fixture
def pixel_dataset() -> Dataset:
    """Minimal dataset with real PixelData bytes for pixel buffer tests."""
    ds = Dataset()
    ds.Rows = 4
    ds.Columns = 4
    ds.BitsAllocated = 8
    ds.SamplesPerPixel = 1
    ds.PixelData = bytes(range(16))  # 16 bytes, known content
    return ds


class TestPixelFuzzerInit:
    """Test PixelFuzzer initialization."""

    def test_init(self):
        """Test that PixelFuzzer can be instantiated."""
        fuzzer = PixelFuzzer()
        assert fuzzer is not None
        assert hasattr(fuzzer, "mutate")


class TestMutatePixels:
    """Test mutate method."""

    def test_mutate_no_pixel_data(self):
        """Test mutation when dataset has no PixelData."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=False)

        result = fuzzer.mutate(dataset)

        # Should return dataset unchanged
        assert result is dataset
        assert result is not None

    def test_returns_same_dataset_object(self):
        """Test that the same dataset object is returned."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=False)

        result = fuzzer.mutate(dataset)

        assert result is dataset
        assert result is not None


class TestPixelDataMutations:
    """Tests for raw PixelData buffer mutation methods."""

    def test_truncation_shrinks_buffer(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Truncation must produce a shorter buffer than the original."""
        original_len = len(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_truncation(pixel_dataset)
        assert isinstance(result, Dataset)
        assert len(result.PixelData) < original_len
        assert len(result.PixelData) >= 1

    def test_truncation_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Truncation on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        ds.Rows = 4
        result = fuzzer._pixel_data_truncation(ds)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_random_garbage_same_length(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Random garbage must preserve the original buffer length."""
        original_len = len(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_random_garbage(pixel_dataset)
        assert isinstance(result, Dataset)
        assert len(result.PixelData) == original_len

    def test_random_garbage_changes_content(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Random garbage must (almost certainly) differ from the original."""
        original = bytes(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_random_garbage(pixel_dataset)
        # With 16 random bytes the probability of an exact match is 1/256^16 ≈ 0
        assert bytes(result.PixelData) != original

    def test_random_garbage_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Random garbage on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        result = fuzzer._pixel_data_random_garbage(ds)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_oversized_grows_buffer(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Oversized attack must produce a buffer larger than the original."""
        original_len = len(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_oversized(pixel_dataset)
        assert isinstance(result, Dataset)
        assert len(result.PixelData) > original_len

    def test_oversized_original_prefix_preserved(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """The original pixel bytes must be at the start of the oversized buffer."""
        original = bytes(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_oversized(pixel_dataset)
        assert bytes(result.PixelData)[: len(original)] == original

    def test_oversized_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Oversized on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        result = fuzzer._pixel_data_oversized(ds)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_byte_flip_changes_content(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Byte flip must change at least one byte in the buffer."""
        original = bytes(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_byte_flip(pixel_dataset)
        assert isinstance(result, Dataset)
        assert bytes(result.PixelData) != original

    def test_byte_flip_preserves_length(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Byte flip must not change the buffer length."""
        original_len = len(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_byte_flip(pixel_dataset)
        assert len(result.PixelData) == original_len

    def test_byte_flip_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Byte flip on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        result = fuzzer._pixel_data_byte_flip(ds)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_fill_pattern_is_uniform(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Fill pattern must produce a buffer of all 0x00 or all 0xFF."""
        result = fuzzer._pixel_data_fill_pattern(pixel_dataset)
        assert isinstance(result, Dataset)
        buf = bytes(result.PixelData)
        assert all(b == 0x00 for b in buf) or all(b == 0xFF for b in buf)

    def test_fill_pattern_preserves_length(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Fill pattern must not change the buffer length."""
        original_len = len(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_fill_pattern(pixel_dataset)
        assert len(result.PixelData) == original_len

    def test_fill_pattern_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Fill pattern on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        result = fuzzer._pixel_data_fill_pattern(ds)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_mutate_returns_dataset_with_pixel_data(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """mutate() must return a Dataset when PixelData is present."""
        result = fuzzer.mutate(pixel_dataset)
        assert isinstance(result, Dataset)


class TestExtremeContradiction:
    """Tests for _extreme_contradiction."""

    def test_overflow_allocation_sets_all_four_fields(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """overflow_allocation must set Rows, Columns, BitsAllocated, SamplesPerPixel."""
        with patch("random.choice", return_value="overflow_allocation"):
            result = fuzzer._extreme_contradiction(pixel_dataset)
        assert result.Rows == 65535
        assert result.Columns == 65535
        assert result.BitsAllocated == 32
        assert result.SamplesPerPixel == 4

    def test_zero_product_sets_fields_to_zero(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """zero_product must set all four allocation fields to zero."""
        with patch("random.choice", return_value="zero_product"):
            result = fuzzer._extreme_contradiction(pixel_dataset)
        assert result.Rows == 0
        assert result.Columns == 0
        assert result.BitsAllocated == 0
        assert result.SamplesPerPixel == 0

    def test_color_space_conflict_sets_contradicting_fields(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """color_space_conflict must produce MONOCHROME2 with SamplesPerPixel=3."""
        with patch("random.choice", return_value="color_space_conflict"):
            result = fuzzer._extreme_contradiction(pixel_dataset)
        assert result.SamplesPerPixel == 3
        assert result.PhotometricInterpretation == "MONOCHROME2"
        assert result.BitsAllocated == 128
        assert result.Rows == 65535

    def test_max_all_fields_sets_extreme_values(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """max_all_fields must set all allocation-math fields to extreme values."""
        with patch("random.choice", return_value="max_all_fields"):
            result = fuzzer._extreme_contradiction(pixel_dataset)
        assert result.Rows == 4294967295
        assert result.Columns == 4294967295
        assert result.BitsAllocated == 255
        assert result.SamplesPerPixel == 65535

    def test_returns_dataset_on_empty_input(self, fuzzer: PixelFuzzer) -> None:
        """Method must return a Dataset even when allocation fields are absent."""
        ds = Dataset()
        result = fuzzer._extreme_contradiction(ds)
        assert isinstance(result, Dataset)

    def test_returns_dataset(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """Method must always return a Dataset."""
        result = fuzzer._extreme_contradiction(pixel_dataset)
        assert isinstance(result, Dataset)


class TestPixelRepresentationAttack:
    """Tests for _pixel_representation_attack."""

    def test_flip_sign_unsigned_to_signed(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """flip_sign variant must flip 0 to 1."""
        pixel_dataset.PixelRepresentation = 0
        with patch("random.choice", return_value="flip_sign"):
            result = fuzzer._pixel_representation_attack(pixel_dataset)
        assert result.PixelRepresentation == 1

    def test_flip_sign_signed_to_unsigned(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """flip_sign variant must flip 1 to 0."""
        pixel_dataset.PixelRepresentation = 1
        with patch("random.choice", return_value="flip_sign"):
            result = fuzzer._pixel_representation_attack(pixel_dataset)
        assert result.PixelRepresentation == 0

    def test_invalid_value_sets_out_of_range(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """invalid_value variant must set PixelRepresentation outside {0, 1}."""
        pixel_dataset.PixelRepresentation = 0
        with patch("random.choice", side_effect=["invalid_value", 255]):
            result = fuzzer._pixel_representation_attack(pixel_dataset)
        assert result.PixelRepresentation not in (0, 1)

    def test_returns_dataset_without_field(self, fuzzer: PixelFuzzer) -> None:
        """Method must return a Dataset even when PixelRepresentation is absent."""
        ds = Dataset()
        result = fuzzer._pixel_representation_attack(ds)
        assert isinstance(result, Dataset)

    def test_returns_dataset(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """Method must always return a Dataset."""
        result = fuzzer._pixel_representation_attack(pixel_dataset)
        assert isinstance(result, Dataset)


class TestNumberOfFramesMismatch:
    """Tests for _number_of_frames_mismatch."""

    def test_over_declare_multiplies_frame_count(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """over_declare variant must set NumberOfFrames > original value."""
        pixel_dataset.NumberOfFrames = 1
        with (
            patch("random.choice", return_value="over_declare"),
            patch("random.randint", return_value=50),
        ):
            result = fuzzer._number_of_frames_mismatch(pixel_dataset)
        assert result.NumberOfFrames == 50

    def test_extreme_sets_large_value(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """extreme variant must set a large NumberOfFrames value."""
        with patch("random.choice", side_effect=["extreme", 65535]):
            result = fuzzer._number_of_frames_mismatch(pixel_dataset)
        assert result.NumberOfFrames == 65535

    def test_zero_variant(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """zero variant must set NumberOfFrames to 0."""
        with patch("random.choice", return_value="zero"):
            result = fuzzer._number_of_frames_mismatch(pixel_dataset)
        assert result.NumberOfFrames == 0

    def test_sets_field_on_single_frame_seed(self, fuzzer: PixelFuzzer) -> None:
        """Method must set NumberOfFrames even when absent from seed."""
        ds = Dataset()
        ds.PixelData = bytes(16)
        result = fuzzer._number_of_frames_mismatch(ds)
        assert isinstance(result, Dataset)
        assert hasattr(result, "NumberOfFrames")

    def test_returns_dataset(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """Method must always return a Dataset."""
        result = fuzzer._number_of_frames_mismatch(pixel_dataset)
        assert isinstance(result, Dataset)


class TestPixelValueRangeAttack:
    """Tests for _pixel_value_range_attack."""

    def test_inverted_sets_smallest_greater_than_largest(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """inverted variant must produce SmallestImagePixelValue > LargestImagePixelValue."""
        with patch("random.choice", return_value="inverted"):
            result = fuzzer._pixel_value_range_attack(pixel_dataset)
        assert result.SmallestImagePixelValue > result.LargestImagePixelValue

    def test_same_value_produces_zero_width_range(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """same_value variant must set Smallest == Largest == 0."""
        with patch("random.choice", return_value="same_value"):
            result = fuzzer._pixel_value_range_attack(pixel_dataset)
        assert result.SmallestImagePixelValue == result.LargestImagePixelValue == 0

    def test_extreme_sets_both_fields(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """extreme variant must set both SmallestImagePixelValue and LargestImagePixelValue."""
        with patch("random.choice", return_value="extreme"):
            result = fuzzer._pixel_value_range_attack(pixel_dataset)
        assert hasattr(result, "SmallestImagePixelValue")
        assert hasattr(result, "LargestImagePixelValue")

    def test_returns_dataset_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Method must return a Dataset even on a minimal dataset."""
        ds = Dataset()
        result = fuzzer._pixel_value_range_attack(ds)
        assert isinstance(result, Dataset)

    def test_returns_dataset(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """Method must always return a Dataset."""
        result = fuzzer._pixel_value_range_attack(pixel_dataset)
        assert isinstance(result, Dataset)


class TestRescaleAttack:
    """Tests for _rescale_attack."""

    def test_zero_slope_sets_rescale_slope_to_zero(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """zero_slope variant must set RescaleSlope to '0'."""
        with patch("random.choice", return_value="zero_slope"):
            result = fuzzer._rescale_attack(pixel_dataset)
        assert str(result.RescaleSlope) == "0"

    def test_nan_slope_sets_field(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """nan_slope variant must attempt to set RescaleSlope; method must not raise."""
        with patch("random.choice", return_value="nan_slope"):
            result = fuzzer._rescale_attack(pixel_dataset)
        assert isinstance(result, Dataset)

    def test_inf_slope_sets_field(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """inf_slope variant must attempt to set RescaleSlope; method must not raise."""
        with patch("random.choice", return_value="inf_slope"):
            result = fuzzer._rescale_attack(pixel_dataset)
        assert isinstance(result, Dataset)

    def test_extreme_slope_sets_rescale_slope(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """extreme_slope variant must set RescaleSlope to a non-default value."""
        with patch("random.choice", side_effect=["extreme_slope", 1e38]):
            result = fuzzer._rescale_attack(pixel_dataset)
        assert isinstance(result, Dataset)
        assert hasattr(result, "RescaleSlope")

    def test_returns_dataset(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """Method must always return a Dataset."""
        result = fuzzer._rescale_attack(pixel_dataset)
        assert isinstance(result, Dataset)


class TestWindowAttack:
    """Tests for _window_attack."""

    def test_zero_width_sets_window_width_to_zero(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """zero_width variant must set WindowWidth to '0'."""
        with patch("random.choice", return_value="zero_width"):
            result = fuzzer._window_attack(pixel_dataset)
        assert float(result.WindowWidth) == 0.0

    def test_negative_width_sets_negative_value(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """negative_width variant must set WindowWidth to a negative value."""
        with patch("random.choice", side_effect=["negative_width", -255]):
            result = fuzzer._window_attack(pixel_dataset)
        assert float(result.WindowWidth) < 0

    def test_extreme_center_sets_window_center(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """extreme_center variant must set WindowCenter to an extreme value."""
        with patch("random.choice", side_effect=["extreme_center", 2147483647]):
            result = fuzzer._window_attack(pixel_dataset)
        assert hasattr(result, "WindowCenter")

    def test_both_zero_sets_center_and_width(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """both_zero variant must set WindowCenter=0 and WindowWidth=0."""
        with patch("random.choice", return_value="both_zero"):
            result = fuzzer._window_attack(pixel_dataset)
        assert float(result.WindowCenter) == 0.0
        assert float(result.WindowWidth) == 0.0

    def test_returns_dataset_without_existing_tags(self, fuzzer: PixelFuzzer) -> None:
        """Method must return a Dataset even when window tags are absent."""
        ds = Dataset()
        result = fuzzer._window_attack(ds)
        assert isinstance(result, Dataset)

    def test_returns_dataset(self, fuzzer: PixelFuzzer, pixel_dataset: Dataset) -> None:
        """Method must always return a Dataset."""
        result = fuzzer._window_attack(pixel_dataset)
        assert isinstance(result, Dataset)
