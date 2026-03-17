"""Tests for pixel_fuzzer.py - Pixel Data Metadata Mutations.

Tests cover pixel metadata mutation strategies.
"""

from __future__ import annotations

from unittest.mock import MagicMock

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

    def test_byte_flip_changes_content(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Byte flip must change at least one byte of the buffer."""
        original = bytes(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_byte_flip(pixel_dataset)
        assert isinstance(result, Dataset)
        assert len(result.PixelData) == len(original)
        assert bytes(result.PixelData) != original

    def test_byte_flip_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Byte flip on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        result = fuzzer._pixel_data_byte_flip(ds)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_fill_pattern_all_same_byte(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """Fill pattern must produce a buffer where all bytes are identical."""
        original_len = len(pixel_dataset.PixelData)
        result = fuzzer._pixel_data_fill_pattern(pixel_dataset)
        assert isinstance(result, Dataset)
        data = bytes(result.PixelData)
        assert len(data) == original_len
        assert data == bytes([data[0]] * len(data))
        assert data[0] in (0x00, 0xFF)

    def test_fill_pattern_noop_without_pixel_data(self, fuzzer: PixelFuzzer) -> None:
        """Fill pattern on a dataset without PixelData must return unchanged."""
        ds = Dataset()
        result = fuzzer._pixel_data_fill_pattern(ds)
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

    def test_mutate_returns_dataset_with_pixel_data(
        self, fuzzer: PixelFuzzer, pixel_dataset: Dataset
    ) -> None:
        """mutate() must return a Dataset when PixelData is present."""
        result = fuzzer.mutate(pixel_dataset)
        assert isinstance(result, Dataset)
