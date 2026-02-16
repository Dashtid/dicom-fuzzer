"""Tests for pixel_fuzzer.py - Pixel Data Metadata Mutations.

Tests cover pixel metadata mutation strategies.
"""

from unittest.mock import MagicMock

from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer


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
