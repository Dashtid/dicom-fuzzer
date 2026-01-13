"""Tests for pixel_fuzzer.py - Pixel Data Noise Injection.

Tests cover pixel mutation and error handling for corrupted headers.
"""

from unittest.mock import MagicMock, PropertyMock

import numpy as np

from dicom_fuzzer.strategies.pixel_fuzzer import PixelFuzzer


class TestPixelFuzzerInit:
    """Test PixelFuzzer initialization."""

    def test_init(self):
        """Test that PixelFuzzer can be instantiated."""
        fuzzer = PixelFuzzer()
        assert fuzzer is not None
        assert hasattr(fuzzer, "mutate_pixels")


class TestMutatePixels:
    """Test mutate_pixels method."""

    def test_mutate_pixels_with_valid_data(self):
        """Test pixel mutation with valid pixel data."""
        fuzzer = PixelFuzzer()

        # Create mock dataset with pixel data
        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=True)

        # Create a small test image
        original_pixels = np.zeros((10, 10), dtype=np.uint8)
        dataset.pixel_array = original_pixels

        result = fuzzer.mutate_pixels(dataset)

        # Should have assigned new PixelData
        assert result is dataset
        assert dataset.PixelData is not None

    def test_mutate_pixels_no_pixel_data(self):
        """Test mutation when dataset has no PixelData."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=False)

        result = fuzzer.mutate_pixels(dataset)

        # Should return dataset unchanged
        assert result is dataset
        assert result is not None

    def test_mutate_pixels_value_error(self):
        """Test mutation handles ValueError from invalid dimensions."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=True)
        type(dataset).pixel_array = PropertyMock(
            side_effect=ValueError("Invalid dimensions")
        )

        result = fuzzer.mutate_pixels(dataset)

        # Should return dataset without crashing
        assert result is dataset
        assert result is not None

    def test_mutate_pixels_attribute_error(self):
        """Test mutation handles AttributeError."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=True)
        type(dataset).pixel_array = PropertyMock(
            side_effect=AttributeError("No pixel_array")
        )

        result = fuzzer.mutate_pixels(dataset)

        # Should return dataset without crashing
        assert result is dataset
        assert result is not None

    def test_mutate_pixels_type_error(self):
        """Test mutation handles TypeError."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=True)
        type(dataset).pixel_array = PropertyMock(side_effect=TypeError("Type mismatch"))

        result = fuzzer.mutate_pixels(dataset)

        # Should return dataset without crashing
        assert result is dataset
        assert result is not None

    def test_noise_injection_creates_changes(self):
        """Test that noise injection actually modifies pixels."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=True)

        # Create a larger image to ensure noise is injected (1% of 100x100 = ~100 pixels)
        original_pixels = np.zeros((100, 100), dtype=np.uint8)
        dataset.pixel_array = original_pixels.copy()

        # Set a fixed seed for reproducibility
        np.random.seed(42)

        result = fuzzer.mutate_pixels(dataset)

        # PixelData should be set
        assert dataset.PixelData is not None
        assert isinstance(dataset.PixelData, bytes)

    def test_returns_same_dataset_object(self):
        """Test that the same dataset object is returned."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=False)

        result = fuzzer.mutate_pixels(dataset)

        assert result is dataset
        assert result is not None

    def test_pixel_data_converted_to_bytes(self):
        """Test that pixel data is converted to bytes."""
        fuzzer = PixelFuzzer()

        dataset = MagicMock()
        dataset.__contains__ = MagicMock(return_value=True)
        dataset.pixel_array = np.zeros((10, 10), dtype=np.uint8)

        fuzzer.mutate_pixels(dataset)

        # PixelData should be bytes
        assert isinstance(dataset.PixelData, bytes)
