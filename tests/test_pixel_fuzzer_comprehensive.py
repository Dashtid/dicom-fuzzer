"""Comprehensive tests for dicom_fuzzer.strategies.pixel_fuzzer module.

This test suite provides thorough coverage of pixel data fuzzing functionality,
including noise injection and error handling.
"""

from unittest.mock import Mock, patch

import numpy as np
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.pixel_fuzzer import PixelFuzzer


class TestPixelFuzzerBasics:
    """Test suite for basic PixelFuzzer functionality."""

    def test_initialization(self):
        """Test PixelFuzzer initialization."""
        fuzzer = PixelFuzzer()
        assert isinstance(fuzzer, PixelFuzzer)


class TestMutatePixels:
    """Test suite for mutate_pixels method."""

    def test_mutate_pixels_no_pixel_data(self):
        """Test mutation when dataset has no pixel data."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated = fuzzer.mutate_pixels(ds)

        assert isinstance(mutated, Dataset)
        assert mutated.PatientName == "Test"

    def test_mutate_pixels_with_pixel_data(self):
        """Test mutation with valid pixel data."""
        fuzzer = PixelFuzzer()
        ds = Dataset()

        # Create mock pixel array
        pixel_array = np.zeros((10, 10), dtype=np.uint8)
        ds.PixelData = pixel_array.tobytes()
        ds.Rows = 10
        ds.Columns = 10
        ds.SamplesPerPixel = 1
        ds.BitsAllocated = 8

        # Mock pixel_array property
        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array)):
            mutated = fuzzer.mutate_pixels(ds)

        assert isinstance(mutated, Dataset)
        assert hasattr(mutated, "PixelData")

    @patch("numpy.random.random")
    @patch("numpy.random.randint")
    def test_mutate_pixels_noise_injection(self, mock_randint, mock_random):
        """Test noise injection into pixel data."""
        # Setup mocks
        mock_random.return_value = np.array([[True, False], [False, True]])
        mock_randint.return_value = np.array([255, 128])

        fuzzer = PixelFuzzer()
        ds = Dataset()

        pixel_array = np.zeros((2, 2), dtype=np.uint8)
        ds.PixelData = pixel_array.tobytes()

        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array.copy())):
            mutated = fuzzer.mutate_pixels(ds)

        assert hasattr(mutated, "PixelData")

    def test_mutate_pixels_exception_handling_value_error(self):
        """Test handling of ValueError during pixel access."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PixelData = b"invalid_data"

        # Mock pixel_array to raise ValueError
        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: (_ for _ in ()).throw(ValueError("Invalid pixel data")))):
            mutated = fuzzer.mutate_pixels(ds)

        # Should return dataset without crashing
        assert isinstance(mutated, Dataset)

    def test_mutate_pixels_exception_handling_attribute_error(self):
        """Test handling of AttributeError during pixel access."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PixelData = b"data"

        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: (_ for _ in ()).throw(AttributeError("Missing attribute")))):
            mutated = fuzzer.mutate_pixels(ds)

        assert isinstance(mutated, Dataset)

    def test_mutate_pixels_exception_handling_type_error(self):
        """Test handling of TypeError during pixel access."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PixelData = b"data"

        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: (_ for _ in ()).throw(TypeError("Type error")))):
            mutated = fuzzer.mutate_pixels(ds)

        assert isinstance(mutated, Dataset)


class TestPixelDataCheck:
    """Test suite for PixelData existence check."""

    def test_pixel_data_check_without_tag(self):
        """Test PixelData check when tag doesn't exist."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.Modality = "CT"

        # Should not attempt mutation
        mutated = fuzzer.mutate_pixels(ds)

        assert "PixelData" not in ds
        assert isinstance(mutated, Dataset)

    def test_pixel_data_check_with_tag(self):
        """Test PixelData check when tag exists."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PixelData = b"\x00" * 100

        # Tag exists, so mutation will be attempted
        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: np.zeros((10, 10), dtype=np.uint8))):
            mutated = fuzzer.mutate_pixels(ds)

        assert "PixelData" in mutated


class TestCorruptedHeaders:
    """Test suite for handling corrupted headers."""

    def test_invalid_dimensions_from_header_fuzzing(self):
        """Test handling invalid dimensions from header fuzzing."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PixelData = b"data"
        ds.Rows = 0  # Invalid
        ds.Columns = 2147483647  # Invalid

        # Should handle exception gracefully
        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: (_ for _ in ()).throw(ValueError("Invalid dimensions")))):
            mutated = fuzzer.mutate_pixels(ds)

        assert isinstance(mutated, Dataset)

    def test_negative_dimensions(self):
        """Test handling negative dimensions."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PixelData = b"data"
        ds.Rows = -1
        ds.Columns = -1

        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: (_ for _ in ()).throw(ValueError("Negative dimensions")))):
            mutated = fuzzer.mutate_pixels(ds)

        assert isinstance(mutated, Dataset)


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_multiple_mutations(self):
        """Test applying mutations multiple times."""
        fuzzer = PixelFuzzer()
        ds = Dataset()

        pixel_array = np.zeros((10, 10), dtype=np.uint8)
        ds.PixelData = pixel_array.tobytes()

        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array.copy())):
            for _ in range(5):
                ds = fuzzer.mutate_pixels(ds)

        assert isinstance(ds, Dataset)

    def test_preserve_other_fields(self):
        """Test mutation preserves other dataset fields."""
        fuzzer = PixelFuzzer()
        ds = Dataset()
        ds.PatientName = "Test Patient"
        ds.Modality = "CT"
        ds.StudyDescription = "Test Study"

        pixel_array = np.zeros((5, 5), dtype=np.uint8)
        ds.PixelData = pixel_array.tobytes()

        with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array.copy())):
            mutated = fuzzer.mutate_pixels(ds)

        # Other fields should be preserved
        assert mutated.PatientName == "Test Patient"
        assert mutated.Modality == "CT"
        assert mutated.StudyDescription == "Test Study"

    def test_different_pixel_array_shapes(self):
        """Test mutation with different pixel array shapes."""
        fuzzer = PixelFuzzer()

        shapes = [(10, 10), (100, 100), (512, 512), (1, 1)]

        for shape in shapes:
            ds = Dataset()
            pixel_array = np.zeros(shape, dtype=np.uint8)
            ds.PixelData = pixel_array.tobytes()

            with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array.copy())):
                mutated = fuzzer.mutate_pixels(ds)

            assert isinstance(mutated, Dataset)

    def test_different_data_types(self):
        """Test mutation with different pixel data types."""
        fuzzer = PixelFuzzer()

        dtypes = [np.uint8, np.uint16, np.int16]

        for dtype in dtypes:
            ds = Dataset()
            pixel_array = np.zeros((10, 10), dtype=dtype)
            ds.PixelData = pixel_array.tobytes()

            with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array.copy())):
                mutated = fuzzer.mutate_pixels(ds)

            assert isinstance(mutated, Dataset)

    @patch("numpy.random.random")
    def test_noise_mask_coverage(self, mock_random):
        """Test different noise mask coverage levels."""
        fuzzer = PixelFuzzer()

        # Test different corruption levels
        coverage_levels = [0.001, 0.01, 0.1, 0.5]

        for coverage in coverage_levels:
            ds = Dataset()
            pixel_array = np.zeros((10, 10), dtype=np.uint8)
            ds.PixelData = pixel_array.tobytes()

            # Create noise mask with specified coverage
            noise_mask = np.random.random((10, 10)) < coverage
            mock_random.return_value = noise_mask

            with patch.object(Dataset, "pixel_array", new_callable=lambda: property(lambda self: pixel_array.copy())):
                mutated = fuzzer.mutate_pixels(ds)

            assert isinstance(mutated, Dataset)
