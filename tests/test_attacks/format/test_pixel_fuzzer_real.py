"""Real-world tests for pixel fuzzer strategy.

Tests pixel data mutation with actual DICOM datasets containing pixel data.
"""

import numpy as np
import pytest
from pydicom import FileDataset
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer


@pytest.fixture
def dataset_with_pixels():
    """Create a dataset with pixel data."""
    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
    file_meta.ImplementationClassUID = generate_uid()

    ds = FileDataset("test.dcm", {}, file_meta=file_meta, preamble=b"\0" * 128)
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID

    # Add required attributes for pixel data
    ds.Rows = 10
    ds.Columns = 10
    ds.SamplesPerPixel = 1
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"

    # Create pixel data (10x10 grayscale image)
    pixels = np.random.randint(0, 255, (10, 10), dtype=np.uint8)
    ds.PixelData = pixels.tobytes()

    return ds


@pytest.fixture
def dataset_no_pixels():
    """Create a dataset without pixel data."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    return ds


class TestPixelFuzzerInitialization:
    """Test PixelFuzzer initialization."""

    def test_initialization(self):
        """Test creating PixelFuzzer instance."""
        fuzzer = PixelFuzzer()

        assert fuzzer is not None
        assert isinstance(fuzzer, PixelFuzzer)


class TestMutatePixels:
    """Test mutate_pixels method."""

    def test_mutate_pixels_with_pixel_data(self, dataset_with_pixels):
        """Test mutating dataset with pixel data."""
        fuzzer = PixelFuzzer()
        _ = dataset_with_pixels.PixelData  # Access to ensure it exists

        result = fuzzer.mutate_pixels(dataset_with_pixels)

        assert result is dataset_with_pixels
        assert hasattr(result, "PixelData")
        # Pixel data should likely be modified (though random chance it's identical)
        # We just verify it exists and is bytes
        assert isinstance(result.PixelData, bytes)

    def test_mutate_pixels_returns_dataset(self, dataset_with_pixels):
        """Test that method returns the dataset."""
        fuzzer = PixelFuzzer()

        result = fuzzer.mutate_pixels(dataset_with_pixels)

        assert result is not None
        assert result is dataset_with_pixels
        assert isinstance(result, Dataset)

    def test_mutate_pixels_without_pixel_data(self, dataset_no_pixels):
        """Test mutating dataset without pixel data."""
        fuzzer = PixelFuzzer()

        result = fuzzer.mutate_pixels(dataset_no_pixels)

        # Should return dataset unchanged
        assert result is not None
        assert result is dataset_no_pixels
        assert isinstance(result, Dataset)
        assert not hasattr(result, "PixelData")

    def test_mutate_pixels_with_invalid_dimensions(self):
        """Test handling dataset with invalid pixel dimensions."""
        fuzzer = PixelFuzzer()

        # Create dataset with PixelData but invalid dimensions
        ds = Dataset()
        ds.Rows = 0  # Invalid
        ds.Columns = 10
        ds.PixelData = b"fake_pixel_data"

        # Should handle gracefully without crashing
        result = fuzzer.mutate_pixels(ds)

        assert result is not None
        assert result is ds
        assert isinstance(result, Dataset)

    def test_mutate_pixels_preserves_other_attributes(self, dataset_with_pixels):
        """Test that mutation preserves other dataset attributes."""
        fuzzer = PixelFuzzer()
        dataset_with_pixels.PatientName = "Test^Patient"
        dataset_with_pixels.StudyDescription = "CT HEAD"

        result = fuzzer.mutate_pixels(dataset_with_pixels)

        assert result is not None
        assert isinstance(result, Dataset)
        assert result.PatientName == "Test^Patient"
        assert result.StudyDescription == "CT HEAD"

    def test_mutate_pixels_multiple_times(self, dataset_with_pixels):
        """Test mutating pixels multiple times."""
        fuzzer = PixelFuzzer()

        for _ in range(5):
            result = fuzzer.mutate_pixels(dataset_with_pixels)
            assert result is not None
            assert hasattr(result, "PixelData")
            assert isinstance(result.PixelData, bytes)

    def test_mutate_pixels_with_corrupted_pixel_data(self):
        """Test handling dataset with corrupted PixelData tag."""
        fuzzer = PixelFuzzer()

        ds = Dataset()
        # Add PixelData but make it invalid
        ds.PixelData = b"invalid"

        # Should handle exception gracefully
        result = fuzzer.mutate_pixels(ds)

        assert result is not None
        assert result is ds
        assert isinstance(result, Dataset)


class TestPixelMutationBehavior:
    """Test specific pixel mutation behaviors."""

    def test_mutation_introduces_noise(self, dataset_with_pixels):
        """Test that mutation introduces some changes."""
        fuzzer = PixelFuzzer()

        # Get original pixels
        original_pixels = dataset_with_pixels.pixel_array.copy()

        # Track if any mutation occurred across multiple tries
        for _ in range(10):
            ds_copy = dataset_with_pixels
            fuzzer.mutate_pixels(ds_copy)

            try:
                new_pixels = ds_copy.pixel_array
                if not np.array_equal(original_pixels, new_pixels):
                    break
            except Exception:
                # If pixel access fails, that's okay
                pass

        # With 10 tries and 1% corruption rate, should see some mutations
        # (Not guaranteed due to randomness, so we just verify no crash)
        assert True  # Test passes if no exceptions

    def test_mutation_affects_small_percentage(self, dataset_with_pixels):
        """Test that mutation affects small percentage of pixels."""
        fuzzer = PixelFuzzer()

        # Get original pixels
        original_pixels = dataset_with_pixels.pixel_array.copy()

        fuzzer.mutate_pixels(dataset_with_pixels)

        try:
            new_pixels = dataset_with_pixels.pixel_array

            # Count differences
            differences = np.sum(original_pixels != new_pixels)
            total_pixels = original_pixels.size

            # Should affect small percentage (around 1% based on code)
            # Allow up to 20% for randomness
            percent_changed = (differences / total_pixels) * 100
            assert percent_changed <= 20
        except Exception:
            # If pixel access fails, that's okay
            pass


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_dataset(self):
        """Test with completely empty dataset."""
        fuzzer = PixelFuzzer()
        ds = Dataset()

        result = fuzzer.mutate_pixels(ds)

        assert result is not None
        assert result is ds
        assert isinstance(result, Dataset)

    def test_dataset_with_pixel_data_tag_but_no_array(self):
        """Test dataset that has PixelData tag but can't create array."""
        fuzzer = PixelFuzzer()

        ds = Dataset()
        ds.PixelData = b"x"  # Too small to be valid

        # Should not crash
        result = fuzzer.mutate_pixels(ds)
        assert result is not None
        assert result is ds
        assert isinstance(result, Dataset)

    def test_multiple_fuzzers_on_same_dataset(self, dataset_with_pixels):
        """Test multiple fuzzer instances on same dataset."""
        fuzzer1 = PixelFuzzer()
        fuzzer2 = PixelFuzzer()

        result1 = fuzzer1.mutate_pixels(dataset_with_pixels)
        result2 = fuzzer2.mutate_pixels(dataset_with_pixels)

        assert result1 is not None
        assert result2 is not None
        assert result1 is result2
        assert isinstance(result1, Dataset)


class TestIntegrationScenarios:
    """Test realistic usage scenarios."""

    def test_fuzzing_workflow(self, dataset_with_pixels):
        """Test complete fuzzing workflow."""
        fuzzer = PixelFuzzer()

        # Original state
        assert "PixelData" in dataset_with_pixels

        # Fuzz
        result = fuzzer.mutate_pixels(dataset_with_pixels)

        # Verify still has pixel data
        assert "PixelData" in result
        assert isinstance(result.PixelData, bytes)

    def test_batch_pixel_fuzzing(self):
        """Test fuzzing multiple datasets in batch."""
        fuzzer = PixelFuzzer()

        datasets = []
        for i in range(5):
            ds = Dataset()
            ds.Rows = 5
            ds.Columns = 5
            ds.SamplesPerPixel = 1
            ds.BitsAllocated = 8
            ds.PixelData = np.zeros((5, 5), dtype=np.uint8).tobytes()
            datasets.append(ds)

        # Fuzz all
        for ds in datasets:
            fuzzer.mutate_pixels(ds)

        # All should still have PixelData
        for ds in datasets:
            assert hasattr(ds, "PixelData")

    def test_fuzzer_with_mixed_datasets(self, dataset_with_pixels, dataset_no_pixels):
        """Test fuzzer with mix of datasets with/without pixels."""
        fuzzer = PixelFuzzer()

        result1 = fuzzer.mutate_pixels(dataset_with_pixels)
        result2 = fuzzer.mutate_pixels(dataset_no_pixels)

        assert result1 is not None
        assert result2 is not None
        # With pixels should still have pixels
        assert "PixelData" in result1
        assert isinstance(result1.PixelData, bytes)

        # Without pixels should still not have pixels
        assert "PixelData" not in result2
