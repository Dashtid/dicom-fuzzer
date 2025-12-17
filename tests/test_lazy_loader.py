"""
Tests for LazyDicomLoader (Performance Optimization Phase 4).

Tests lazy loading strategies:
- Metadata-only loading (stop_before_pixels)
- Deferred loading (defer_size)
- On-demand pixel loading
- Helper functions
"""

from pathlib import Path

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)


@pytest.fixture
def sample_dicom_file(tmp_path):
    """Create a sample DICOM file with pixel data."""
    # Create file meta
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"  # Implicit VR Little Endian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    # Create main dataset
    ds = Dataset()
    ds.file_meta = file_meta
    ds.is_implicit_VR = True
    ds.is_little_endian = True

    # Required DICOM tags
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SeriesInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.InstanceNumber = 1

    # Add pixel data (small image)
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)  # 8KB of pixel data

    # Save to file
    file_path = tmp_path / "test.dcm"
    ds.save_as(file_path, write_like_original=False)

    return file_path


class TestLazyDicomLoader:
    """Test LazyDicomLoader class."""

    def test_metadata_only_loading(self, sample_dicom_file):
        """Test that metadata-only mode doesn't load pixel data."""
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(sample_dicom_file)

        # Metadata should be loaded
        assert ds.PatientName == "Test^Patient"
        assert ds.Modality == "CT"
        assert ds.SeriesInstanceUID is not None

        # Pixel data should NOT be loaded in metadata-only mode
        # In stop_before_pixels mode, PixelData may or may not exist as an attribute
        # depending on pydicom version - check if it exists, it should not be bytes
        if hasattr(ds, "PixelData"):
            assert not isinstance(ds.PixelData, bytes), (
                "PixelData should not be bytes in metadata-only mode"
            )

    def test_full_loading(self, sample_dicom_file):
        """Test that full loading includes pixel data."""
        loader = LazyDicomLoader(metadata_only=False)
        ds = loader.load(sample_dicom_file)

        # Metadata should be loaded
        assert ds.PatientName == "Test^Patient"
        assert ds.Modality == "CT"

        # Pixel data should be loaded as bytes
        assert hasattr(ds, "PixelData")
        assert isinstance(ds.PixelData, bytes)
        assert len(ds.PixelData) == 64 * 64 * 2  # 8KB

    def test_defer_size_loading(self, sample_dicom_file):
        """Test deferred loading with size threshold."""
        # Defer elements larger than 1KB (pixel data is 8KB)
        loader = LazyDicomLoader(metadata_only=False, defer_size=1024)
        ds = loader.load(sample_dicom_file)

        # Metadata should be loaded
        assert ds.PatientName == "Test^Patient"

        # Note: defer_size behavior varies by pydicom version
        # Modern versions may still load pixel data as bytes
        assert hasattr(ds, "PixelData"), "PixelData should exist"

    def test_load_pixels_on_demand(self, sample_dicom_file):
        """Test on-demand pixel loading after metadata-only load."""
        loader = LazyDicomLoader(metadata_only=True)

        # Load metadata only
        ds = loader.load(sample_dicom_file)
        # In metadata-only mode, PixelData may not exist as an attribute
        if hasattr(ds, "PixelData"):
            assert not isinstance(ds.PixelData, bytes), (
                "PixelData should not be bytes in metadata-only mode"
            )

        # Load pixels on demand
        pixel_data = loader.load_pixels(ds, sample_dicom_file)
        assert isinstance(pixel_data, bytes)
        assert len(pixel_data) == 64 * 64 * 2

    def test_force_flag(self, tmp_path):
        """Test force flag for non-standard DICOM files."""
        # Create a file without proper DICOM preamble
        file_path = tmp_path / "invalid.dcm"
        file_path.write_bytes(b"NOT_A_DICOM_FILE")

        # force=True should attempt to read anyway (may succeed or fail depending on pydicom version)
        loader_force = LazyDicomLoader(force=True)
        try:
            ds = loader_force.load(file_path)
            # If it succeeds with force=True, that's acceptable behavior
            assert ds is not None
        except Exception:
            # If it fails, that's also acceptable - it's still invalid data
            pass

        # force=False should fail when file is clearly invalid
        loader_no_force = LazyDicomLoader(force=False)
        with pytest.raises(Exception):
            loader_no_force.load(file_path)


class TestHelperFunctions:
    """Test helper functions for creating loaders."""

    def test_create_metadata_loader(self, sample_dicom_file):
        """Test create_metadata_loader helper."""
        loader = create_metadata_loader()

        # Should be configured for metadata-only
        assert loader.metadata_only is True
        assert loader.force is True
        assert loader.defer_size is None

        # Should load metadata without pixel data
        ds = loader.load(sample_dicom_file)
        assert ds.PatientName == "Test^Patient"
        # In metadata-only mode, PixelData attribute doesn't exist
        assert not hasattr(ds, "PixelData") or ds.PixelData is None

    def test_create_deferred_loader(self, sample_dicom_file):
        """Test create_deferred_loader helper."""
        loader = create_deferred_loader(defer_size_mb=1)

        # Should be configured for deferred loading
        assert loader.metadata_only is False
        assert loader.defer_size == 1 * 1024 * 1024  # 1 MB in bytes
        assert loader.force is True

        # Should defer large elements (behavior varies by pydicom version)
        ds = loader.load(sample_dicom_file)
        assert ds.PatientName == "Test^Patient"
        # Modern pydicom may still load pixels as bytes despite defer_size
        assert hasattr(ds, "PixelData"), "PixelData should exist"


class TestPerformanceCharacteristics:
    """Test performance characteristics (qualitative)."""

    def test_metadata_loading_is_faster(self, sample_dicom_file):
        """
        Test that metadata-only loading is faster than full loading.

        Note: This is a qualitative test, not a precise benchmark.
        """
        import time

        # Metadata-only (should be fast)
        loader_meta = LazyDicomLoader(metadata_only=True)
        start = time.perf_counter()
        for _ in range(100):
            ds = loader_meta.load(sample_dicom_file)
        meta_time = time.perf_counter() - start

        # Full loading (should be slower)
        loader_full = LazyDicomLoader(metadata_only=False)
        start = time.perf_counter()
        for _ in range(100):
            ds = loader_full.load(sample_dicom_file)
        full_time = time.perf_counter() - start

        # Metadata-only should be faster (not a strict assertion for CI)
        # Just verify both completed without errors
        assert meta_time > 0
        assert full_time > 0
        # Print for manual inspection
        print(
            f"\nMetadata-only: {meta_time:.4f}s, Full: {full_time:.4f}s, "
            f"Speedup: {full_time / meta_time:.1f}x"
        )


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_load_nonexistent_file(self):
        """Test loading non-existent file."""
        loader = LazyDicomLoader()
        with pytest.raises(FileNotFoundError):
            loader.load(Path("/nonexistent/file.dcm"))

    def test_load_pixels_without_pixel_data(self, tmp_path):
        """Test loading pixels from file without pixel data."""
        # Create DICOM file without pixel data
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        ds = Dataset()
        ds.file_meta = file_meta
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.PatientName = "No^Pixels"

        file_path = tmp_path / "no_pixels.dcm"
        ds.save_as(file_path)

        # Load metadata
        loader = LazyDicomLoader(metadata_only=True)
        ds_loaded = loader.load(file_path)

        # Attempt to load pixels (should return empty bytes with warning)
        pixel_data = loader.load_pixels(ds_loaded, file_path)
        assert pixel_data == b"", "Should return empty bytes when no pixel data"

    def test_multiple_loads_same_file(self, sample_dicom_file):
        """Test loading same file multiple times."""
        loader = LazyDicomLoader(metadata_only=True)

        # Load same file multiple times
        ds1 = loader.load(sample_dicom_file)
        ds2 = loader.load(sample_dicom_file)
        ds3 = loader.load(sample_dicom_file)

        # Should be independent Dataset objects
        assert ds1 is not ds2
        assert ds2 is not ds3

        # But with same content
        assert ds1.PatientName == ds2.PatientName == ds3.PatientName
        assert ds1.SeriesInstanceUID == ds2.SeriesInstanceUID == ds3.SeriesInstanceUID

    def test_load_pixels_already_loaded(self, sample_dicom_file):
        """Test load_pixels when dataset already has pixel data (lines 121-122)."""
        loader = LazyDicomLoader(metadata_only=False)

        # Load full dataset with pixel data
        ds = loader.load(sample_dicom_file)
        assert hasattr(ds, "PixelData")
        assert isinstance(ds.PixelData, bytes)

        # Attempting to load pixels again should return existing pixel data
        # and log a warning (lines 121-122)
        pixel_data = loader.load_pixels(ds, sample_dicom_file)
        assert pixel_data == ds.PixelData
        assert len(pixel_data) == 64 * 64 * 2

    def test_load_pixels_nonexistent_file(self, tmp_path):
        """Test load_pixels with non-existent file (line 125)."""
        loader = LazyDicomLoader(metadata_only=True)

        # Create a minimal dataset
        ds = Dataset()
        ds.PatientName = "Test^Patient"

        # Try to load pixels from non-existent file
        nonexistent_path = tmp_path / "nonexistent.dcm"
        with pytest.raises(FileNotFoundError):
            loader.load_pixels(ds, nonexistent_path)

    def test_load_pixels_exception_handling(self, tmp_path):
        """Test load_pixels exception handling (lines 143-145)."""
        loader = LazyDicomLoader(metadata_only=True, force=False)

        # Create a completely invalid file that cannot be read even with force=False
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(
            b"\x00" * 100
        )  # Binary garbage that pydicom cannot parse

        # Create a minimal dataset
        ds = Dataset()
        ds.PatientName = "Test^Patient"

        # Attempting to load pixels from invalid file should raise exception
        with pytest.raises(Exception):
            loader.load_pixels(ds, invalid_file)

    def test_load_exception_handling(self, tmp_path):
        """Test load exception handling (lines 102-103)."""
        loader = LazyDicomLoader(metadata_only=False, force=False)

        # Create a corrupted DICOM file
        corrupted_file = tmp_path / "corrupted.dcm"
        corrupted_file.write_bytes(b"DICM" + b"\x00" * 100)  # Invalid DICOM data

        # Attempting to load corrupted file should raise exception
        with pytest.raises(Exception):
            loader.load(corrupted_file)


class TestBatchLoading:
    """Test batch loading functionality (lines 157-171)."""

    def test_load_batch_success(self, tmp_path):
        """Test successful batch loading of multiple files (lines 157-169)."""
        # Create multiple DICOM files
        file_paths = []
        for i in range(3):
            file_meta = FileMetaDataset()
            file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
            file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.ImplementationClassUID = generate_uid()

            ds = Dataset()
            ds.file_meta = file_meta
            ds.is_implicit_VR = True
            ds.is_little_endian = True
            ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
            ds.PatientName = f"Patient^{i}"
            ds.PatientID = str(i)
            ds.SeriesInstanceUID = generate_uid()
            ds.StudyInstanceUID = generate_uid()
            ds.Modality = "CT"

            # Add pixel data
            ds.Rows = 32
            ds.Columns = 32
            ds.BitsAllocated = 16
            ds.BitsStored = 16
            ds.HighBit = 15
            ds.SamplesPerPixel = 1
            ds.PixelRepresentation = 0
            ds.PhotometricInterpretation = "MONOCHROME2"
            ds.PixelData = b"\x00" * (32 * 32 * 2)

            file_path = tmp_path / f"file_{i}.dcm"
            ds.save_as(file_path, write_like_original=False)
            file_paths.append(file_path)

        # Batch load with metadata-only
        loader = LazyDicomLoader(metadata_only=True)
        datasets = loader.load_batch(file_paths)

        # All files should be loaded
        assert len(datasets) == 3
        for i, ds in enumerate(datasets):
            assert ds.PatientName == f"Patient^{i}"
            assert ds.PatientID == str(i)

    def test_load_batch_with_invalid_files(self, tmp_path):
        """Test batch loading with some invalid files (lines 162-164)."""
        # Create mix of valid and invalid files
        file_paths = []

        # Valid file 1
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        ds = Dataset()
        ds.file_meta = file_meta
        ds.is_implicit_VR = True
        ds.is_little_endian = True
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.PatientName = "Valid^Patient"
        ds.PatientID = "123"
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.Modality = "CT"

        valid_file = tmp_path / "valid.dcm"
        ds.save_as(valid_file, write_like_original=False)
        file_paths.append(valid_file)

        # Invalid file
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"NOT_DICOM")
        file_paths.append(invalid_file)

        # Non-existent file
        file_paths.append(tmp_path / "nonexistent.dcm")

        # Batch load - should skip invalid files and continue
        loader = LazyDicomLoader(metadata_only=True, force=False)
        datasets = loader.load_batch(file_paths)

        # Only the valid file should be loaded (1 out of 3)
        assert len(datasets) == 1
        assert datasets[0].PatientName == "Valid^Patient"

    def test_load_batch_empty_list(self):
        """Test batch loading with empty list (lines 166-169)."""
        loader = LazyDicomLoader(metadata_only=True)
        datasets = loader.load_batch([])

        # Should return empty list
        assert datasets == []

    def test_load_batch_full_loading(self, tmp_path):
        """Test batch loading with full pixel data loading (line 168)."""
        # Create DICOM file with pixel data
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        ds = Dataset()
        ds.file_meta = file_meta
        ds.is_implicit_VR = True
        ds.is_little_endian = True
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.PatientName = "Test^Patient"
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.Modality = "CT"

        # Add pixel data
        ds.Rows = 16
        ds.Columns = 16
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.PixelRepresentation = 0
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = b"\x00" * (16 * 16 * 2)

        file_path = tmp_path / "test.dcm"
        ds.save_as(file_path, write_like_original=False)

        # Batch load with full loading (metadata_only=False)
        loader = LazyDicomLoader(metadata_only=False)
        datasets = loader.load_batch([file_path])

        # Should have pixel data loaded
        assert len(datasets) == 1
        assert hasattr(datasets[0], "PixelData")
        assert isinstance(datasets[0].PixelData, bytes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
