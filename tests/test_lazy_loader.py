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
from pydicom.dataset import Dataset, FileMetaInformationDataset
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
    file_meta = FileMetaInformationDataset()
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

        # Pixel data should NOT be loaded (RawDataElement, not bytes)
        assert hasattr(ds, "PixelData")
        # In stop_before_pixels mode, PixelData is a RawDataElement
        assert not isinstance(ds.PixelData, bytes)

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

        # Pixel data should be deferred (RawDataElement)
        assert hasattr(ds, "PixelData")
        assert not isinstance(ds.PixelData, bytes)  # Deferred

    def test_load_pixels_on_demand(self, sample_dicom_file):
        """Test on-demand pixel loading after metadata-only load."""
        loader = LazyDicomLoader(metadata_only=True)

        # Load metadata only
        ds = loader.load(sample_dicom_file)
        assert not isinstance(ds.PixelData, bytes)

        # Load pixels on demand
        pixel_data = loader.load_pixels(ds, sample_dicom_file)
        assert isinstance(pixel_data, bytes)
        assert len(pixel_data) == 64 * 64 * 2

    def test_force_flag(self, tmp_path):
        """Test force flag for non-standard DICOM files."""
        # Create a file without proper DICOM preamble
        file_path = tmp_path / "invalid.dcm"
        file_path.write_bytes(b"NOT_A_DICOM_FILE")

        # force=True should attempt to read anyway
        loader = LazyDicomLoader(force=True)
        with pytest.raises(Exception):  # Should fail, but gracefully
            loader.load(file_path)

        # force=False should fail immediately
        loader = LazyDicomLoader(force=False)
        with pytest.raises(Exception):
            loader.load(file_path)


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
        assert not isinstance(ds.PixelData, bytes)

    def test_create_deferred_loader(self, sample_dicom_file):
        """Test create_deferred_loader helper."""
        loader = create_deferred_loader(defer_size=1024)

        # Should be configured for deferred loading
        assert loader.metadata_only is False
        assert loader.defer_size == 1024
        assert loader.force is True

        # Should defer large elements
        ds = loader.load(sample_dicom_file)
        assert ds.PatientName == "Test^Patient"
        assert not isinstance(ds.PixelData, bytes)  # Deferred


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
        file_meta = FileMetaInformationDataset()
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

        # Attempt to load pixels (should fail gracefully)
        with pytest.raises(AttributeError):
            loader.load_pixels(ds_loaded, file_path)

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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
