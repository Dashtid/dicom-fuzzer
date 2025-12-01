"""Additional tests for LazyDicomLoader to improve code coverage.

These tests target specific uncovered paths in lazy_loader.py to achieve
maximum test coverage.
"""

from pathlib import Path
from unittest.mock import patch

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)


@pytest.fixture
def sample_dicom_file(tmp_path: Path) -> Path:
    """Create a sample DICOM file for testing."""
    file_path = tmp_path / "test.dcm"

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    ds = pydicom.dataset.FileDataset(
        str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST123"
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.Modality = "CT"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    ds.save_as(str(file_path), write_like_original=False)
    return file_path


@pytest.fixture
def dicom_without_pixels(tmp_path: Path) -> Path:
    """Create a DICOM file without pixel data."""
    file_path = tmp_path / "no_pixels.dcm"

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    ds = pydicom.dataset.FileDataset(
        str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST123"
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.Modality = "CT"
    # No PixelData

    ds.save_as(str(file_path), write_like_original=False)
    return file_path


class TestLazyDicomLoaderInit:
    """Test LazyDicomLoader initialization."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        loader = LazyDicomLoader()
        assert loader.metadata_only is False
        assert loader.defer_size is None
        assert loader.force is True

    def test_init_metadata_only(self):
        """Test initialization with metadata_only=True."""
        loader = LazyDicomLoader(metadata_only=True)
        assert loader.metadata_only is True

    def test_init_with_defer_size(self):
        """Test initialization with defer_size parameter."""
        loader = LazyDicomLoader(defer_size=1024)
        assert loader.defer_size == 1024

    def test_init_with_all_params(self):
        """Test initialization with all parameters."""
        loader = LazyDicomLoader(metadata_only=True, defer_size=2048, force=False)
        assert loader.metadata_only is True
        assert loader.defer_size == 2048
        assert loader.force is False


class TestLazyDicomLoaderLoad:
    """Test LazyDicomLoader.load method."""

    def test_load_success(self, sample_dicom_file: Path):
        """Test successful file loading."""
        loader = LazyDicomLoader()
        ds = loader.load(sample_dicom_file)

        assert ds is not None
        assert ds.PatientName == "Test^Patient"
        assert hasattr(ds, "PixelData")

    def test_load_metadata_only(self, sample_dicom_file: Path):
        """Test metadata-only loading (stop_before_pixels=True)."""
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(sample_dicom_file)

        assert ds is not None
        assert ds.PatientName == "Test^Patient"
        # PixelData should not be loaded (pydicom behavior)

    def test_load_file_not_found(self, tmp_path: Path):
        """Test loading non-existent file raises FileNotFoundError."""
        loader = LazyDicomLoader()
        non_existent = tmp_path / "does_not_exist.dcm"

        with pytest.raises(FileNotFoundError, match="DICOM file not found"):
            loader.load(non_existent)

    def test_load_invalid_file(self, tmp_path: Path):
        """Test loading invalid file raises exception."""
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"not a dicom file")

        loader = LazyDicomLoader(force=False)

        with pytest.raises(Exception):
            loader.load(invalid_file)

    def test_load_with_defer_size(self, sample_dicom_file: Path):
        """Test loading with defer_size parameter."""
        loader = LazyDicomLoader(defer_size=1024)
        ds = loader.load(sample_dicom_file)

        assert ds is not None
        assert ds.PatientName == "Test^Patient"


class TestLazyDicomLoaderLoadPixels:
    """Test LazyDicomLoader.load_pixels method."""

    def test_load_pixels_success(self, sample_dicom_file: Path):
        """Test loading pixels on demand."""
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(sample_dicom_file)

        # Remove PixelData if it was loaded
        if hasattr(ds, "PixelData"):
            del ds.PixelData

        pixel_data = loader.load_pixels(ds, sample_dicom_file)

        assert pixel_data is not None
        assert len(pixel_data) > 0
        assert hasattr(ds, "PixelData")

    def test_load_pixels_already_loaded(self, sample_dicom_file: Path):
        """Test load_pixels when pixels already loaded (line 117-119)."""
        loader = LazyDicomLoader()
        ds = loader.load(sample_dicom_file)

        # Ensure PixelData exists
        assert hasattr(ds, "PixelData")
        original_pixel_data = ds.PixelData

        # Load pixels again - should return existing data
        pixel_data = loader.load_pixels(ds, sample_dicom_file)

        assert pixel_data is not None
        assert len(pixel_data) == len(original_pixel_data)

    def test_load_pixels_file_not_found(self, tmp_path: Path):
        """Test load_pixels with non-existent file (line 121-122)."""
        loader = LazyDicomLoader()
        ds = Dataset()  # Empty dataset without PixelData

        non_existent = tmp_path / "does_not_exist.dcm"

        with pytest.raises(FileNotFoundError, match="DICOM file not found"):
            loader.load_pixels(ds, non_existent)

    def test_load_pixels_no_pixel_data_in_file(self, dicom_without_pixels: Path):
        """Test load_pixels when file has no pixel data (line 136-138)."""
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(dicom_without_pixels)

        # Remove PixelData if it exists
        if hasattr(ds, "PixelData"):
            del ds.PixelData

        pixel_data = loader.load_pixels(ds, dicom_without_pixels)

        # Should return empty bytes
        assert pixel_data == b""

    def test_load_pixels_read_error(self, tmp_path: Path, sample_dicom_file: Path):
        """Test load_pixels when re-read fails (line 140-142)."""
        loader = LazyDicomLoader(metadata_only=True)

        # Create a dataset without PixelData attribute
        ds = Dataset()
        ds.PatientName = "Test"

        # Mock dcmread to raise an exception
        with patch("pydicom.dcmread") as mock_read:
            mock_read.side_effect = Exception("Read error")

            with pytest.raises(Exception, match="Read error"):
                loader.load_pixels(ds, sample_dicom_file)


class TestLazyDicomLoaderBatch:
    """Test LazyDicomLoader.load_batch method."""

    def test_load_batch_success(self, sample_dicom_file: Path, tmp_path: Path):
        """Test batch loading of multiple files."""
        # Create additional files
        file_paths = [sample_dicom_file]
        for i in range(3):
            new_file = tmp_path / f"test_{i}.dcm"
            ds = pydicom.dcmread(sample_dicom_file)
            ds.PatientID = f"PAT{i}"
            ds.save_as(str(new_file), write_like_original=False)
            file_paths.append(new_file)

        loader = LazyDicomLoader()
        datasets = loader.load_batch(file_paths)

        assert len(datasets) == 4

    def test_load_batch_with_errors(self, sample_dicom_file: Path, tmp_path: Path):
        """Test batch loading with some invalid files (lines 159-161)."""
        # Create an invalid file
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"not a dicom file")

        file_paths = [sample_dicom_file, invalid_file]

        loader = LazyDicomLoader(force=False)
        datasets = loader.load_batch(file_paths)

        # Should load valid file and skip invalid
        assert len(datasets) == 1

    def test_load_batch_metadata_only(self, sample_dicom_file: Path):
        """Test batch loading with metadata_only=True."""
        loader = LazyDicomLoader(metadata_only=True)
        datasets = loader.load_batch([sample_dicom_file])

        assert len(datasets) == 1

    def test_load_batch_empty_list(self):
        """Test batch loading with empty file list."""
        loader = LazyDicomLoader()
        datasets = loader.load_batch([])

        assert datasets == []


class TestFactoryFunctions:
    """Test factory functions for creating loaders."""

    def test_create_metadata_loader(self):
        """Test create_metadata_loader factory function (line 171-178)."""
        loader = create_metadata_loader()

        assert isinstance(loader, LazyDicomLoader)
        assert loader.metadata_only is True
        assert loader.force is True

    def test_create_deferred_loader_default(self):
        """Test create_deferred_loader with default size (lines 181-193)."""
        loader = create_deferred_loader()

        assert isinstance(loader, LazyDicomLoader)
        assert loader.metadata_only is False
        assert loader.defer_size == 10 * 1024 * 1024  # 10 MB in bytes
        assert loader.force is True

    def test_create_deferred_loader_custom_size(self):
        """Test create_deferred_loader with custom size."""
        loader = create_deferred_loader(defer_size_mb=5)

        assert loader.defer_size == 5 * 1024 * 1024  # 5 MB in bytes

    def test_create_deferred_loader_large_size(self):
        """Test create_deferred_loader with large size."""
        loader = create_deferred_loader(defer_size_mb=100)

        assert loader.defer_size == 100 * 1024 * 1024


class TestLazyLoaderIntegration:
    """Integration tests for lazy loader."""

    def test_metadata_then_pixels_workflow(self, sample_dicom_file: Path):
        """Test typical workflow: load metadata, then load pixels on demand."""
        # Step 1: Load metadata only
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(sample_dicom_file)

        # Verify metadata is available
        assert ds.PatientName == "Test^Patient"
        assert ds.Modality == "CT"

        # Step 2: Remove PixelData to simulate metadata-only state
        if hasattr(ds, "PixelData"):
            del ds.PixelData

        # Step 3: Load pixels on demand
        pixel_data = loader.load_pixels(ds, sample_dicom_file)

        # Verify pixels are now available
        assert len(pixel_data) > 0
        assert hasattr(ds, "PixelData")

    def test_full_load_workflow(self, sample_dicom_file: Path):
        """Test full loading workflow."""
        loader = LazyDicomLoader(metadata_only=False)
        ds = loader.load(sample_dicom_file)

        assert ds.PatientName == "Test^Patient"
        assert hasattr(ds, "PixelData")
        assert len(ds.PixelData) > 0

    def test_batch_then_individual_pixels(
        self, sample_dicom_file: Path, tmp_path: Path
    ):
        """Test batch metadata loading followed by individual pixel loading."""
        # Create multiple files
        file_paths = [sample_dicom_file]
        for i in range(2):
            new_file = tmp_path / f"batch_{i}.dcm"
            ds = pydicom.dcmread(sample_dicom_file)
            ds.PatientID = f"BATCH{i}"
            ds.save_as(str(new_file), write_like_original=False)
            file_paths.append(new_file)

        # Batch load metadata
        loader = LazyDicomLoader(metadata_only=True)
        datasets = loader.load_batch(file_paths)

        assert len(datasets) == 3

        # Load pixels for specific files only
        for i, (ds, path) in enumerate(zip(datasets, file_paths)):
            if i == 1:  # Only load pixels for second file
                if hasattr(ds, "PixelData"):
                    del ds.PixelData
                pixel_data = loader.load_pixels(ds, path)
                assert len(pixel_data) > 0
