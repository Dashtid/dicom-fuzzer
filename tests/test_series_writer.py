"""
Unit Tests for SeriesWriter

Tests the SeriesWriter class for writing fuzzed DICOM series to disk with
metadata tracking and reproduction scripts.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.core.series_writer import SeriesMetadata, SeriesWriter


# Helper function for mocking save_as
def create_dummy_dicom_file(path, *args, **kwargs):
    """Create a dummy DICOM file for testing."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(b"dummy_dicom_data_" * 10)  # ~160 bytes


@pytest.fixture
def temp_output_dir():
    """Create temporary output directory."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    # Cleanup
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def sample_series():
    """Create sample DicomSeries for testing."""
    return DicomSeries(
        series_uid="1.2.840.113619.2.55.3.123456",
        study_uid="1.2.840.113619.2.55.3.123400",
        modality="CT",
        slices=[
            Path("/tmp/slice1.dcm"),
            Path("/tmp/slice2.dcm"),
            Path("/tmp/slice3.dcm"),
        ],
        slice_spacing=1.25,
        orientation=(1.0, 0.0, 0.0, 0.0, 1.0, 0.0),
    )


@pytest.fixture
def sample_datasets():
    """Create sample pydicom Datasets for testing."""
    datasets = []
    for i in range(1, 4):
        ds = Dataset()
        ds.SeriesInstanceUID = "1.2.840.113619.2.55.3.123456"
        ds.StudyInstanceUID = "1.2.840.113619.2.55.3.123400"
        ds.Modality = "CT"
        ds.SOPInstanceUID = f"1.2.840.113619.2.55.3.123456.{i}"
        ds.ImagePositionPatient = [0.0, 0.0, float(i * 1.25)]
        ds.Rows = 512
        ds.Columns = 512
        datasets.append(ds)
    return datasets


class TestSeriesWriterInitialization:
    """Test SeriesWriter initialization."""

    def test_valid_initialization(self, temp_output_dir):
        """Test valid SeriesWriter initialization."""
        writer = SeriesWriter(temp_output_dir)
        assert writer.output_root == temp_output_dir
        assert temp_output_dir.exists()

    def test_creates_output_directory(self):
        """Test that output directory is created if it doesn't exist."""
        temp_dir = Path(tempfile.mkdtemp()) / "new_subdir"
        try:
            writer = SeriesWriter(temp_dir)
            assert temp_dir.exists()
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir.parent)


class TestWriteSeries:
    """Test write_series method."""

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_series_basic(
        self, mock_save_as, temp_output_dir, sample_series, sample_datasets
    ):
        """Test basic series writing."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)
        metadata = writer.write_series(sample_series, sample_datasets)

        # Check metadata
        assert metadata.series_uid == sample_series.series_uid
        assert metadata.modality == sample_series.modality
        assert metadata.slice_count == 3
        assert len(metadata.slice_files) == 3

        # Check save_as was called for each slice
        assert mock_save_as.call_count == 3

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_series_with_mutations(
        self, mock_save_as, temp_output_dir, sample_series, sample_datasets
    ):
        """Test writing series with mutation metadata."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)

        mutations_applied = [
            {"strategy": "slice_position_attack", "tag": "ImagePositionPatient"},
            {"strategy": "metadata_corruption", "tag": "SeriesInstanceUID"},
        ]

        metadata = writer.write_series(
            sample_series,
            sample_datasets,
            mutation_strategy="slice_position_attack",
            mutations_applied=mutations_applied,
        )

        assert metadata.mutation_strategy == "slice_position_attack"
        assert metadata.mutation_count == 2
        assert len(metadata.mutations_applied) == 2

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_series_with_original_series(
        self, mock_save_as, temp_output_dir, sample_series, sample_datasets
    ):
        """Test writing series with original series comparison."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)

        original_series = DicomSeries(
            series_uid="1.2.840.113619.2.55.3.123400",
            study_uid="1.2.840.113619.2.55.3.123400",
            modality="CT",
            slices=[Path("/tmp/orig1.dcm"), Path("/tmp/orig2.dcm")],
            slice_spacing=1.0,
        )

        metadata = writer.write_series(
            sample_series, sample_datasets, original_series=original_series
        )

        assert metadata.original_series_uid == original_series.series_uid
        assert metadata.original_slice_count == 2
        assert metadata.original_slice_spacing == 1.0

    def test_write_series_mismatch_count_raises_error(
        self, temp_output_dir, sample_series, sample_datasets
    ):
        """Test that mismatched dataset/series count raises error."""
        writer = SeriesWriter(temp_output_dir)

        # Remove one dataset to cause mismatch
        with pytest.raises(ValueError, match="Dataset count.*does not match"):
            writer.write_series(sample_series, sample_datasets[:2])

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_series_creates_directory(
        self, mock_save_as, temp_output_dir, sample_series, sample_datasets
    ):
        """Test that series directory is created."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)
        metadata = writer.write_series(sample_series, sample_datasets)

        series_dir = metadata.output_directory
        assert series_dir.exists()
        assert series_dir.is_dir()
        assert series_dir.name.startswith("series_")
        assert "CT" in series_dir.name


class TestWriteSingleSlice:
    """Test write_single_slice method."""

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_single_slice_basic(
        self, mock_save_as, temp_output_dir, sample_datasets
    ):
        """Test basic single slice writing."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)
        output_path = writer.write_single_slice(sample_datasets[0], "test_slice.dcm")

        assert output_path == temp_output_dir / "test_slice.dcm"
        mock_save_as.assert_called_once()

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_single_slice_with_mutations(
        self, mock_save_as, temp_output_dir, sample_datasets
    ):
        """Test single slice writing with mutation metadata."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)

        mutations = [{"strategy": "bit_flip", "offset": 100}]

        output_path = writer.write_single_slice(
            sample_datasets[0],
            "test_slice.dcm",
            mutation_strategy="bit_flip",
            mutations_applied=mutations,
        )

        # Check that metadata JSON was created
        metadata_path = output_path.with_suffix(".json")
        assert metadata_path.exists()


class TestCreateSeriesDirectory:
    """Test _create_series_directory method."""

    def test_create_series_directory_basic(self, temp_output_dir, sample_series):
        """Test basic series directory creation."""
        writer = SeriesWriter(temp_output_dir)
        series_dir = writer._create_series_directory(sample_series)

        assert series_dir.exists()
        assert series_dir.is_dir()
        assert "CT" in series_dir.name

    def test_create_series_directory_handles_existing(
        self, temp_output_dir, sample_series
    ):
        """Test that existing directories are handled with counter."""
        writer = SeriesWriter(temp_output_dir)

        # Create first directory
        dir1 = writer._create_series_directory(sample_series)
        dir1_name = dir1.name

        # Create second directory (should append _1)
        dir2 = writer._create_series_directory(sample_series)
        assert dir2.name != dir1_name
        assert dir2.exists()


class TestWriteMetadataJson:
    """Test _write_metadata_json method."""

    def test_write_metadata_json(self, temp_output_dir, sample_series):
        """Test metadata JSON writing."""
        writer = SeriesWriter(temp_output_dir)

        metadata = SeriesMetadata(
            series_uid=sample_series.series_uid,
            study_uid=sample_series.study_uid,
            modality=sample_series.modality,
            slice_count=3,
            output_directory=temp_output_dir / "test_series",
        )

        series_dir = temp_output_dir / "test_series"
        series_dir.mkdir()

        writer._write_metadata_json(series_dir, metadata)

        metadata_path = series_dir / "metadata.json"
        assert metadata_path.exists()


class TestCreateReproductionScript:
    """Test _create_reproduction_script method."""

    def test_create_reproduction_script(self, temp_output_dir, sample_series):
        """Test reproduction script creation."""
        writer = SeriesWriter(temp_output_dir)

        metadata = SeriesMetadata(
            series_uid=sample_series.series_uid,
            study_uid=sample_series.study_uid,
            modality=sample_series.modality,
            slice_count=3,
            output_directory=temp_output_dir / "test_series",
            slice_files=["slice_001.dcm", "slice_002.dcm", "slice_003.dcm"],
        )

        series_dir = temp_output_dir / "test_series"
        series_dir.mkdir()

        writer._create_reproduction_script(series_dir, metadata)

        script_path = series_dir / "reproduce.py"
        assert script_path.exists()

        # Check script content
        script_content = script_path.read_text()
        assert "#!/usr/bin/env python3" in script_content
        assert metadata.series_uid in script_content
        assert "pydicom" in script_content


class TestCleanupOldSeries:
    """Test cleanup_old_series method."""

    def test_cleanup_old_series(self, temp_output_dir):
        """Test cleanup of old series directories."""
        writer = SeriesWriter(temp_output_dir)

        # Create some old directories
        old_dir1 = temp_output_dir / "series_old_1"
        old_dir1.mkdir()
        old_dir2 = temp_output_dir / "series_old_2"
        old_dir2.mkdir()

        # Test that method runs without error
        deleted_count = writer.cleanup_old_series(days=7)
        assert deleted_count >= 0


class TestSeriesMetadata:
    """Test SeriesMetadata dataclass."""

    def test_metadata_initialization(self, sample_series, temp_output_dir):
        """Test SeriesMetadata initialization."""
        metadata = SeriesMetadata(
            series_uid=sample_series.series_uid,
            study_uid=sample_series.study_uid,
            modality=sample_series.modality,
            slice_count=3,
            output_directory=temp_output_dir,
        )

        assert metadata.series_uid == sample_series.series_uid
        assert metadata.slice_count == 3
        assert metadata.mutation_count == 0

    def test_metadata_to_dict(self, sample_series, temp_output_dir):
        """Test SeriesMetadata to_dict conversion."""
        metadata = SeriesMetadata(
            series_uid=sample_series.series_uid,
            study_uid=sample_series.study_uid,
            modality=sample_series.modality,
            slice_count=3,
            output_directory=temp_output_dir,
        )

        data = metadata.to_dict()

        assert isinstance(data, dict)
        assert data["series_uid"] == sample_series.series_uid
        assert data["slice_count"] == 3
        assert isinstance(data["output_directory"], str)


class TestSeriesWriterIntegration:
    """Integration tests for SeriesWriter."""

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_full_write_workflow(
        self, mock_save_as, temp_output_dir, sample_series, sample_datasets
    ):
        """Test complete write workflow with real files."""
        mock_save_as.side_effect = create_dummy_dicom_file

        writer = SeriesWriter(temp_output_dir)

        # Write series
        metadata = writer.write_series(
            sample_series,
            sample_datasets,
            mutation_strategy="test_strategy",
            mutations_applied=[{"test": "mutation"}],
        )

        # Verify directory structure
        series_dir = metadata.output_directory
        assert series_dir.exists()

        # Verify slice files
        for slice_file in metadata.slice_files:
            assert (series_dir / slice_file).exists()

        # Verify metadata.json
        metadata_path = series_dir / "metadata.json"
        assert metadata_path.exists()
        with open(metadata_path) as f:
            metadata_json = json.load(f)
            assert metadata_json["series_uid"] == sample_series.series_uid

        # Verify reproduce.py
        script_path = series_dir / "reproduce.py"
        assert script_path.exists()


class TestSeriesWriterErrorHandling:
    """Test error handling in SeriesWriter."""

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_series_save_failure(
        self, mock_save_as, temp_output_dir, sample_series, sample_datasets
    ):
        """Test that save_as failure raises OSError."""
        mock_save_as.side_effect = Exception("Simulated save failure")

        writer = SeriesWriter(temp_output_dir)

        with pytest.raises(OSError, match="Failed to write slice"):
            writer.write_series(sample_series, sample_datasets)

    @patch("dicom_fuzzer.core.series_writer.Dataset.save_as")
    def test_write_single_slice_save_failure(
        self, mock_save_as, temp_output_dir, sample_datasets
    ):
        """Test that single slice save failure raises OSError."""
        mock_save_as.side_effect = Exception("Simulated save failure")

        writer = SeriesWriter(temp_output_dir)

        with pytest.raises(OSError, match="Failed to write"):
            writer.write_single_slice(sample_datasets[0], "test.dcm")

    def test_write_series_loads_datasets_from_paths(self, temp_output_dir):
        """Test write_series when datasets=None loads from series.slices paths."""
        # Create actual DICOM files for the test
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        slice_dir = temp_output_dir / "input_slices"
        slice_dir.mkdir()

        slice_paths = []
        for i in range(2):
            slice_path = slice_dir / f"slice_{i}.dcm"
            slice_paths.append(slice_path)

            # Create minimal valid DICOM file
            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

            ds = FileDataset(
                str(slice_path), {}, file_meta=file_meta, preamble=b"\0" * 128
            )
            ds.is_little_endian = True
            ds.is_implicit_VR = False
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4.6"
            ds.Modality = "CT"
            ds.SOPInstanceUID = generate_uid()
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ds.save_as(slice_path)

        # Create series pointing to these files
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4.6",
            modality="CT",
            slices=slice_paths,
            slice_spacing=1.0,
        )

        output_dir = temp_output_dir / "output"
        writer = SeriesWriter(output_dir)

        # Write without providing datasets - should load from paths
        metadata = writer.write_series(series, datasets=None)

        assert metadata.slice_count == 2
        assert len(metadata.slice_files) == 2

    def test_write_series_load_failure_raises_oserror(self, temp_output_dir):
        """Test that failure to load from series.slices raises OSError."""
        # Create series with non-existent slice paths
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4.6",
            modality="CT",
            slices=[Path("/nonexistent/slice1.dcm"), Path("/nonexistent/slice2.dcm")],
            slice_spacing=1.0,
        )

        writer = SeriesWriter(temp_output_dir)

        with pytest.raises(OSError, match="Failed to read slice"):
            writer.write_series(series, datasets=None)


class TestSeriesMetadataGetOutputPaths:
    """Test SeriesMetadata.get_output_paths method."""

    def test_get_output_paths_returns_full_paths(self, temp_output_dir):
        """Test that get_output_paths returns complete Path objects."""
        metadata = SeriesMetadata(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4.6",
            modality="CT",
            slice_count=3,
            output_directory=temp_output_dir,
            slice_files=["slice_001.dcm", "slice_002.dcm", "slice_003.dcm"],
        )

        paths = metadata.get_output_paths()

        assert len(paths) == 3
        assert all(isinstance(p, Path) for p in paths)
        assert paths[0] == temp_output_dir / "slice_001.dcm"
        assert paths[1] == temp_output_dir / "slice_002.dcm"
        assert paths[2] == temp_output_dir / "slice_003.dcm"


class TestCleanupOldSeriesEdgeCases:
    """Test cleanup_old_series edge cases."""

    def test_cleanup_skips_files(self, temp_output_dir):
        """Test that cleanup skips regular files, only deletes directories."""
        writer = SeriesWriter(temp_output_dir)

        # Create a file (not directory) in output root
        test_file = temp_output_dir / "test_file.txt"
        test_file.write_text("test content")

        # Cleanup should not fail and should not delete the file
        deleted_count = writer.cleanup_old_series(days=0)

        assert test_file.exists()  # File should still exist
        assert deleted_count >= 0

    def test_cleanup_handles_permission_error(self, temp_output_dir):
        """Test that cleanup handles permission errors gracefully."""
        writer = SeriesWriter(temp_output_dir)

        # Create a directory
        old_dir = temp_output_dir / "series_old"
        old_dir.mkdir()

        # Mock shutil.rmtree to simulate permission error
        with patch("dicom_fuzzer.core.series_writer.shutil.rmtree") as mock_rmtree:
            mock_rmtree.side_effect = PermissionError("Cannot delete")

            # Should not raise, just log warning
            deleted_count = writer.cleanup_old_series(days=0)

            # No successful deletions due to permission error
            assert deleted_count == 0
