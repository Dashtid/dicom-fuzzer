"""Coverage-focused tests for SeriesDetector.

These tests create actual DICOM files and execute real code paths
to improve coverage, rather than using mocks which bypass the actual implementation.
"""

import tempfile
import warnings
from pathlib import Path

import numpy as np
import pytest
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import (
    CTImageStorage,
    ExplicitVRLittleEndian,
    MRImageStorage,
    generate_uid,
)

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.core.series_detector import SeriesDetector


def create_dicom_file(
    output_path: Path,
    series_uid: str,
    study_uid: str,
    modality: str = "CT",
    instance_number: int = 1,
    image_position: tuple[float, float, float] | None = None,
    rows: int = 64,
    columns: int = 64,
    include_orientation: bool = True,
) -> Path:
    """Create a minimal DICOM file for testing.

    Args:
        output_path: Where to write the file
        series_uid: SeriesInstanceUID
        study_uid: StudyInstanceUID
        modality: Imaging modality (CT, MR, etc.)
        instance_number: Instance number
        image_position: (x, y, z) position, defaults to (0, 0, instance_number)
        rows: Image rows
        columns: Image columns
        include_orientation: Whether to include ImageOrientationPatient

    Returns:
        Path to the created file

    """
    # File meta info
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = (
        CTImageStorage if modality == "CT" else MRImageStorage
    )
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    # Create dataset
    ds = FileDataset(str(output_path), {}, file_meta=file_meta, preamble=b"\0" * 128)

    # Required UIDs
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = series_uid

    # Patient/Study info
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST001"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.Modality = modality

    # Series info
    ds.SeriesNumber = 1
    ds.InstanceNumber = instance_number

    # Image position (critical for series detection)
    if image_position is None:
        image_position = (0.0, 0.0, float(instance_number * 2.5))  # 2.5mm spacing
    ds.ImagePositionPatient = list(image_position)

    # Image orientation (optional)
    if include_orientation:
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]

    # Image dimensions
    ds.Rows = rows
    ds.Columns = columns
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"

    # Create pixel data
    pixel_array = np.zeros((rows, columns), dtype=np.uint16)
    ds.PixelData = pixel_array.tobytes()

    # Save
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        ds.save_as(output_path)

    return output_path


class TestSeriesDetectorWithRealFiles:
    """Test SeriesDetector with actual DICOM files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_detect_single_series_from_files(self, temp_dir, detector):
        """Test detecting a single series from a list of files."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create 5 slices
        files = []
        for i in range(5):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
                image_position=(0.0, 0.0, float(i * 2.5)),
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=True)

        assert len(series_list) == 1
        assert series_list[0].series_uid == series_uid
        assert series_list[0].study_uid == study_uid
        assert series_list[0].modality == "CT"
        assert series_list[0].slice_count == 5

    def test_detect_multiple_series_from_files(self, temp_dir, detector):
        """Test detecting multiple series from mixed files."""
        series1_uid = generate_uid()
        series2_uid = generate_uid()
        study_uid = generate_uid()

        files = []

        # Create CT series with 3 slices
        for i in range(3):
            file_path = temp_dir / f"ct_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series1_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        # Create MR series with 2 slices
        for i in range(2):
            file_path = temp_dir / f"mr_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series2_uid,
                study_uid=study_uid,
                modality="MR",
                instance_number=i + 1,
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=True)

        assert len(series_list) == 2

        ct_series = [s for s in series_list if s.modality == "CT"][0]
        mr_series = [s for s in series_list if s.modality == "MR"][0]

        assert ct_series.slice_count == 3
        assert mr_series.slice_count == 2

    def test_detect_series_in_directory_recursive(self, temp_dir, detector):
        """Test detecting series in directory with subdirectories."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create subdirectory
        subdir = temp_dir / "series1"
        subdir.mkdir()

        # Create files in subdirectory
        for i in range(3):
            file_path = subdir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )

        series_list = detector.detect_series_in_directory(
            temp_dir, recursive=True, validate=True
        )

        assert len(series_list) == 1
        assert series_list[0].slice_count == 3

    def test_detect_series_in_directory_non_recursive(self, temp_dir, detector):
        """Test detecting series in directory without recursion."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create files in root directory
        for i in range(2):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )

        # Create subdirectory with more files (should be ignored)
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        for i in range(2):
            file_path = subdir / f"sub_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=generate_uid(),
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )

        series_list = detector.detect_series_in_directory(
            temp_dir, recursive=False, validate=True
        )

        assert len(series_list) == 1
        assert series_list[0].slice_count == 2

    def test_detect_series_empty_directory(self, temp_dir, detector):
        """Test detecting series in empty directory."""
        series_list = detector.detect_series_in_directory(temp_dir, recursive=True)

        assert series_list == []

    def test_detect_series_directory_not_found(self, detector):
        """Test error when directory doesn't exist."""
        with pytest.raises(FileNotFoundError):
            detector.detect_series_in_directory(
                Path("/nonexistent/path/does/not/exist")
            )

    def test_detect_series_empty_file_list(self, detector):
        """Test detecting series with empty file list."""
        series_list = detector.detect_series([], validate=False)
        assert series_list == []


class TestSliceSorting:
    """Test slice sorting functionality with real files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_slices_sorted_by_z_position(self, temp_dir, detector):
        """Test that slices are sorted by z-position (ImagePositionPatient[2])."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create files with non-sequential z-positions
        z_positions = [15.0, 5.0, 10.0, 0.0, 20.0]  # Out of order
        files = []

        for i, z_pos in enumerate(z_positions):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
                image_position=(0.0, 0.0, z_pos),
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=False)

        assert len(series_list) == 1
        series = series_list[0]

        # Slices should be sorted by z-position (descending - superior to inferior)
        # So highest z first: 20, 15, 10, 5, 0
        assert series.slice_count == 5

        # Verify sorting by reading back the positions
        positions = series.get_slice_positions()
        z_values = [pos[2] for pos in positions]

        # Should be in descending order
        assert z_values == sorted(z_values, reverse=True)

    def test_sort_slices_fallback_to_instance_number(self, temp_dir, detector):
        """Test sorting falls back to instance number when z-positions are equal."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create files with same z-position but different instance numbers
        files = []
        for i in range(3):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=3 - i,  # Reverse order: 3, 2, 1
                image_position=(0.0, 0.0, 0.0),  # Same z-position
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=False)

        assert len(series_list) == 1
        series = series_list[0]
        assert series.slice_count == 3


class TestSeriesSummary:
    """Test series summary generation with real series."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_summary_single_series(self, temp_dir, detector):
        """Test summary statistics for single series."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        files = []
        for i in range(10):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=False)
        summary = detector.get_series_summary(series_list)

        assert summary["total_series"] == 1
        assert summary["total_slices"] == 10
        assert summary["modalities"] == {"CT": 1}
        assert summary["multislice_series"] == 1
        assert summary["single_slice_series"] == 0
        assert summary["avg_slices_per_series"] == 10.0

    def test_summary_mixed_modalities(self, temp_dir, detector):
        """Test summary with multiple modalities."""
        study_uid = generate_uid()

        # Create CT series (10 slices)
        ct_series_uid = generate_uid()
        files = []
        for i in range(10):
            file_path = temp_dir / f"ct_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=ct_series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        # Create MR series (5 slices)
        mr_series_uid = generate_uid()
        for i in range(5):
            file_path = temp_dir / f"mr_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=mr_series_uid,
                study_uid=study_uid,
                modality="MR",
                instance_number=i + 1,
            )
            files.append(file_path)

        # Create single-slice US
        us_series_uid = generate_uid()
        file_path = temp_dir / "us_slice.dcm"
        create_dicom_file(
            file_path,
            series_uid=us_series_uid,
            study_uid=study_uid,
            modality="US",
            instance_number=1,
        )
        files.append(file_path)

        series_list = detector.detect_series(files, validate=False)
        summary = detector.get_series_summary(series_list)

        assert summary["total_series"] == 3
        assert summary["total_slices"] == 16
        assert summary["modalities"]["CT"] == 1
        assert summary["modalities"]["MR"] == 1
        assert summary["modalities"]["US"] == 1
        assert summary["multislice_series"] == 2
        assert summary["single_slice_series"] == 1

    def test_summary_empty_list(self, detector):
        """Test summary with empty series list."""
        summary = detector.get_series_summary([])

        assert summary["total_series"] == 0
        assert summary["total_slices"] == 0
        assert summary["modalities"] == {}
        assert summary["multislice_series"] == 0
        assert summary["single_slice_series"] == 0


class TestValidation:
    """Test series validation with real files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_validate_consistent_series(self, temp_dir, detector):
        """Test validation of consistent series passes."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        files = []
        for i in range(3):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=True)

        assert len(series_list) == 1
        # Validation errors would be logged but series should still be created


class TestFileExtensions:
    """Test finding DICOM files with various extensions."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_find_dcm_lowercase(self, temp_dir, detector):
        """Test finding .dcm files."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        file_path = temp_dir / "test.dcm"
        create_dicom_file(file_path, series_uid, study_uid)

        found_files = detector._find_dicom_files(temp_dir, recursive=True)

        assert len(found_files) == 1
        assert found_files[0].name == "test.dcm"

    def test_find_dcm_uppercase(self, temp_dir, detector):
        """Test finding .DCM files (uppercase)."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        file_path = temp_dir / "test.DCM"
        create_dicom_file(file_path, series_uid, study_uid)

        found_files = detector._find_dicom_files(temp_dir, recursive=True)

        # Should find the file (case insensitive on Windows, depends on filesystem)
        assert len(found_files) >= 1

    def test_find_dicom_extension(self, temp_dir, detector):
        """Test finding .dicom files."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        file_path = temp_dir / "test.dicom"
        create_dicom_file(file_path, series_uid, study_uid)

        found_files = detector._find_dicom_files(temp_dir, recursive=True)

        assert len(found_files) == 1
        assert found_files[0].name == "test.dicom"


class TestDicomFileValidation:
    """Test DICOM file validation."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_is_dicom_file_valid(self, temp_dir, detector):
        """Test _is_dicom_file returns True for valid DICOM."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        file_path = temp_dir / "valid.dcm"
        create_dicom_file(file_path, series_uid, study_uid)

        assert detector._is_dicom_file(file_path) is True

    def test_is_dicom_file_invalid(self, temp_dir, detector):
        """Test _is_dicom_file returns False for non-DICOM file."""
        file_path = temp_dir / "invalid.txt"
        file_path.write_text("This is not a DICOM file")

        assert detector._is_dicom_file(file_path) is False

    def test_is_dicom_file_empty(self, temp_dir, detector):
        """Test _is_dicom_file returns False for empty file."""
        file_path = temp_dir / "empty.dcm"
        file_path.write_bytes(b"")

        assert detector._is_dicom_file(file_path) is False


class TestMissingMetadata:
    """Test handling of files with missing metadata."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_series_without_orientation(self, temp_dir, detector):
        """Test creating series when ImageOrientationPatient is missing."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        files = []
        for i in range(2):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
                include_orientation=False,
            )
            files.append(file_path)

        series_list = detector.detect_series(files, validate=False)

        assert len(series_list) == 1
        # Series should be created even without orientation


class TestSeriesDetectorCache:
    """Test the series detector cache functionality."""

    def test_detector_has_empty_cache_on_init(self):
        """Test that detector starts with empty cache."""
        detector = SeriesDetector()
        assert detector._series_cache == {}


class TestDetectSeriesPathInput:
    """Test detect_series when called with Path instead of list."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_detect_series_with_path_input(self, temp_dir, detector):
        """Test detect_series accepts Path object (directory) as input."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        for i in range(3):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )

        # Call detect_series with Path object (should delegate to detect_series_in_directory)
        series_list = detector.detect_series(temp_dir, validate=True)

        assert len(series_list) == 1
        assert series_list[0].slice_count == 3


class TestGroupBySeriesUidRealFiles:
    """Test _group_by_series_uid with real files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_group_files_by_series_uid(self, temp_dir, detector):
        """Test grouping files by SeriesInstanceUID."""
        series1_uid = generate_uid()
        series2_uid = generate_uid()
        study_uid = generate_uid()

        files = []

        # Series 1: 2 files
        for i in range(2):
            file_path = temp_dir / f"s1_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series1_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        # Series 2: 3 files
        for i in range(3):
            file_path = temp_dir / f"s2_slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series2_uid,
                study_uid=study_uid,
                modality="MR",
                instance_number=i + 1,
            )
            files.append(file_path)

        groups = detector._group_by_series_uid(files)

        assert len(groups) == 2
        assert series1_uid in groups
        assert series2_uid in groups
        assert len(groups[series1_uid]["files"]) == 2
        assert len(groups[series2_uid]["files"]) == 3
        assert groups[series1_uid]["modality"] == "CT"
        assert groups[series2_uid]["modality"] == "MR"


class TestSortSlicesByPositionRealFiles:
    """Test _sort_slices_by_position with real files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_sort_slices_by_position_descending_z(self, temp_dir, detector):
        """Test slices are sorted by z-position in descending order."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create files with specific z-positions (out of order)
        file_z10 = temp_dir / "z10.dcm"
        file_z5 = temp_dir / "z5.dcm"
        file_z0 = temp_dir / "z0.dcm"

        create_dicom_file(
            file_z10,
            series_uid,
            study_uid,
            instance_number=1,
            image_position=(0, 0, 10.0),
        )
        create_dicom_file(
            file_z5,
            series_uid,
            study_uid,
            instance_number=2,
            image_position=(0, 0, 5.0),
        )
        create_dicom_file(
            file_z0,
            series_uid,
            study_uid,
            instance_number=3,
            image_position=(0, 0, 0.0),
        )

        # Pass files in wrong order
        files = [file_z5, file_z0, file_z10]

        sorted_files = detector._sort_slices_by_position(files)

        # Should be sorted descending by z: z10, z5, z0
        assert sorted_files[0] == file_z10
        assert sorted_files[1] == file_z5
        assert sorted_files[2] == file_z0

    def test_sort_empty_list(self, detector):
        """Test sorting empty list returns empty list."""
        result = detector._sort_slices_by_position([])
        assert result == []


class TestCreateSeriesRealFiles:
    """Test _create_series with real files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def detector(self):
        """Create a SeriesDetector instance."""
        return SeriesDetector()

    def test_create_series_extracts_orientation(self, temp_dir, detector):
        """Test _create_series extracts ImageOrientationPatient."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        file_path = temp_dir / "slice.dcm"
        create_dicom_file(
            file_path,
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            include_orientation=True,
        )

        series = detector._create_series(
            series_uid=series_uid,
            files=[file_path],
            study_uid=study_uid,
            modality="CT",
        )

        assert series is not None
        assert series.orientation is not None
        # Should be [1, 0, 0, 0, 1, 0] as tuple
        assert len(series.orientation) == 6

    def test_create_series_without_orientation(self, temp_dir, detector):
        """Test _create_series handles missing orientation gracefully."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        file_path = temp_dir / "slice.dcm"
        create_dicom_file(
            file_path,
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            include_orientation=False,
        )

        series = detector._create_series(
            series_uid=series_uid,
            files=[file_path],
            study_uid=study_uid,
            modality="CT",
        )

        assert series is not None
        # Orientation should be None or unchanged


class TestDicomSeriesIntegration:
    """Integration tests for DicomSeries with real files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_series_calculate_slice_spacing(self, temp_dir):
        """Test DicomSeries.calculate_slice_spacing with uniform spacing."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create files with 2.5mm uniform spacing
        files = []
        for i in range(5):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
                image_position=(0.0, 0.0, float(i * 2.5)),
            )
            files.append(file_path)

        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=files,
        )

        spacing = series.calculate_slice_spacing()

        # Should be ~2.5mm
        assert spacing is not None
        assert abs(spacing - 2.5) < 0.1

    def test_series_get_dimensions(self, temp_dir):
        """Test DicomSeries.get_dimensions returns correct values."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Create 3 slices with 64x64 dimensions
        files = []
        for i in range(3):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
                rows=64,
                columns=64,
            )
            files.append(file_path)

        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=files,
        )

        dimensions = series.get_dimensions()

        assert dimensions == (64, 64, 3)

    def test_series_load_first_slice(self, temp_dir):
        """Test DicomSeries.load_first_slice returns Dataset."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        files = []
        for i in range(2):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=files,
        )

        ds = series.load_first_slice()

        assert ds is not None
        assert isinstance(ds, Dataset)
        assert ds.Modality == "CT"

    def test_series_validate_consistency(self, temp_dir):
        """Test DicomSeries.validate_series_consistency with consistent series."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        files = []
        for i in range(3):
            file_path = temp_dir / f"slice_{i:03d}.dcm"
            create_dicom_file(
                file_path,
                series_uid=series_uid,
                study_uid=study_uid,
                modality="CT",
                instance_number=i + 1,
            )
            files.append(file_path)

        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=files,
        )

        errors = series.validate_series_consistency()

        assert errors == []  # No validation errors

    def test_series_properties(self, temp_dir):
        """Test DicomSeries properties (is_3d, is_multislice, slice_count)."""
        series_uid = generate_uid()
        study_uid = generate_uid()

        # Single slice series
        single_file = temp_dir / "single.dcm"
        create_dicom_file(single_file, series_uid, study_uid)

        single_series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=[single_file],
        )

        assert single_series.slice_count == 1
        assert single_series.is_3d is False
        assert single_series.is_multislice is False

        # Multi-slice series
        multi_uid = generate_uid()
        multi_files = []
        for i in range(5):
            file_path = temp_dir / f"multi_{i:03d}.dcm"
            create_dicom_file(file_path, multi_uid, study_uid, instance_number=i + 1)
            multi_files.append(file_path)

        multi_series = DicomSeries(
            series_uid=multi_uid,
            study_uid=study_uid,
            modality="CT",
            slices=multi_files,
        )

        assert multi_series.slice_count == 5
        assert multi_series.is_3d is True
        assert multi_series.is_multislice is True
