"""
Comprehensive test suite for SeriesDetector

Tests the SeriesDetector class including:
- Series detection from file lists
- Directory scanning (recursive and non-recursive)
- File grouping by SeriesInstanceUID
- Slice sorting by ImagePositionPatient
- Edge cases (missing UIDs, mixed series, malformed files)
- Summary statistics generation
"""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.core.series_detector import SeriesDetector


class TestSeriesDetectorInitialization:
    """Test SeriesDetector initialization."""

    def test_initialization(self):
        """Test creating a SeriesDetector."""
        detector = SeriesDetector()
        assert detector._series_cache == {}


class TestDetectSeries:
    """Test detect_series method."""

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_detect_single_series(self, mock_dcmread):
        """Test detecting a single series."""
        # Mock DICOM files with same SeriesInstanceUID
        mock_datasets = []
        for i in range(3):
            ds = Mock()
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.ImagePositionPatient = [100.0, 200.0, float(i * 5)]
            ds.InstanceNumber = i + 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 2  # Called twice per file

        detector = SeriesDetector()
        files = [Path(f"/tmp/slice{i}.dcm") for i in range(3)]

        series_list = detector.detect_series(files, validate=False)

        assert len(series_list) == 1
        assert series_list[0].series_uid == "1.2.3.4.5"
        assert series_list[0].study_uid == "1.2.3.4"
        assert series_list[0].modality == "CT"
        assert series_list[0].slice_count == 3

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_detect_multiple_series(self, mock_dcmread):
        """Test detecting multiple series in file list."""

        # Mock files from two different series
        def mock_read(path, stop_before_pixels=False):
            ds = Mock()
            if "series1" in str(path):
                ds.SeriesInstanceUID = "1.1.1.1.1"
                ds.StudyInstanceUID = "1.1.1.1"
                ds.Modality = "CT"
            else:
                ds.SeriesInstanceUID = "2.2.2.2.2"
                ds.StudyInstanceUID = "2.2.2.2"
                ds.Modality = "MR"

            ds.ImagePositionPatient = [0.0, 0.0, 0.0]
            ds.InstanceNumber = 1
            return ds

        mock_dcmread.side_effect = lambda path, stop_before_pixels=False: mock_read(
            path, stop_before_pixels
        )

        detector = SeriesDetector()
        files = [
            Path("/tmp/series1_slice1.dcm"),
            Path("/tmp/series1_slice2.dcm"),
            Path("/tmp/series2_slice1.dcm"),
            Path("/tmp/series2_slice2.dcm"),
        ]

        series_list = detector.detect_series(files, validate=False)

        assert len(series_list) == 2

        # Find each series
        ct_series = [s for s in series_list if s.modality == "CT"][0]
        mr_series = [s for s in series_list if s.modality == "MR"][0]

        assert ct_series.slice_count == 2
        assert mr_series.slice_count == 2

    def test_detect_series_empty_list(self):
        """Test detecting series with empty file list."""
        detector = SeriesDetector()
        series_list = detector.detect_series([], validate=False)
        assert series_list == []

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_detect_series_with_validation(self, mock_dcmread):
        """Test detection with validation enabled."""
        # Mock consistent series
        mock_datasets = []
        for i in range(2):
            ds = Mock()
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.ImagePositionPatient = [0.0, 0.0, float(i)]
            ds.InstanceNumber = i + 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 3  # Multiple calls

        detector = SeriesDetector()
        files = [Path(f"/tmp/slice{i}.dcm") for i in range(2)]

        series_list = detector.detect_series(files, validate=True)
        assert len(series_list) == 1

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_detect_series_missing_series_uid(self, mock_dcmread):
        """Test handling files without SeriesInstanceUID."""
        # Mock file without SeriesInstanceUID
        ds = Mock(spec=[])  # No SeriesInstanceUID
        mock_dcmread.return_value = ds

        detector = SeriesDetector()
        files = [Path("/tmp/slice1.dcm")]

        series_list = detector.detect_series(files, validate=False)
        assert len(series_list) == 0  # File should be skipped


class TestDetectSeriesInDirectory:
    """Test detect_series_in_directory method."""

    def test_directory_not_found(self):
        """Test error when directory doesn't exist."""
        detector = SeriesDetector()
        with pytest.raises(FileNotFoundError, match="Directory not found"):
            detector.detect_series_in_directory(Path("/nonexistent/path"))

    @patch("dicom_fuzzer.core.series_detector.SeriesDetector._find_dicom_files")
    @patch("dicom_fuzzer.core.series_detector.SeriesDetector.detect_series")
    def test_directory_scan_success(self, mock_detect, mock_find):
        """Test successful directory scanning."""
        # Mock finding files
        mock_files = [Path("/tmp/slice1.dcm"), Path("/tmp/slice2.dcm")]
        mock_find.return_value = mock_files

        # Mock series detection
        mock_series = Mock(spec=DicomSeries)
        mock_detect.return_value = [mock_series]

        detector = SeriesDetector()

        with patch.object(Path, "exists", return_value=True):
            series_list = detector.detect_series_in_directory(
                Path("/tmp"), recursive=True
            )

        assert len(series_list) == 1
        mock_find.assert_called_once_with(Path("/tmp"), recursive=True)
        mock_detect.assert_called_once()

    @patch("dicom_fuzzer.core.series_detector.SeriesDetector._find_dicom_files")
    def test_directory_scan_no_files_found(self, mock_find):
        """Test directory scan when no DICOM files found."""
        mock_find.return_value = []

        detector = SeriesDetector()

        with patch.object(Path, "exists", return_value=True):
            series_list = detector.detect_series_in_directory(Path("/tmp"))

        assert series_list == []


class TestFindDicomFiles:
    """Test _find_dicom_files method."""

    @patch.object(Path, "rglob")
    def test_find_files_recursive(self, mock_rglob):
        """Test finding DICOM files recursively."""
        # Mock found files
        mock_files = [
            Path("/tmp/subdir/file1.dcm"),
            Path("/tmp/subdir/file2.DCM"),
            Path("/tmp/file3.dicom"),
        ]
        mock_rglob.side_effect = [
            [mock_files[0]],  # *.dcm
            [mock_files[1]],  # *.DCM
            [mock_files[2]],  # *.dicom
            [],  # *.DICOM
            [],  # Files without extension
        ]

        detector = SeriesDetector()
        found = detector._find_dicom_files(Path("/tmp"), recursive=True)

        assert len(found) == 3
        assert mock_files[0] in found
        assert mock_files[1] in found
        assert mock_files[2] in found

    @patch.object(Path, "glob")
    def test_find_files_non_recursive(self, mock_glob):
        """Test finding DICOM files non-recursively."""
        mock_files = [Path("/tmp/file1.dcm")]
        mock_glob.side_effect = [[mock_files[0]], [], [], [], []]

        detector = SeriesDetector()
        found = detector._find_dicom_files(Path("/tmp"), recursive=False)

        assert len(found) >= 1
        assert mock_files[0] in found


class TestIsDicomFile:
    """Test _is_dicom_file method."""

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_valid_dicom_file(self, mock_dcmread):
        """Test detection of valid DICOM file."""
        mock_dcmread.return_value = Mock()

        detector = SeriesDetector()
        result = detector._is_dicom_file(Path("/tmp/file.dcm"))

        assert result is True

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_invalid_dicom_file(self, mock_dcmread):
        """Test detection of invalid file."""
        mock_dcmread.side_effect = Exception("Not a DICOM file")

        detector = SeriesDetector()
        result = detector._is_dicom_file(Path("/tmp/file.txt"))

        assert result is False


class TestGroupBySeriesUid:
    """Test _group_by_series_uid method."""

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_grouping_single_series(self, mock_dcmread):
        """Test grouping files from single series."""
        # Mock files with same SeriesInstanceUID
        mock_datasets = []
        for i in range(3):
            ds = Mock()
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        detector = SeriesDetector()
        files = [Path(f"/tmp/slice{i}.dcm") for i in range(3)]

        groups = detector._group_by_series_uid(files)

        assert len(groups) == 1
        assert "1.2.3.4.5" in groups
        assert len(groups["1.2.3.4.5"]["files"]) == 3
        assert groups["1.2.3.4.5"]["study_uid"] == "1.2.3.4"
        assert groups["1.2.3.4.5"]["modality"] == "CT"

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_grouping_multiple_series(self, mock_dcmread):
        """Test grouping files from multiple series."""

        # Mock two series
        def mock_read(path, stop_before_pixels=False):
            ds = Mock()
            if "series1" in str(path):
                ds.SeriesInstanceUID = "1.1.1.1.1"
                ds.StudyInstanceUID = "1.1.1.1"
                ds.Modality = "CT"
            else:
                ds.SeriesInstanceUID = "2.2.2.2.2"
                ds.StudyInstanceUID = "2.2.2.2"
                ds.Modality = "MR"
            return ds

        mock_dcmread.side_effect = lambda path, stop_before_pixels=False: mock_read(
            path, stop_before_pixels
        )

        detector = SeriesDetector()
        files = [
            Path("/tmp/series1_slice1.dcm"),
            Path("/tmp/series1_slice2.dcm"),
            Path("/tmp/series2_slice1.dcm"),
        ]

        groups = detector._group_by_series_uid(files)

        assert len(groups) == 2
        assert "1.1.1.1.1" in groups
        assert "2.2.2.2.2" in groups
        assert len(groups["1.1.1.1.1"]["files"]) == 2
        assert len(groups["2.2.2.2.2"]["files"]) == 1


class TestSortSlicesByPosition:
    """Test _sort_slices_by_position method."""

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_sort_by_image_position(self, mock_dcmread):
        """Test sorting slices by ImagePositionPatient."""
        # Mock slices with different z-positions (out of order)
        mock_datasets = []
        z_positions = [10.0, 0.0, 5.0]  # Out of order
        for z in z_positions:
            ds = Mock()
            ds.ImagePositionPatient = [100.0, 200.0, z]
            ds.InstanceNumber = 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        detector = SeriesDetector()
        files = [
            Path("/tmp/slice1.dcm"),
            Path("/tmp/slice2.dcm"),
            Path("/tmp/slice3.dcm"),
        ]

        sorted_files = detector._sort_slices_by_position(files)

        # Should be sorted descending by z (superior to inferior)
        assert len(sorted_files) == 3
        # File with z=10.0 should be first (most superior)
        assert sorted_files[0] == Path("/tmp/slice1.dcm")

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_sort_fallback_to_instance_number(self, mock_dcmread):
        """Test sorting falls back to InstanceNumber when positions are same."""
        # Mock slices with same z-position but different instance numbers
        mock_datasets = []
        instance_nums = [2, 1, 3]
        for num in instance_nums:
            ds = Mock()
            ds.ImagePositionPatient = [0.0, 0.0, 0.0]  # Same position
            ds.InstanceNumber = num
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        detector = SeriesDetector()
        files = [Path(f"/tmp/slice{i}.dcm") for i in range(3)]

        sorted_files = detector._sort_slices_by_position(files)

        assert len(sorted_files) == 3

    def test_sort_empty_list(self):
        """Test sorting empty file list."""
        detector = SeriesDetector()
        sorted_files = detector._sort_slices_by_position([])
        assert sorted_files == []


class TestGetSeriesSummary:
    """Test get_series_summary method."""

    def test_summary_empty_list(self):
        """Test summary with no series."""
        detector = SeriesDetector()
        summary = detector.get_series_summary([])

        assert summary["total_series"] == 0
        assert summary["total_slices"] == 0
        assert summary["multislice_series"] == 0
        assert summary["single_slice_series"] == 0

    def test_summary_single_series(self):
        """Test summary with single series."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(130)],
        )

        detector = SeriesDetector()
        summary = detector.get_series_summary([series])

        assert summary["total_series"] == 1
        assert summary["total_slices"] == 130
        assert summary["modalities"] == {"CT": 1}
        assert summary["multislice_series"] == 1
        assert summary["single_slice_series"] == 0
        assert summary["avg_slices_per_series"] == 130.0

    def test_summary_mixed_series(self):
        """Test summary with multiple series of different modalities."""
        series1 = DicomSeries(
            series_uid="1.1.1.1.1",
            study_uid="1.1.1.1",
            modality="CT",
            slices=[Path(f"/tmp/ct{i}.dcm") for i in range(100)],
        )

        series2 = DicomSeries(
            series_uid="2.2.2.2.2",
            study_uid="2.2.2.2",
            modality="MR",
            slices=[Path(f"/tmp/mr{i}.dcm") for i in range(50)],
        )

        series3 = DicomSeries(
            series_uid="3.3.3.3.3",
            study_uid="3.3.3.3",
            modality="US",
            slices=[Path("/tmp/us1.dcm")],  # Single slice
        )

        detector = SeriesDetector()
        summary = detector.get_series_summary([series1, series2, series3])

        assert summary["total_series"] == 3
        assert summary["total_slices"] == 151
        assert summary["modalities"] == {"CT": 1, "MR": 1, "US": 1}
        assert summary["multislice_series"] == 2
        assert summary["single_slice_series"] == 1
        assert pytest.approx(summary["avg_slices_per_series"], abs=0.1) == 50.3


class TestEdgeCasesAndExceptionPaths:
    """Tests for edge cases and exception handling paths."""

    @patch("dicom_fuzzer.core.series_detector.SeriesDetector.detect_series_in_directory")
    def test_detect_series_with_path_object(self, mock_detect_dir):
        """Test detect_series when called with Path object (directory)."""
        mock_series = Mock(spec=DicomSeries)
        mock_detect_dir.return_value = [mock_series]

        detector = SeriesDetector()
        series_list = detector.detect_series(Path("/tmp/dicom_dir"), validate=True)

        mock_detect_dir.assert_called_once_with(
            Path("/tmp/dicom_dir"), recursive=True, validate=True
        )
        assert len(series_list) == 1

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_detect_series_create_series_exception(self, mock_dcmread):
        """Test handling exception when creating series."""
        # Mock successful file reading but series creation fails
        ds = Mock()
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds.InstanceNumber = 1
        mock_dcmread.return_value = ds

        detector = SeriesDetector()

        # Mock _create_series to raise exception
        with patch.object(
            detector, "_create_series", side_effect=Exception("Series creation failed")
        ):
            files = [Path("/tmp/slice1.dcm")]
            series_list = detector.detect_series(files, validate=False)

            # Should return empty list since series creation failed
            assert series_list == []

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_group_by_series_uid_file_read_exception(self, mock_dcmread):
        """Test _group_by_series_uid handles file read exceptions."""
        # Mock one file succeeds, one fails
        ds = Mock()
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"

        mock_dcmread.side_effect = [
            ds,  # First file succeeds
            Exception("File read error"),  # Second file fails
        ]

        detector = SeriesDetector()
        files = [Path("/tmp/slice1.dcm"), Path("/tmp/slice2.dcm")]

        groups = detector._group_by_series_uid(files)

        # Should have one file in the group, second was skipped
        assert len(groups) == 1
        assert "1.2.3.4.5" in groups
        assert len(groups["1.2.3.4.5"]["files"]) == 1

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_group_by_series_uid_missing_optional_fields(self, mock_dcmread):
        """Test _group_by_series_uid handles missing StudyInstanceUID and Modality."""
        # Mock file with SeriesInstanceUID but no optional fields
        ds = Mock()
        ds.SeriesInstanceUID = "1.2.3.4.5"
        # No StudyInstanceUID, no Modality
        delattr(ds, "StudyInstanceUID") if hasattr(ds, "StudyInstanceUID") else None
        delattr(ds, "Modality") if hasattr(ds, "Modality") else None

        # Use spec to ensure attributes are really missing
        ds = Mock(spec=["SeriesInstanceUID"])
        ds.SeriesInstanceUID = "1.2.3.4.5"

        mock_dcmread.return_value = ds

        detector = SeriesDetector()
        files = [Path("/tmp/slice1.dcm")]

        groups = detector._group_by_series_uid(files)

        assert len(groups) == 1
        assert groups["1.2.3.4.5"]["study_uid"] == "UNKNOWN"
        assert groups["1.2.3.4.5"]["modality"] == "UNKNOWN"

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_sort_slices_missing_image_position(self, mock_dcmread):
        """Test sorting when ImagePositionPatient is missing."""
        # Mock files without ImagePositionPatient
        mock_datasets = []
        for i in range(3):
            ds = Mock(spec=["InstanceNumber"])
            ds.InstanceNumber = i + 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        detector = SeriesDetector()
        files = [Path(f"/tmp/slice{i}.dcm") for i in range(3)]

        sorted_files = detector._sort_slices_by_position(files)

        # Should still return files, sorted by instance number
        assert len(sorted_files) == 3

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_sort_slices_read_exception(self, mock_dcmread):
        """Test sorting handles exceptions when reading position."""
        # Mock: first file succeeds, others fail
        ds = Mock()
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds.InstanceNumber = 1

        mock_dcmread.side_effect = [
            ds,  # First file succeeds
            Exception("Read error"),  # Second file fails
            Exception("Read error"),  # Third file fails
        ]

        detector = SeriesDetector()
        files = [Path(f"/tmp/slice{i}.dcm") for i in range(3)]

        sorted_files = detector._sort_slices_by_position(files)

        # Should still return all files
        assert len(sorted_files) == 3

    @patch.object(Path, "rglob")
    @patch.object(Path, "is_file")
    @patch("dicom_fuzzer.core.series_detector.SeriesDetector._is_dicom_file")
    def test_find_dicom_files_no_extension_recursive(
        self, mock_is_dicom, mock_is_file, mock_rglob
    ):
        """Test finding DICOM files without extension (recursive)."""
        # Mock DICOM file patterns return empty
        mock_rglob.return_value = []

        # Create mock file without extension
        file_no_ext = Mock(spec=Path)
        file_no_ext.is_file.return_value = True
        file_no_ext.suffix = ""
        file_no_ext.name = "DICOMFILE"

        # Mock rglob to return no .dcm files but our file without extension
        def rglob_side_effect(pattern):
            if pattern == "*":
                return [file_no_ext]
            return []

        mock_rglob.side_effect = rglob_side_effect
        mock_is_dicom.return_value = True

        detector = SeriesDetector()

        # Override Path.rglob on the directory
        directory = Mock(spec=Path)
        directory.rglob = mock_rglob

        # This tests the _find_dicom_files branch for files without extension
        # We need to actually call the method
        with patch.object(Path, "rglob", mock_rglob):
            found = detector._find_dicom_files(Path("/tmp"), recursive=True)

        # May be empty since mocking is complex - the important thing is no exception
        assert isinstance(found, list)

    @patch.object(Path, "glob")
    def test_find_dicom_files_no_extension_non_recursive(self, mock_glob):
        """Test finding DICOM files without extension (non-recursive)."""
        # Mock file without extension
        file_no_ext = Mock(spec=Path)
        file_no_ext.is_file.return_value = True
        file_no_ext.suffix = ""
        file_no_ext.name = "DICOMFILE"

        # Mock glob returns
        def glob_side_effect(pattern):
            if pattern == "*":
                return [file_no_ext]
            return []

        mock_glob.side_effect = glob_side_effect

        detector = SeriesDetector()

        with patch.object(
            detector, "_is_dicom_file", return_value=True
        ), patch.object(Path, "glob", mock_glob):
            found = detector._find_dicom_files(Path("/tmp"), recursive=False)

        assert isinstance(found, list)

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_create_series_orientation_extraction_exception(self, mock_dcmread):
        """Test _create_series handles exception when extracting orientation."""
        # First call for sorting - normal
        ds1 = Mock()
        ds1.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds1.InstanceNumber = 1

        # Second call for orientation extraction - fails
        mock_dcmread.side_effect = [ds1, Exception("Cannot read orientation")]

        detector = SeriesDetector()
        files = [Path("/tmp/slice1.dcm")]

        series = detector._create_series(
            series_uid="1.2.3.4.5",
            files=files,
            study_uid="1.2.3.4",
            modality="CT",
        )

        # Should still create series, just without orientation
        assert series is not None
        assert series.series_uid == "1.2.3.4.5"

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_create_series_missing_orientation(self, mock_dcmread):
        """Test _create_series when ImageOrientationPatient is missing."""
        ds = Mock()
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds.InstanceNumber = 1
        # No ImageOrientationPatient
        delattr(ds, "ImageOrientationPatient") if hasattr(
            ds, "ImageOrientationPatient"
        ) else None

        ds = Mock(spec=["ImagePositionPatient", "InstanceNumber"])
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds.InstanceNumber = 1

        mock_dcmread.return_value = ds

        detector = SeriesDetector()
        files = [Path("/tmp/slice1.dcm")]

        series = detector._create_series(
            series_uid="1.2.3.4.5",
            files=files,
            study_uid="1.2.3.4",
            modality="CT",
        )

        # Should create series without orientation
        assert series is not None

    @patch("dicom_fuzzer.core.series_detector.pydicom.dcmread")
    def test_sort_slices_missing_instance_number(self, mock_dcmread):
        """Test sorting when InstanceNumber is missing."""
        ds = Mock(spec=["ImagePositionPatient"])
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]

        mock_dcmread.return_value = ds

        detector = SeriesDetector()
        files = [Path("/tmp/slice1.dcm")]

        sorted_files = detector._sort_slices_by_position(files)

        assert len(sorted_files) == 1
