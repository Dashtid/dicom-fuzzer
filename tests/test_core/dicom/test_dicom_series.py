"""
Comprehensive test suite for DicomSeries

Tests the DicomSeries dataclass including:
- Initialization and validation
- Properties (slice_count, is_3d)
- Slice position extraction
- Slice spacing calculation
- Dimensions retrieval
- Series consistency validation
- Edge cases (single-slice, missing metadata, malformed data)
"""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.dicom.dicom_series import DicomSeries


class TestDicomSeriesInitialization:
    """Test DicomSeries initialization and validation."""

    def test_valid_initialization(self):
        """Test creating a valid DicomSeries."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )
        assert series.series_uid == "1.2.3.4.5"
        assert series.study_uid == "1.2.3.4"
        assert series.modality == "CT"
        assert series.slices == []
        assert series.slice_spacing is None
        assert series.orientation is None
        assert series.metadata == {}

    def test_initialization_with_slices(self):
        """Test initialization with slice list."""
        slices = [Path("/tmp/slice1.dcm"), Path("/tmp/slice2.dcm")]
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=slices,
        )
        assert series.slice_count == 2
        assert series.slices == slices

    def test_empty_series_uid_raises_error(self):
        """Test that empty SeriesInstanceUID raises ValueError."""
        with pytest.raises(ValueError, match="SeriesInstanceUID cannot be empty"):
            DicomSeries(
                series_uid="",
                study_uid="1.2.3.4",
                modality="CT",
            )

    def test_empty_study_uid_raises_error(self):
        """Test that empty StudyInstanceUID raises ValueError."""
        with pytest.raises(ValueError, match="StudyInstanceUID cannot be empty"):
            DicomSeries(
                series_uid="1.2.3.4.5",
                study_uid="",
                modality="CT",
            )

    def test_empty_modality_raises_error(self):
        """Test that empty Modality raises ValueError."""
        with pytest.raises(ValueError, match="Modality cannot be empty"):
            DicomSeries(
                series_uid="1.2.3.4.5",
                study_uid="1.2.3.4",
                modality="",
            )


class TestDicomSeriesProperties:
    """Test DicomSeries properties."""

    def test_slice_count_empty(self):
        """Test slice_count with no slices."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )
        assert series.slice_count == 0

    def test_slice_count_single(self):
        """Test slice_count with single slice."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )
        assert series.slice_count == 1

    def test_slice_count_multiple(self):
        """Test slice_count with multiple slices."""
        slices = [Path(f"/tmp/slice{i}.dcm") for i in range(130)]
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=slices,
        )
        assert series.slice_count == 130

    def test_is_3d_empty_series(self):
        """Test is_3d with no slices."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )
        assert series.is_3d is False

    def test_is_3d_single_slice(self):
        """Test is_3d with single slice."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )
        assert series.is_3d is False

    def test_is_3d_multiple_slices(self):
        """Test is_3d with multiple slices."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm"), Path("/tmp/slice2.dcm")],
        )
        assert series.is_3d is True


class TestGetSlicePositions:
    """Test get_slice_positions method."""

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_get_positions_with_valid_data(self, mock_dcmread):
        """Test extracting positions from slices with valid ImagePositionPatient."""
        # Mock DICOM datasets
        mock_ds1 = Mock()
        mock_ds1.ImagePositionPatient = [100.0, 200.0, 0.0]

        mock_ds2 = Mock()
        mock_ds2.ImagePositionPatient = [100.0, 200.0, 5.0]

        mock_ds3 = Mock()
        mock_ds3.ImagePositionPatient = [100.0, 200.0, 10.0]

        mock_dcmread.side_effect = [mock_ds1, mock_ds2, mock_ds3]

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[
                Path("/tmp/slice1.dcm"),
                Path("/tmp/slice2.dcm"),
                Path("/tmp/slice3.dcm"),
            ],
        )

        positions = series.get_slice_positions()
        assert len(positions) == 3
        assert positions[0] == (100.0, 200.0, 0.0)
        assert positions[1] == (100.0, 200.0, 5.0)
        assert positions[2] == (100.0, 200.0, 10.0)

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_get_positions_missing_attribute(self, mock_dcmread):
        """Test handling of missing ImagePositionPatient."""
        mock_ds = Mock(spec=[])  # No ImagePositionPatient attribute
        mock_dcmread.return_value = mock_ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        positions = series.get_slice_positions()
        assert len(positions) == 1
        assert positions[0] == (0.0, 0.0, 0.0)  # Default fallback

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_get_positions_read_error(self, mock_dcmread):
        """Test handling of file read errors."""
        mock_dcmread.side_effect = Exception("File not found")

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        positions = series.get_slice_positions()
        assert len(positions) == 1
        assert positions[0] == (0.0, 0.0, 0.0)  # Error fallback


class TestCalculateSliceSpacing:
    """Test calculate_slice_spacing method."""

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_uniform_spacing(self, mock_dcmread):
        """Test calculating uniform slice spacing."""
        # Mock slices with uniform 5mm spacing
        mock_datasets = []
        for z in [0.0, 5.0, 10.0, 15.0, 20.0]:
            ds = Mock()
            ds.ImagePositionPatient = [100.0, 200.0, z]
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(5)],
        )

        spacing = series.calculate_slice_spacing()
        assert spacing is not None
        assert pytest.approx(spacing, abs=0.01) == 5.0

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_non_uniform_spacing(self, mock_dcmread):
        """Test non-uniform spacing returns None."""
        # Mock slices with non-uniform spacing
        mock_datasets = []
        for z in [0.0, 5.0, 12.0, 15.0]:  # 5, 7, 3 mm gaps
            ds = Mock()
            ds.ImagePositionPatient = [100.0, 200.0, z]
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(4)],
        )

        spacing = series.calculate_slice_spacing()
        assert spacing is None  # Non-uniform spacing

    def test_single_slice_spacing(self):
        """Test spacing calculation with single slice."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        spacing = series.calculate_slice_spacing()
        assert spacing is None  # Cannot calculate spacing with <2 slices


class TestGetDimensions:
    """Test get_dimensions method."""

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_dimensions_valid(self, mock_dcmread):
        """Test getting dimensions from valid series."""
        mock_ds = Mock()
        mock_ds.Rows = 512
        mock_ds.Columns = 512
        mock_dcmread.return_value = mock_ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(130)],
        )

        dims = series.get_dimensions()
        assert dims == (512, 512, 130)

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_dimensions_missing_attributes(self, mock_dcmread):
        """Test dimensions with missing Rows/Columns."""
        mock_ds = Mock(spec=[])  # No Rows/Columns
        mock_dcmread.return_value = mock_ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        dims = series.get_dimensions()
        assert dims == (0, 0, 1)

    def test_dimensions_empty_series(self):
        """Test dimensions with no slices."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )

        dims = series.get_dimensions()
        assert dims is None


class TestLoadFirstSlice:
    """Test load_first_slice method."""

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_load_first_slice_success(self, mock_dcmread):
        """Test successfully loading first slice."""
        mock_ds = Mock()
        mock_dcmread.return_value = mock_ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        ds = series.load_first_slice()
        assert ds is mock_ds
        mock_dcmread.assert_called_once_with(Path("/tmp/slice1.dcm"))

    def test_load_first_slice_empty_series(self):
        """Test loading first slice from empty series."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )

        ds = series.load_first_slice()
        assert ds is None

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_load_first_slice_error(self, mock_dcmread):
        """Test error handling when loading fails."""
        mock_dcmread.side_effect = Exception("Read error")

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        ds = series.load_first_slice()
        assert ds is None


class TestValidateSeriesConsistency:
    """Test validate_series_consistency method."""

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_consistent_series(self, mock_dcmread):
        """Test validation of consistent series."""
        # Mock consistent slices
        mock_datasets = []
        for i in range(3):
            ds = Mock()
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        errors = series.validate_series_consistency()
        assert len(errors) == 0

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_mismatched_series_uid(self, mock_dcmread):
        """Test detection of mismatched SeriesInstanceUID."""
        ds1 = Mock()
        ds1.SeriesInstanceUID = "1.2.3.4.5"
        ds1.StudyInstanceUID = "1.2.3.4"
        ds1.Modality = "CT"

        ds2 = Mock()
        ds2.SeriesInstanceUID = "9.9.9.9.9"  # Different!
        ds2.StudyInstanceUID = "1.2.3.4"
        ds2.Modality = "CT"

        mock_dcmread.side_effect = [ds1, ds2]

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm"), Path("/tmp/slice2.dcm")],
        )

        errors = series.validate_series_consistency()
        assert len(errors) > 0
        assert any("mismatched SeriesInstanceUID" in err for err in errors)

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_mismatched_modality(self, mock_dcmread):
        """Test detection of mismatched Modality."""
        ds1 = Mock()
        ds1.SeriesInstanceUID = "1.2.3.4.5"
        ds1.StudyInstanceUID = "1.2.3.4"
        ds1.Modality = "CT"

        ds2 = Mock()
        ds2.SeriesInstanceUID = "1.2.3.4.5"
        ds2.StudyInstanceUID = "1.2.3.4"
        ds2.Modality = "MR"  # Different!

        mock_dcmread.side_effect = [ds1, ds2]

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm"), Path("/tmp/slice2.dcm")],
        )

        errors = series.validate_series_consistency()
        assert len(errors) > 0
        assert any("mismatched Modality" in err for err in errors)

    @patch("dicom_fuzzer.core.dicom.dicom_series.pydicom.dcmread")
    def test_missing_required_attributes(self, mock_dcmread):
        """Test detection of missing required attributes."""
        ds = Mock(spec=[])  # No DICOM attributes
        mock_dcmread.return_value = ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        errors = series.validate_series_consistency()
        assert len(errors) >= 3  # Missing SeriesUID, StudyUID, Modality
        assert any("missing SeriesInstanceUID" in err for err in errors)
        assert any("missing StudyInstanceUID" in err for err in errors)
        assert any("missing Modality" in err for err in errors)

    def test_empty_series_validation(self):
        """Test validation of empty series."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )

        errors = series.validate_series_consistency()
        assert len(errors) == 1
        assert "Series has no slices" in errors[0]


class TestDicomSeriesStringRepresentation:
    """Test __repr__ method."""

    def test_repr_short_uid(self):
        """Test string representation with short UID."""
        series = DicomSeries(
            series_uid="1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(130)],
        )

        repr_str = repr(series)
        assert "DicomSeries" in repr_str
        assert "1.2.3.4.5.6.7.8." in repr_str  # Truncated UID
        assert "modality=CT" in repr_str
        assert "slices=130" in repr_str
        assert "is_3d=True" in repr_str

    def test_repr_single_slice(self):
        """Test repr for single-slice series."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="MR",
            slices=[Path("/tmp/slice1.dcm")],
        )

        repr_str = repr(series)
        assert "slices=1" in repr_str
        assert "is_3d=False" in repr_str
