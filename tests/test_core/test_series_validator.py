"""
Comprehensive test suite for SeriesValidator

Tests the SeriesValidator class including:
- Series validation (completeness, consistency, geometry, metadata)
- ValidationReport generation
- ValidationIssue severity levels
- Security concern detection
- Edge cases (empty series, single-slice, extreme values)
"""

from pathlib import Path
from unittest.mock import Mock, patch

from dicom_fuzzer.core.dicom.dicom_series import DicomSeries
from dicom_fuzzer.core.series.series_validator import (
    SeriesValidator,
    ValidationIssue,
    ValidationReport,
    ValidationSeverity,
)


class TestValidationSeverity:
    """Test ValidationSeverity enum."""

    def test_severity_levels_exist(self):
        """Test all severity levels are defined."""
        assert hasattr(ValidationSeverity, "INFO")
        assert hasattr(ValidationSeverity, "WARNING")
        assert hasattr(ValidationSeverity, "ERROR")
        assert hasattr(ValidationSeverity, "CRITICAL")

    def test_severity_values(self):
        """Test severity values."""
        assert ValidationSeverity.INFO.value == "info"
        assert ValidationSeverity.WARNING.value == "warning"
        assert ValidationSeverity.ERROR.value == "error"
        assert ValidationSeverity.CRITICAL.value == "critical"


class TestValidationIssue:
    """Test ValidationIssue dataclass."""

    def test_issue_creation(self):
        """Test creating a ValidationIssue."""
        issue = ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category="consistency",
            message="Test error",
            slice_index=5,
            slice_path=Path("/tmp/slice5.dcm"),
            details={"key": "value"},
        )

        assert issue.severity == ValidationSeverity.ERROR
        assert issue.category == "consistency"
        assert issue.message == "Test error"
        assert issue.slice_index == 5
        assert issue.slice_path == Path("/tmp/slice5.dcm")
        assert issue.details == {"key": "value"}

    def test_issue_repr(self):
        """Test string representation of issue."""
        issue = ValidationIssue(
            severity=ValidationSeverity.WARNING,
            category="geometry",
            message="Non-uniform spacing",
            slice_index=10,
        )

        repr_str = repr(issue)
        assert "WARNING" in repr_str
        assert "geometry" in repr_str
        assert "Non-uniform spacing" in repr_str
        assert "slice 10" in repr_str


class TestValidationReport:
    """Test ValidationReport dataclass."""

    def test_empty_report(self):
        """Test empty validation report."""
        series = DicomSeries(series_uid="1.2.3.4.5", study_uid="1.2.3.4", modality="CT")
        report = ValidationReport(series=series)

        assert report.is_valid is True
        assert len(report.issues) == 0
        assert report.has_critical_issues() is False
        assert report.has_errors() is False

    def test_report_with_issues(self):
        """Test report with various issues."""
        series = DicomSeries(series_uid="1.2.3.4.5", study_uid="1.2.3.4", modality="CT")
        report = ValidationReport(series=series)

        report.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.INFO, category="test", message="Info"
            )
        )
        report.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="test",
                message="Warning",
            )
        )
        report.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.ERROR, category="test", message="Error"
            )
        )

        assert len(report.issues) == 3
        assert len(report.get_issues_by_severity(ValidationSeverity.INFO)) == 1
        assert len(report.get_issues_by_severity(ValidationSeverity.WARNING)) == 1
        assert len(report.get_issues_by_severity(ValidationSeverity.ERROR)) == 1
        assert report.has_errors() is True

    def test_report_summary(self):
        """Test report summary generation."""
        series = DicomSeries(series_uid="1.2.3.4.5", study_uid="1.2.3.4", modality="CT")
        report = ValidationReport(series=series)

        # Empty report
        summary = report.summary()
        assert "valid with no issues" in summary

        # Report with issues
        report.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category="test",
                message="Critical",
            )
        )
        report.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.ERROR, category="test", message="Error"
            )
        )

        summary = report.summary()
        assert "1 critical" in summary
        assert "1 errors" in summary


class TestSeriesValidatorInitialization:
    """Test SeriesValidator initialization."""

    def test_default_initialization(self):
        """Test default validator creation."""
        validator = SeriesValidator()
        assert validator.strict is False

    def test_strict_initialization(self):
        """Test strict mode validator."""
        validator = SeriesValidator(strict=True)
        assert validator.strict is True


class TestValidateCompleteness:
    """Test completeness validation."""

    def test_empty_series_critical(self):
        """Test validation of empty series."""
        series = DicomSeries(series_uid="1.2.3.4.5", study_uid="1.2.3.4", modality="CT")
        validator = SeriesValidator()
        report = validator.validate_series(series)

        # Should have critical issue for no slices
        critical_issues = report.get_issues_by_severity(ValidationSeverity.CRITICAL)
        assert len(critical_issues) > 0
        assert any("no slices" in issue.message.lower() for issue in critical_issues)

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_missing_instance_numbers(self, mock_dcmread):
        """Test detection of missing InstanceNumber."""
        # Mock datasets without InstanceNumber
        ds = Mock(spec=[])  # No InstanceNumber
        mock_dcmread.return_value = ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        warnings = report.get_issues_by_severity(ValidationSeverity.WARNING)
        assert any("missing InstanceNumber" in issue.message for issue in warnings)

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_gaps_in_instance_sequence(self, mock_dcmread):
        """Test detection of gaps in InstanceNumber sequence."""
        # Mock datasets with gaps (1, 2, 5)
        mock_datasets = []
        for num in [1, 2, 5]:  # Missing 3 and 4
            ds = Mock()
            ds.InstanceNumber = num
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 2  # Called multiple times

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        errors = report.get_issues_by_severity(ValidationSeverity.ERROR)
        assert any(
            "Missing" in issue.message and "instance" in issue.message
            for issue in errors
        )

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_large_series_warning(self, mock_dcmread):
        """Test warning for unusually large series."""
        # Mock dataset
        ds = Mock()
        ds.InstanceNumber = 1
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        mock_dcmread.return_value = ds

        # Create series with > 1000 slices
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(1500)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        warnings = report.get_issues_by_severity(ValidationSeverity.WARNING)
        assert any("Unusually large series" in issue.message for issue in warnings)


class TestValidateConsistency:
    """Test consistency validation."""

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_consistent_series_no_errors(self, mock_dcmread):
        """Test validation of consistent series."""
        # Mock consistent datasets
        mock_datasets = []
        for i in range(3):
            ds = Mock()
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = i + 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 2

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        # Should not have consistency errors
        consistency_errors = [
            issue for issue in report.issues if issue.category == "consistency"
        ]
        # Note: May have other category errors, but consistency should be OK
        # if it has errors, they should not be about mismatched UIDs
        for issue in consistency_errors:
            assert "mismatched" not in issue.message.lower()


class TestValidateGeometry:
    """Test geometry validation."""

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_uniform_spacing_no_warning(self, mock_dcmread):
        """Test uniform spacing doesn't trigger warnings."""
        # Mock uniform 5mm spacing
        mock_datasets = []
        for z in [0.0, 5.0, 10.0, 15.0]:
            ds = Mock()
            ds.ImagePositionPatient = [0.0, 0.0, z]
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 2

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(4)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        geometry_issues = [
            issue for issue in report.issues if issue.category == "geometry"
        ]
        # Should not have non-uniform spacing warning
        assert not any("Non-uniform" in issue.message for issue in geometry_issues)

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_overlapping_slices_error(self, mock_dcmread):
        """Test detection of overlapping slices."""
        # Mock overlapping positions
        mock_datasets = []
        for z in [0.0, 0.0, 5.0]:  # First two at same position
            ds = Mock()
            ds.ImagePositionPatient = [0.0, 0.0, z]
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 2

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        errors = report.get_issues_by_severity(ValidationSeverity.ERROR)
        assert any(
            "Overlapping" in issue.message or "duplicate" in issue.message.lower()
            for issue in errors
        )

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_extreme_spacing_warning(self, mock_dcmread):
        """Test warning for extreme slice spacing."""
        # Mock extreme 60mm spacing
        mock_datasets = []
        for z in [0.0, 60.0, 120.0]:
            ds = Mock()
            ds.ImagePositionPatient = [0.0, 0.0, z]
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 2

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        # Check for warnings about spacing or overlapping (extreme spacing may also trigger overlapping detection)
        all_issues = report.issues
        assert any(
            "spacing" in issue.message.lower()
            or "extreme" in issue.message.lower()
            or "overlap" in issue.message.lower()
            for issue in all_issues
        ), f"Expected spacing or overlap issue, got: {[i.message for i in all_issues]}"


class TestValidateMetadata:
    """Test metadata validation."""

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_missing_required_tags(self, mock_dcmread):
        """Test detection of missing required tags."""
        # Mock dataset without required tags
        ds = Mock(spec=[])  # No attributes
        mock_dcmread.return_value = ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        errors = report.get_issues_by_severity(ValidationSeverity.ERROR)
        # Should detect missing SeriesInstanceUID, StudyInstanceUID, Modality
        assert len(errors) >= 3


class TestValidateSecurityConcerns:
    """Test security concern detection."""

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_extreme_dimensions_warning(self, mock_dcmread):
        """Test warning for extreme image dimensions."""
        # Mock dataset with extreme dimensions
        ds = Mock()
        ds.Rows = 8192  # Very large
        ds.Columns = 8192
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        mock_dcmread.return_value = ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path("/tmp/slice1.dcm")],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        warnings = report.get_issues_by_severity(ValidationSeverity.WARNING)
        security_warnings = [w for w in warnings if w.category == "security"]
        assert any("large" in issue.message.lower() for issue in security_warnings)

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_memory_exhaustion_warning(self, mock_dcmread):
        """Test warning for potential memory exhaustion."""
        # Mock very large volume
        ds = Mock()
        ds.Rows = 2048
        ds.Columns = 2048
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        mock_dcmread.return_value = ds

        # 500 slices * 2048 * 2048 = 2 billion pixels
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(500)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        warnings = report.get_issues_by_severity(ValidationSeverity.WARNING)
        security_warnings = [w for w in warnings if w.category == "security"]
        assert any(
            "memory exhaustion" in issue.message.lower() for issue in security_warnings
        )


class TestValidateSeriesIntegration:
    """Integration tests for full series validation."""

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_perfect_series_validation(self, mock_dcmread):
        """Test validation of a perfect series."""
        from unittest.mock import MagicMock

        # Mock perfect series
        mock_datasets = []
        for i in range(10):
            ds = MagicMock()  # MagicMock handles hasattr() properly
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = i + 1
            ds.ImagePositionPatient = [0.0, 0.0, float(i * 5)]
            ds.Rows = 512
            ds.Columns = 512
            mock_datasets.append(ds)

        # Return mocks in cycle - validator calls dcmread multiple times per slice
        from itertools import cycle

        mock_dcmread.side_effect = cycle(mock_datasets)

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(10)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        # Should be valid with minimal issues
        assert (
            report.is_valid is True
            or len(report.get_issues_by_severity(ValidationSeverity.ERROR)) == 0
        )

    def test_validation_timing(self):
        """Test that validation_time is populated."""
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        assert report.validation_time >= 0.0


class TestValidateGeometryEdgeCases:
    """Test edge cases in geometry validation for 100% coverage."""

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_insufficient_position_data_warning(self, mock_dcmread):
        """Test warning when series has slices but get_slice_positions returns <2 positions.

        This tests lines 300-307 in series_validator.py.
        """
        # Mock dataset with no ImagePositionPatient to simulate insufficient positions
        ds = Mock()
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        ds.InstanceNumber = 1
        # No ImagePositionPatient attribute
        ds.configure_mock(**{"ImagePositionPatient": None})
        mock_dcmread.return_value = ds

        # Create series with multiple slices
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        # Mock get_slice_positions to return only 1 position
        with patch.object(
            series, "get_slice_positions", return_value=[(0.0, 0.0, 0.0)]
        ):
            validator = SeriesValidator()
            report = validator.validate_series(series)

            # Should have warning about insufficient position data
            geometry_warnings = [
                issue
                for issue in report.issues
                if issue.category == "geometry"
                and issue.severity == ValidationSeverity.WARNING
            ]
            assert any(
                "Insufficient position data" in issue.message
                for issue in geometry_warnings
            ), (
                f"Expected 'Insufficient position data' warning, got: {[i.message for i in geometry_warnings]}"
            )

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_non_uniform_spacing_warning(self, mock_dcmread):
        """Test warning for non-uniform slice spacing (coefficient of variation > 0.01).

        This tests line 323 in series_validator.py.
        """
        # Mock datasets with non-uniform spacing
        # Spacings: 5, 10, 5 - mean=6.67, std=2.36, cv=0.35 > 0.01
        mock_datasets = []
        z_positions = [0.0, 5.0, 15.0, 20.0]  # Spacings: 5, 10, 5
        for i, z in enumerate(z_positions):
            ds = Mock()
            ds.ImagePositionPatient = [0.0, 0.0, z]
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = i + 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 3  # Called multiple times

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(4)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        # Check for non-uniform spacing warning
        geometry_warnings = [
            issue
            for issue in report.issues
            if issue.category == "geometry"
            and issue.severity == ValidationSeverity.WARNING
        ]
        assert any("Non-uniform" in issue.message for issue in geometry_warnings), (
            f"Expected 'Non-uniform' spacing warning, got: {[i.message for i in geometry_warnings]}"
        )

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_large_spacing_warning_over_50mm(self, mock_dcmread):
        """Test warning for unusually large spacing (>50mm).

        This tests line 349 in series_validator.py.
        """
        # Mock datasets with >50mm spacing between slices
        mock_datasets = []
        z_positions = [0.0, 55.0, 110.0]  # Spacing is 55mm > 50mm threshold
        for i, z in enumerate(z_positions):
            ds = Mock()
            ds.ImagePositionPatient = [0.0, 0.0, z]
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = i + 1
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 3

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        validator = SeriesValidator()
        report = validator.validate_series(series)

        # Check for large spacing warning
        geometry_warnings = [
            issue
            for issue in report.issues
            if issue.category == "geometry"
            and issue.severity == ValidationSeverity.WARNING
        ]
        assert any(
            "large spacing" in issue.message.lower() for issue in geometry_warnings
        ), (
            f"Expected 'large spacing' warning, got: {[i.message for i in geometry_warnings]}"
        )

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_empty_positions_list(self, mock_dcmread):
        """Test when get_slice_positions returns empty list.

        This ensures the insufficient position data path is hit (lines 299-307).
        """
        ds = Mock()
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        ds.InstanceNumber = 1
        mock_dcmread.return_value = ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(3)],
        )

        # Mock get_slice_positions to return empty list
        with patch.object(series, "get_slice_positions", return_value=[]):
            validator = SeriesValidator()
            report = validator.validate_series(series)

            # Should have warning about insufficient position data
            geometry_warnings = [
                issue
                for issue in report.issues
                if issue.category == "geometry"
                and "Insufficient position data" in issue.message
            ]
            assert len(geometry_warnings) == 1, (
                f"Expected exactly 1 'Insufficient position data' warning, got {len(geometry_warnings)}"
            )

    @patch("dicom_fuzzer.core.series.series_validator.pydicom.dcmread")
    def test_single_position_insufficient_data(self, mock_dcmread):
        """Test when series has multiple slices but only one valid position.

        This specifically targets the len(positions) < 2 check (lines 299-307).
        """
        ds = Mock()
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"
        ds.InstanceNumber = 1
        mock_dcmread.return_value = ds

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.2.3.4",
            modality="CT",
            slices=[Path(f"/tmp/slice{i}.dcm") for i in range(5)],
        )

        # Mock get_slice_positions to return exactly 1 position
        with patch.object(
            series, "get_slice_positions", return_value=[(100.0, 200.0, 50.0)]
        ):
            validator = SeriesValidator()
            report = validator.validate_series(series)

            # Should have warning about insufficient position data
            insufficient_warnings = [
                issue
                for issue in report.issues
                if "Insufficient position data" in issue.message
            ]
            assert len(insufficient_warnings) >= 1, (
                "Expected 'Insufficient position data' warning"
            )
