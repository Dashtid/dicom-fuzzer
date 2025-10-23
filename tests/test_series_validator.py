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

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.core.series_validator import (
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

        warnings = report.get_issues_by_severity(ValidationSeverity.WARNING)
        assert any("large spacing" in issue.message.lower() for issue in warnings)


class TestValidateMetadata:
    """Test metadata validation."""

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
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

    @patch("dicom_fuzzer.core.series_validator.pydicom.dcmread")
    def test_perfect_series_validation(self, mock_dcmread):
        """Test validation of a perfect series."""
        # Mock perfect series
        mock_datasets = []
        for i in range(10):
            ds = Mock()
            ds.SeriesInstanceUID = "1.2.3.4.5"
            ds.StudyInstanceUID = "1.2.3.4"
            ds.Modality = "CT"
            ds.InstanceNumber = i + 1
            ds.ImagePositionPatient = [0.0, 0.0, float(i * 5)]
            ds.Rows = 512
            ds.Columns = 512
            mock_datasets.append(ds)

        mock_dcmread.side_effect = mock_datasets * 3

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
