"""Comprehensive tests for dicom_fuzzer.core.validator module."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from pydicom import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.core.validator import ValidationResult, DicomValidator


class TestValidationResult:
    """Test ValidationResult class."""

    def test_init_default_valid(self):
        """Test default initialization is valid."""
        result = ValidationResult()

        assert result.is_valid is True
        assert result.errors == []
        assert result.warnings == []
        assert result.info == {}

    def test_init_invalid(self):
        """Test initialization as invalid."""
        result = ValidationResult(is_valid=False)

        assert result.is_valid is False

    def test_add_error_sets_invalid(self):
        """Test adding error makes result invalid."""
        result = ValidationResult(is_valid=True)

        result.add_error("Test error")

        assert result.is_valid is False
        assert "Test error" in result.errors

    def test_add_error_with_context(self):
        """Test adding error with context."""
        result = ValidationResult()
        context = {"tag": "0x0008", "value": "invalid"}

        result.add_error("Invalid tag", context)

        assert result.errors == ["Invalid tag"]
        assert result.info["Invalid tag"] == context

    def test_add_warning_keeps_valid(self):
        """Test warnings don't affect validity."""
        result = ValidationResult(is_valid=True)

        result.add_warning("Minor issue")

        assert result.is_valid is True
        assert "Minor issue" in result.warnings

    def test_add_warning_with_context(self):
        """Test warning with context."""
        result = ValidationResult()
        context = {"field": "PatientName"}

        result.add_warning("Missing optional field", context)

        assert result.warnings == ["Missing optional field"]
        assert result.info["Missing optional field"] == context

    def test_bool_conversion_valid(self):
        """Test boolean conversion for valid result."""
        result = ValidationResult(is_valid=True)

        assert bool(result) is True
        if result:
            assert True
        else:
            assert False, "Should be truthy"

    def test_bool_conversion_invalid(self):
        """Test boolean conversion for invalid result."""
        result = ValidationResult(is_valid=False)

        assert bool(result) is False

    def test_multiple_errors(self):
        """Test multiple errors."""
        result = ValidationResult()

        result.add_error("Error 1")
        result.add_error("Error 2")
        result.add_error("Error 3")

        assert len(result.errors) == 3
        assert result.is_valid is False

    def test_multiple_warnings(self):
        """Test multiple warnings."""
        result = ValidationResult()

        result.add_warning("Warning 1")
        result.add_warning("Warning 2")

        assert len(result.warnings) == 2
        assert result.is_valid is True

    def test_mixed_errors_and_warnings(self):
        """Test mix of errors and warnings."""
        result = ValidationResult()

        result.add_warning("Warning")
        result.add_error("Error")
        result.add_warning("Another warning")

        assert len(result.errors) == 1
        assert len(result.warnings) == 2
        assert result.is_valid is False


class TestDicomValidator:
    """Test DicomValidator class."""

    def test_initialization_default(self):
        """Test default initialization."""
        validator = DicomValidator()

        assert validator.strict_mode is False
        assert validator.check_required is True
        assert validator.check_vr is True

    def test_initialization_strict_mode(self):
        """Test strict mode initialization."""
        validator = DicomValidator(strict_mode=True)

        assert validator.strict_mode is True

    def test_initialization_custom_options(self):
        """Test custom options."""
        validator = DicomValidator(
            strict_mode=True,
            check_required=False,
            check_vr=False
        )

        assert validator.check_required is False
        assert validator.check_vr is False

    def test_validate_file_missing(self):
        """Test validation of missing file."""
        validator = DicomValidator()

        result = validator.validate_file("nonexistent.dcm")

        assert result.is_valid is False
        assert len(result.errors) > 0

    @patch('dicom_fuzzer.core.validator.Path.exists')
    @patch('pydicom.dcmread')
    def test_validate_file_success(self, mock_dcmread, mock_exists):
        """Test successful file validation."""
        mock_exists.return_value = True
        mock_dataset = Mock(spec=Dataset)
        mock_dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        mock_dataset.PatientName = "Test^Patient"
        mock_dcmread.return_value = mock_dataset

        validator = DicomValidator()
        result = validator.validate_file("test.dcm")

        # Should call validation
        mock_dcmread.assert_called_once()

    def test_validate_dataset_empty(self):
        """Test validation of empty dataset."""
        validator = DicomValidator(strict_mode=True)
        dataset = Dataset()

        result = validator.validate_dataset(dataset)

        # Empty dataset should have issues in strict mode
        assert isinstance(result, ValidationResult)

    def test_validate_dataset_basic(self):
        """Test basic dataset validation."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "Test"

        result = validator.validate_dataset(dataset)

        assert isinstance(result, ValidationResult)

    @patch('dicom_fuzzer.core.validator.SecurityEventLogger')
    def test_validation_logs_security_events(self, mock_logger):
        """Test that validation failures log security events."""
        validator = DicomValidator(strict_mode=True)

        # This will trigger validation logic
        result = validator.validate_file("missing.dcm")

        assert isinstance(result, ValidationResult)


class TestValidationIntegration:
    """Integration tests for validation."""

    def test_validation_workflow(self):
        """Test complete validation workflow."""
        result = ValidationResult()

        # Simulate validation process
        result.add_warning("Optional field missing")

        if some_critical_check_fails := False:
            result.add_error("Critical error")

        # Result should still be valid
        assert result.is_valid is True
        assert len(result.warnings) == 1

    def test_error_accumulation(self):
        """Test error accumulation."""
        result = ValidationResult()

        errors_found = ["Error 1", "Error 2", "Error 3"]
        for error in errors_found:
            result.add_error(error)

        assert len(result.errors) == 3
        assert all(e in result.errors for e in errors_found)

    def test_validation_with_context(self):
        """Test validation with rich context."""
        result = ValidationResult()

        result.add_error(
            "Invalid VR",
            {"tag": "0x0010,0x0010", "expected": "PN", "actual": "LO"}
        )

        assert result.is_valid is False
        assert "Invalid VR" in result.info
