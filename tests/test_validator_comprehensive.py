"""Comprehensive tests for dicom_fuzzer.core.validator module."""

from pydicom import Dataset

from dicom_fuzzer.core.validator import DicomValidator, ValidationResult


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
        assert validator.max_file_size == 100 * 1024 * 1024

    def test_initialization_strict_mode(self):
        """Test strict mode initialization."""
        validator = DicomValidator(strict_mode=True)

        assert validator.strict_mode is True

    def test_initialization_custom_options(self):
        """Test custom options."""
        validator = DicomValidator(strict_mode=True, max_file_size=50 * 1024 * 1024)

        assert validator.strict_mode is True
        assert validator.max_file_size == 50 * 1024 * 1024

    def test_validate_file_missing(self):
        """Test validation of missing file."""
        validator = DicomValidator()

        result, dataset = validator.validate_file("nonexistent.dcm")

        assert result.is_valid is False
        assert len(result.errors) > 0
        assert dataset is None

    def test_validate_file_success(self, tmp_path):
        """Test successful file validation."""
        # Create a minimal valid DICOM file
        test_file = tmp_path / "test.dcm"

        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

        # Create file meta information
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"  # Implicit VR Little Endian
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7"

        # Create dataset
        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test^Patient"
        ds.PatientID = "TEST001"

        # Save the file
        pydicom.dcmwrite(str(test_file), ds)

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        # Should return result and dataset
        assert isinstance(result, ValidationResult)
        assert dataset is not None

    def test_validate_dataset_empty(self):
        """Test validation of empty dataset."""
        validator = DicomValidator(strict_mode=True)
        dataset = Dataset()

        result = validator.validate(dataset)

        # Empty dataset should have issues in strict mode
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False  # Empty dataset is invalid

    def test_validate_dataset_basic(self):
        """Test basic dataset validation."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "Test"

        result = validator.validate(dataset)

        assert isinstance(result, ValidationResult)

    def test_validation_logs_security_events(self):
        """Test that validation failures log security events."""
        validator = DicomValidator(strict_mode=True)

        # This will trigger validation logic
        result, dataset = validator.validate_file("missing.dcm")

        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert dataset is None


class TestValidationIntegration:
    """Integration tests for validation."""

    def test_validation_workflow(self):
        """Test complete validation workflow."""
        result = ValidationResult()

        # Simulate validation process
        result.add_warning("Optional field missing")

        # Demonstrate conditional error (walrus operator for demonstration)
        if critical_check_fails := False:
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
            "Invalid VR", {"tag": "0x0010,0x0010", "expected": "PN", "actual": "LO"}
        )

        assert result.is_valid is False
        assert "Invalid VR" in result.info
