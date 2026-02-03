"""
Real-object tests for DICOM Validator module.

LEARNING OBJECTIVE: This test suite demonstrates comprehensive validation testing
using actual DICOM datasets and real file I/O operations.

CONCEPT: These are "real-object" tests that use actual pydicom Dataset objects
and real DICOM files, not mocks or stubs.
"""

import pytest
from pydicom import DataElement, Dataset
from pydicom.dataset import FileDataset
from pydicom.tag import Tag
from pydicom.uid import ImplicitVRLittleEndian, generate_uid

from dicom_fuzzer.core.dicom.validator import DicomValidator, ValidationResult


class TestValidationResult:
    """Test ValidationResult class with real validation scenarios."""

    def test_initialization_valid(self):
        """Test creating a valid ValidationResult."""
        result = ValidationResult(is_valid=True)
        assert result.is_valid is True
        assert result.errors == []
        assert result.warnings == []
        assert result.info == {}

    def test_initialization_invalid(self):
        """Test creating an invalid ValidationResult."""
        result = ValidationResult(is_valid=False)
        assert result.is_valid is False
        assert result.errors == []
        assert result.warnings == []
        assert result.info == {}

    def test_default_initialization(self):
        """Test default initialization is valid."""
        result = ValidationResult()
        assert result.is_valid is True
        assert result.errors == []
        assert result.warnings == []

    def test_add_error(self):
        """Test adding errors to result."""
        result = ValidationResult()
        result.add_error("Missing required tag")

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0] == "Missing required tag"

    def test_add_multiple_errors(self):
        """Test adding multiple errors."""
        result = ValidationResult()
        result.add_error("Error 1")
        result.add_error("Error 2")
        result.add_error("Error 3")

        assert result.is_valid is False
        assert len(result.errors) == 3
        assert result.errors == ["Error 1", "Error 2", "Error 3"]

    def test_add_warning(self):
        """Test adding warnings to result."""
        result = ValidationResult()
        result.add_warning("Non-standard value detected")

        assert result.is_valid is True  # Warnings don't invalidate
        assert len(result.warnings) == 1
        assert result.warnings[0] == "Non-standard value detected"

    def test_add_multiple_warnings(self):
        """Test adding multiple warnings."""
        result = ValidationResult()
        result.add_warning("Warning 1")
        result.add_warning("Warning 2")

        assert result.is_valid is True
        assert len(result.warnings) == 2

    def test_errors_and_warnings_together(self):
        """Test that errors and warnings can coexist."""
        result = ValidationResult()
        result.add_warning("Minor issue")
        result.add_error("Critical problem")

        assert result.is_valid is False
        assert len(result.warnings) == 1
        assert len(result.errors) == 1

    def test_bool_true_when_valid(self):
        """Test __bool__ returns True for valid result."""
        result = ValidationResult(is_valid=True)
        assert bool(result) is True
        assert result  # Direct boolean evaluation

    def test_bool_false_when_invalid(self):
        """Test __bool__ returns False for invalid result."""
        result = ValidationResult(is_valid=False)
        assert bool(result) is False
        assert not result  # Direct boolean evaluation

    def test_bool_after_error(self):
        """Test __bool__ after adding error."""
        result = ValidationResult()
        assert bool(result) is True

        result.add_error("Something wrong")
        assert bool(result) is False

    def test_str_valid_no_warnings(self):
        """Test string representation of valid result."""
        result = ValidationResult(is_valid=True)
        str_repr = str(result)

        assert str_repr == "[PASS] Validation passed"

    def test_str_invalid_with_errors(self):
        """Test string representation with errors."""
        result = ValidationResult(is_valid=False)
        result.add_error("Missing tag")
        result.add_error("Invalid value")

        str_repr = str(result)
        assert "[FAIL]" in str_repr
        assert "2 error(s)" in str_repr
        assert "Missing tag" in str_repr
        assert "Invalid value" in str_repr

    def test_str_valid_with_warnings(self):
        """Test string representation with warnings."""
        result = ValidationResult(is_valid=True)
        result.add_warning("Non-standard value")
        result.add_warning("Deprecated tag")

        str_repr = str(result)
        assert "[WARN]" in str_repr
        assert "2 warning(s)" in str_repr
        assert "Non-standard value" in str_repr
        assert "Deprecated tag" in str_repr

    def test_info_dict(self):
        """Test storing additional info in result."""
        result = ValidationResult()
        result.info["tags_checked"] = 42
        result.info["file_size"] = 1024

        assert result.info["tags_checked"] == 42
        assert result.info["file_size"] == 1024


class TestDicomValidatorInitialization:
    """Test DicomValidator initialization and configuration."""

    def test_default_initialization(self):
        """Test creating validator with defaults."""
        validator = DicomValidator()

        assert validator.strict_mode is False
        assert validator.max_file_size == 100 * 1024 * 1024  # 100 MB

    def test_strict_mode_enabled(self):
        """Test creating validator in strict mode."""
        validator = DicomValidator(strict_mode=True)

        assert validator.strict_mode is True

    def test_custom_max_file_size(self):
        """Test creating validator with custom max file size."""
        validator = DicomValidator(max_file_size=50 * 1024 * 1024)

        assert validator.max_file_size == 50 * 1024 * 1024

    def test_both_custom_settings(self):
        """Test creating validator with all custom settings."""
        validator = DicomValidator(strict_mode=True, max_file_size=10 * 1024 * 1024)

        assert validator.strict_mode is True
        assert validator.max_file_size == 10 * 1024 * 1024


@pytest.fixture
def valid_dataset():
    """Create a valid DICOM dataset with all required tags."""
    ds = Dataset()

    # Patient module
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"

    # Study module
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"
    ds.StudyTime = "120000"

    # Series module
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"

    # Image module
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    return ds


@pytest.fixture
def dataset_missing_patient_tags():
    """Create a dataset missing patient tags."""
    ds = Dataset()

    # Study module (complete)
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"

    # Series module (complete)
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"

    # Image module (complete)
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    # Missing: PatientName, PatientID

    return ds


@pytest.fixture
def dataset_with_null_bytes():
    """Create a dataset with null bytes in string value."""
    ds = Dataset()

    # Valid required tags
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    # Add suspicious value with null byte
    ds.PatientComments = "Normal text\x00with null byte"

    return ds


@pytest.fixture
def dataset_with_deeply_nested_sequence():
    """Create a dataset with deeply nested sequence."""
    ds = Dataset()

    # Valid required tags
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    # Create deeply nested sequence (depth > 10)
    current = ds
    for i in range(12):
        seq_ds = Dataset()
        current.ReferencedImageSequence = [seq_ds]
        current = seq_ds

    return ds


@pytest.fixture
def dataset_with_large_private_tag():
    """Create a dataset with large private tag."""
    ds = Dataset()

    # Valid required tags
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    # Add large private tag (> 1 MB)
    private_data = b"X" * (2 * 1024 * 1024)  # 2 MB
    ds.add(DataElement(Tag(0x0009, 0x0010), "LO", "PRIVATE"))
    ds.add(DataElement(Tag(0x0009, 0x1001), "OB", private_data))

    return ds


class TestDicomValidatorValidate:
    """Test DicomValidator.validate() method with real datasets."""

    def test_validate_valid_dataset(self, valid_dataset):
        """Test validating a completely valid dataset."""
        validator = DicomValidator()
        result = validator.validate(valid_dataset)

        assert result.is_valid is True
        assert len(result.errors) == 0
        assert bool(result) is True

    def test_validate_missing_patient_tags_non_strict(
        self, dataset_missing_patient_tags
    ):
        """Test validating dataset missing patient tags in non-strict mode."""
        validator = DicomValidator(strict_mode=False)
        result = validator.validate(dataset_missing_patient_tags)

        # Non-strict mode allows missing tags as warnings
        assert result.is_valid is True
        assert len(result.warnings) > 0

    def test_validate_missing_patient_tags_strict(self, dataset_missing_patient_tags):
        """Test validating dataset missing patient tags in strict mode."""
        validator = DicomValidator(strict_mode=True)
        result = validator.validate(dataset_missing_patient_tags)

        # Strict mode treats missing required tags as errors
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_with_check_required_tags_false(
        self, dataset_missing_patient_tags
    ):
        """Test validating with required tag checking disabled."""
        validator = DicomValidator(strict_mode=True)
        result = validator.validate(
            dataset_missing_patient_tags, check_required_tags=False
        )

        # Should pass because we disabled required tag checking
        assert result.is_valid is True

    def test_validate_null_bytes_detected(self, dataset_with_null_bytes):
        """Test that null bytes in values are detected."""
        validator = DicomValidator()
        result = validator.validate(dataset_with_null_bytes, check_security=True)

        # Null bytes should be flagged as security issue
        assert result.is_valid is False
        assert any("null byte" in err.lower() for err in result.errors)

    def test_validate_null_bytes_ignored(self, dataset_with_null_bytes):
        """Test validating with security checks disabled."""
        validator = DicomValidator()
        result = validator.validate(
            dataset_with_null_bytes, check_security=False, check_required_tags=False
        )

        # Should pass because security checks are disabled
        assert result.is_valid is True

    def test_validate_deeply_nested_sequence(self, dataset_with_deeply_nested_sequence):
        """Test that deeply nested sequences are detected."""
        validator = DicomValidator(strict_mode=True)
        result = validator.validate(
            dataset_with_deeply_nested_sequence, check_security=True
        )

        # Deep nesting should be flagged
        assert result.is_valid is False
        assert any(
            "deeply nested" in err.lower() or "depth" in err.lower()
            for err in result.errors
        )

    def test_validate_large_private_tag(self, dataset_with_large_private_tag):
        """Test that large private tags are detected."""
        validator = DicomValidator(strict_mode=True)
        result = validator.validate(dataset_with_large_private_tag, check_security=True)

        # Large private tag should be flagged
        assert result.is_valid is False
        assert any(
            "private" in err.lower() or "large" in err.lower() for err in result.errors
        )

    def test_validate_empty_dataset(self):
        """Test validating an empty dataset."""
        validator = DicomValidator(strict_mode=True)
        result = validator.validate(Dataset())

        # Empty dataset should fail validation
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_all_checks_disabled(self, dataset_missing_patient_tags):
        """Test validating with all checks disabled."""
        validator = DicomValidator()
        result = validator.validate(
            dataset_missing_patient_tags,
            check_required_tags=False,
            check_values=False,
            check_security=False,
        )

        # With all checks disabled, should pass
        assert result.is_valid is True


@pytest.fixture
def valid_dicom_file(tmp_path):
    """Create a valid DICOM file on disk."""
    file_meta = Dataset()
    file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    file_path = tmp_path / "valid.dcm"
    ds = FileDataset(str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128)

    # Required tags
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID

    ds.save_as(str(file_path), write_like_original=False)

    return file_path


@pytest.fixture
def invalid_dicom_file(tmp_path):
    """Create an invalid DICOM file (not actually DICOM format)."""
    file_path = tmp_path / "invalid.dcm"
    file_path.write_bytes(b"This is not a DICOM file")
    return file_path


@pytest.fixture
def large_dicom_file(tmp_path):
    """Create a DICOM file larger than default max size."""
    file_meta = Dataset()
    file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    file_path = tmp_path / "large.dcm"
    ds = FileDataset(str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128)

    # Required tags
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.StudyDate = "20250119"
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID

    # Add large pixel data to exceed size limit
    # Note: This creates a file larger than 100 MB default limit
    large_data = b"\x00" * (101 * 1024 * 1024)  # 101 MB
    ds.PixelData = large_data

    ds.save_as(str(file_path), write_like_original=False)

    return file_path


class TestDicomValidatorValidateFile:
    """Test DicomValidator.validate_file() method with real files."""

    def test_validate_file_valid(self, valid_dicom_file):
        """Test validating a valid DICOM file."""
        validator = DicomValidator()
        result, dataset = validator.validate_file(str(valid_dicom_file))

        assert result.is_valid is True
        assert len(result.errors) == 0
        assert dataset is not None

    def test_validate_file_with_path_object(self, valid_dicom_file):
        """Test validating with Path object."""
        validator = DicomValidator()
        result, dataset = validator.validate_file(valid_dicom_file)

        assert result.is_valid is True
        assert dataset is not None

    def test_validate_file_nonexistent(self):
        """Test validating a file that doesn't exist."""
        validator = DicomValidator()
        result, dataset = validator.validate_file("/path/to/nonexistent/file.dcm")

        assert result.is_valid is False
        assert any(
            "not found" in err.lower() or "does not exist" in err.lower()
            for err in result.errors
        )
        assert dataset is None

    def test_validate_file_invalid_format(self, invalid_dicom_file):
        """Test validating a file that's not DICOM format."""
        validator = DicomValidator()
        result, dataset = validator.validate_file(str(invalid_dicom_file))

        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_file_too_large(self, large_dicom_file):
        """Test validating a file that exceeds max size."""
        validator = DicomValidator(max_file_size=50 * 1024 * 1024)  # 50 MB limit
        result, dataset = validator.validate_file(str(large_dicom_file))

        # Should fail due to size limit
        assert result.is_valid is False
        assert any(
            "too large" in err.lower() or "size" in err.lower() for err in result.errors
        )

    def test_validate_file_large_allowed(self, large_dicom_file):
        """Test validating large file with higher size limit."""
        validator = DicomValidator(max_file_size=200 * 1024 * 1024)  # 200 MB limit
        result, dataset = validator.validate_file(str(large_dicom_file))

        # Should pass with higher limit
        assert result.is_valid is True


class TestDicomValidatorValidateBatch:
    """Test DicomValidator.validate_batch() method with multiple datasets."""

    def test_validate_batch_all_valid(self, valid_dataset):
        """Test validating a batch of all valid datasets."""
        validator = DicomValidator()

        datasets = [valid_dataset, valid_dataset, valid_dataset]
        results = validator.validate_batch(datasets)

        assert len(results) == 3
        assert all(r.is_valid for r in results)

    def test_validate_batch_mixed(self, valid_dataset, dataset_missing_patient_tags):
        """Test validating a batch with mixed valid/invalid datasets."""
        validator = DicomValidator(strict_mode=True)

        datasets = [valid_dataset, dataset_missing_patient_tags, valid_dataset]
        results = validator.validate_batch(datasets)

        assert len(results) == 3
        assert results[0].is_valid is True
        assert results[1].is_valid is False
        assert results[2].is_valid is True

    def test_validate_batch_empty(self):
        """Test validating an empty batch."""
        validator = DicomValidator()
        results = validator.validate_batch([])

        assert len(results) == 0

    def test_validate_batch_single_dataset(self, valid_dataset):
        """Test validating a batch with single dataset."""
        validator = DicomValidator()
        results = validator.validate_batch([valid_dataset])

        assert len(results) == 1
        assert results[0].is_valid is True

    def test_validate_batch_with_custom_checks(
        self, dataset_with_null_bytes, valid_dataset
    ):
        """Test validating batch - security checks are always applied."""
        validator = DicomValidator()

        datasets = [dataset_with_null_bytes, valid_dataset]
        results = validator.validate_batch(datasets)

        assert len(results) == 2
        assert results[0].is_valid is False  # Has null bytes
        assert results[1].is_valid is True


class TestDicomValidatorSecurityChecks:
    """Test security validation features."""

    def test_security_check_null_bytes(self):
        """Test detection of null bytes in text values."""
        validator = DicomValidator()

        ds = Dataset()
        ds.PatientName = "Normal\x00Suspicious"

        result = validator.validate(ds, check_security=True, check_required_tags=False)
        assert result.is_valid is False

    def test_security_check_multiple_null_bytes(self):
        """Test detection of multiple null bytes."""
        validator = DicomValidator()

        ds = Dataset()
        ds.PatientName = "Test\x00Patient"
        ds.PatientID = "ID\x00123"
        ds.StudyDescription = "Study\x00Description"

        result = validator.validate(ds, check_security=True, check_required_tags=False)
        assert result.is_valid is False
        # Should report multiple instances
        assert len(result.errors) >= 1

    def test_security_check_sequence_depth(self):
        """Test detection of excessively deep sequence nesting."""
        validator = DicomValidator(strict_mode=True)

        ds = Dataset()
        current = ds

        # Create nesting depth of 15 (exceeds typical limit of 10)
        for i in range(15):
            seq_ds = Dataset()
            current.ReferencedImageSequence = [seq_ds]
            current = seq_ds

        result = validator.validate(ds, check_security=True, check_required_tags=False)
        assert result.is_valid is False

    def test_security_check_normal_sequence_depth(self):
        """Test that normal sequence depth is allowed."""
        validator = DicomValidator()

        ds = Dataset()
        current = ds

        # Create reasonable nesting depth of 5
        for i in range(5):
            seq_ds = Dataset()
            current.ReferencedImageSequence = [seq_ds]
            current = seq_ds

        result = validator.validate(ds, check_security=True, check_required_tags=False)
        assert result.is_valid is True

    def test_security_check_private_tag_size(self):
        """Test detection of suspiciously large private tags."""
        validator = DicomValidator(strict_mode=True)

        ds = Dataset()
        # Add private tag with 2 MB of data
        large_data = b"X" * (2 * 1024 * 1024)
        ds.add(DataElement(Tag(0x0009, 0x0010), "LO", "PRIVATE_CREATOR"))
        ds.add(DataElement(Tag(0x0009, 0x1001), "OB", large_data))

        result = validator.validate(ds, check_security=True, check_required_tags=False)
        assert result.is_valid is False

    def test_security_check_reasonable_private_tag(self):
        """Test that reasonable private tags are allowed."""
        validator = DicomValidator()

        ds = Dataset()
        # Add private tag with reasonable data size
        ds.add(DataElement(Tag(0x0009, 0x0010), "LO", "PRIVATE_CREATOR"))
        ds.add(DataElement(Tag(0x0009, 0x1001), "LO", "Reasonable private data"))

        result = validator.validate(ds, check_security=True, check_required_tags=False)
        assert result.is_valid is True


class TestDicomValidatorRequiredTags:
    """Test required tag validation."""

    def test_all_required_tags_present(self, valid_dataset):
        """Test dataset with all required tags."""
        validator = DicomValidator(strict_mode=True)
        result = validator.validate(valid_dataset)

        assert result.is_valid is True

    def test_missing_patient_tags(self):
        """Test detection of missing patient tags."""
        validator = DicomValidator(strict_mode=True)

        ds = Dataset()
        # Missing PatientName and PatientID
        ds.StudyInstanceUID = generate_uid()
        ds.StudyDate = "20250119"
        ds.SeriesInstanceUID = generate_uid()
        ds.Modality = "CT"
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

        result = validator.validate(ds)
        assert result.is_valid is False

    def test_missing_study_tags(self):
        """Test detection of missing study tags."""
        validator = DicomValidator(strict_mode=True)

        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        # Missing StudyInstanceUID and StudyDate
        ds.SeriesInstanceUID = generate_uid()
        ds.Modality = "CT"
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

        result = validator.validate(ds)
        assert result.is_valid is False

    def test_missing_series_tags(self):
        """Test detection of missing series tags."""
        validator = DicomValidator(strict_mode=True)

        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = generate_uid()
        ds.StudyDate = "20250119"
        # Missing SeriesInstanceUID and Modality
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

        result = validator.validate(ds)
        assert result.is_valid is False

    def test_missing_image_tags(self):
        """Test detection of missing image tags."""
        validator = DicomValidator(strict_mode=True)

        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = generate_uid()
        ds.StudyDate = "20250119"
        ds.SeriesInstanceUID = generate_uid()
        ds.Modality = "CT"
        # Missing SOPInstanceUID and SOPClassUID

        result = validator.validate(ds)
        assert result.is_valid is False


class TestValidatorFileOperations:
    """Test file validation operations (from additional tests)."""

    def test_validate_file_empty_file(self, tmp_path):
        """Test validation of empty file."""
        test_file = tmp_path / "empty.dcm"
        test_file.write_bytes(b"")

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        assert result.is_valid is False
        assert dataset is None
        assert any("empty" in error.lower() for error in result.errors)

    def test_validate_extremely_long_tag_value(self, tmp_path):
        """Test detection of extremely long tag values (potential attack)."""
        import pydicom
        from pydicom.dataset import FileMetaDataset

        test_file = tmp_path / "long_value.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "A" * 15000  # Very long value
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        # Should warn about extremely long value
        assert len(result.warnings) > 0
        assert any("extremely long" in warning.lower() for warning in result.warnings)


class TestDicomValidatorEdgeCases:
    """Test edge cases and error handling."""

    def test_validate_none_dataset(self):
        """Test validating None instead of dataset."""
        validator = DicomValidator()

        # Validator handles None gracefully by returning invalid result
        result = validator.validate(None)
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_file_empty_path(self):
        """Test validating with empty file path."""
        validator = DicomValidator()
        result, dataset = validator.validate_file("")

        assert result.is_valid is False
        assert len(result.errors) > 0
        assert dataset is None

    def test_validate_batch_with_none(self, valid_dataset):
        """Test batch validation with None in list."""
        validator = DicomValidator()

        # Validator handles None gracefully
        datasets = [valid_dataset, None, valid_dataset]
        results = validator.validate_batch(datasets)

        assert len(results) == 3
        assert results[0].is_valid is True
        assert results[1].is_valid is False  # None dataset invalid
        assert results[2].is_valid is True

    def test_strict_mode_vs_non_strict(self):
        """Test difference between strict and non-strict mode."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        # Missing other required tags

        strict_validator = DicomValidator(strict_mode=True)
        non_strict_validator = DicomValidator(strict_mode=False)

        strict_result = strict_validator.validate(ds)
        non_strict_result = non_strict_validator.validate(ds)

        # Strict mode should be more restrictive
        assert strict_result.is_valid is False
        # Non-strict mode may pass or have warnings instead of errors
        if not non_strict_result.is_valid:
            # If non-strict also fails, it should have fewer errors
            assert len(non_strict_result.errors) <= len(strict_result.errors)
