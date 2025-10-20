"""
Additional tests for DicomValidator to improve code coverage.

These tests target specific uncovered code paths in validator.py
to increase overall test coverage.
"""

import pytest
from pathlib import Path
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
import pydicom

from dicom_fuzzer.core.validator import DicomValidator, ValidationResult


class TestValidatorSecurityChecks:
    """Test security-focused validation paths."""

    def test_validate_with_null_bytes_in_string(self, tmp_path):
        """Test detection of null bytes in tag values (potential attack)."""
        test_file = tmp_path / "null_bytes.dcm"

        # Create DICOM file with null bytes in a tag value
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test\x00Patient"  # Null byte in middle
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        # Should detect null bytes
        assert result.is_valid is False
        assert any("null bytes" in error.lower() for error in result.errors)

    def test_validate_extremely_long_tag_value(self, tmp_path):
        """Test detection of extremely long tag values (potential attack)."""
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

    def test_validate_large_number_of_elements(self, tmp_path):
        """Test detection of suspiciously large number of elements."""
        test_file = tmp_path / "many_elements.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Add many private tags (odd group numbers indicate private tags)
        for i in range(150):
            tag = Tag(0x0009 + (i * 2), 0x0010)  # Private tags
            ds.add_new(tag, 'LO', f'PrivateValue{i}')

        pydicom.dcmwrite(str(test_file), ds)

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        # Should warn about many private tags
        assert len(result.warnings) > 0
        assert any("private tag" in warning.lower() for warning in result.warnings)

    def test_validate_deeply_nested_sequences(self, tmp_path):
        """Test detection of deeply nested sequences."""
        test_file = tmp_path / "nested.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Create deeply nested sequence (depth = 12, just above threshold of 10)
        # Build from innermost to outermost to avoid self-reference issues
        innermost = Dataset()
        innermost.PatientName = "Test"

        current_seq = innermost
        for i in range(12):
            wrapper = Dataset()
            wrapper.add_new(Tag(0x0040, 0x0260), 'SQ', [current_seq])
            current_seq = wrapper

        ds.add_new(Tag(0x0040, 0x0260), 'SQ', [current_seq])

        pydicom.dcmwrite(str(test_file), ds)

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        # Should warn about deep nesting
        assert len(result.warnings) > 0
        assert any("nested" in warning.lower() or "depth" in warning.lower() for warning in result.warnings)

    def test_validate_large_private_tag_data(self):
        """Test detection of large private tag data via validate()."""
        # Create dataset directly (no file needed)
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Add large private tag data (> 1MB)
        large_data = b'\x00' * (2 * 1024 * 1024)  # 2MB
        ds.add_new(Tag(0x0009, 0x0010), 'OB', large_data)

        validator = DicomValidator()
        result = validator.validate(ds, check_security=True)

        # Should warn about large private data (>1MB)
        assert len(result.warnings) > 0
        warnings_text = ' '.join(result.warnings).lower()
        # The validator checks for private tags with data > 1MB
        assert "private" in warnings_text and "large" in warnings_text


class TestValidatorFileOperations:
    """Test file validation operations."""

    def test_validate_file_empty_file(self, tmp_path):
        """Test validation of empty file."""
        test_file = tmp_path / "empty.dcm"
        test_file.write_bytes(b'')

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file)

        assert result.is_valid is False
        assert dataset is None
        assert any("empty" in error.lower() for error in result.errors)

    def test_validate_file_without_parsing(self, tmp_path):
        """Test validation without parsing dataset."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        validator = DicomValidator()
        result, dataset = validator.validate_file(test_file, parse_dataset=False)

        # Should not parse dataset
        assert result.is_valid is True
        assert dataset is None


class TestValidatorBatchOperations:
    """Test batch validation operations."""

    def test_validate_batch_basic(self):
        """Test batch validation of multiple datasets."""
        datasets = []
        for i in range(3):
            ds = Dataset()
            ds.PatientName = f"Patient{i}"
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ds.SOPInstanceUID = f"1.2.3.{i}"
            datasets.append(ds)

        validator = DicomValidator()
        results = validator.validate_batch(datasets)

        assert len(results) == 3
        assert all(isinstance(r, ValidationResult) for r in results)

    def test_validate_batch_stop_on_error(self):
        """Test batch validation with stop_on_first_error."""
        datasets = []
        # First dataset is empty (will fail)
        datasets.append(Dataset())
        # Second dataset is valid
        ds = Dataset()
        ds.PatientName = "Patient"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"
        datasets.append(ds)

        validator = DicomValidator(strict_mode=True)
        results = validator.validate_batch(datasets, stop_on_first_error=True)

        # Should stop after first error
        assert len(results) == 1
        assert results[0].is_valid is False

    def test_validate_batch_continue_on_error(self):
        """Test batch validation continuing after errors."""
        datasets = []
        # First dataset is empty (will fail)
        datasets.append(Dataset())
        # Second dataset is valid
        ds = Dataset()
        ds.PatientName = "Patient"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"
        datasets.append(ds)

        validator = DicomValidator()
        results = validator.validate_batch(datasets, stop_on_first_error=False)

        # Should process all datasets
        assert len(results) == 2
        assert results[0].is_valid is False
        assert results[1].is_valid is True


class TestValidatorRequiredTags:
    """Test required tag validation."""

    def test_validate_missing_patient_tags_strict_mode(self):
        """Test missing patient tags in strict mode."""
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"
        # Missing PatientName and PatientID

        validator = DicomValidator(strict_mode=True)
        result = validator.validate(ds)

        # Strict mode should error on missing required tags
        assert result.is_valid is False
        assert any("Patient" in error for error in result.errors)

    def test_validate_missing_tags_non_strict_mode(self):
        """Test missing tags in non-strict mode."""
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"
        # Missing many required tags

        validator = DicomValidator(strict_mode=False)
        result = validator.validate(ds)

        # Non-strict mode should warn, not error
        assert len(result.warnings) > 0
        # Should still be valid overall in non-strict mode
        assert result.is_valid is True

    def test_validate_all_required_tags_present(self):
        """Test validation with all required tags present."""
        ds = Dataset()
        # Patient tags
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        # Study tags
        ds.StudyInstanceUID = "1.2.3.4"
        ds.StudyDate = "20250101"
        # Series tags
        ds.SeriesInstanceUID = "1.2.3.4.5"
        ds.Modality = "CT"
        # Image tags
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.5.6"

        validator = DicomValidator(strict_mode=True)
        result = validator.validate(ds)

        # Should pass with minimal or no warnings
        assert result.is_valid is True


class TestValidationResultMethods:
    """Test ValidationResult helper methods."""

    def test_validation_result_string_with_warnings_only(self):
        """Test string representation with warnings but no errors."""
        result = ValidationResult(is_valid=True)
        result.add_warning("Test warning 1")
        result.add_warning("Test warning 2")

        result_str = str(result)
        assert "[WARN]" in result_str
        assert "2 warning(s)" in result_str
        assert "Test warning 1" in result_str

    def test_validation_result_with_context(self):
        """Test adding errors and warnings with context."""
        result = ValidationResult()
        result.add_error("Test error", context={"tag": "0010,0010", "value": "test"})
        result.add_warning("Test warning", context={"count": 5})

        assert "Test error" in result.info
        assert result.info["Test error"]["tag"] == "0010,0010"
        assert "Test warning" in result.info
        assert result.info["Test warning"]["count"] == 5
