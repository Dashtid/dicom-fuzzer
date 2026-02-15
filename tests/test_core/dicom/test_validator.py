"""
Comprehensive tests for DICOM Validator.

Tests cover:
- ValidationResult class functionality
- DicomValidator initialization
- Structure validation
- Required tags validation
- Tag value validation
- Security validation
- File validation
- Batch validation
- Strict vs non-strict modes
- Edge cases
"""

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag

from dicom_fuzzer.core.dicom.validator import DicomValidator, ValidationResult


class TestValidationResult:
    """Test ValidationResult class functionality."""

    def test_initialization_defaults_to_valid(self):
        """Test that ValidationResult is valid by default."""
        result = ValidationResult()

        assert result.is_valid is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert len(result.info) == 0

    def test_initialization_with_invalid(self):
        """Test creating an invalid result."""
        result = ValidationResult(is_valid=False)

        assert result.is_valid is False
        assert len(result.errors) == 0

    def test_add_error_marks_invalid(self):
        """Test that adding error marks result as invalid."""
        result = ValidationResult()
        assert result.is_valid is True

        result.add_error("Test error")

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "Test error" in result.errors

    def test_add_error_with_context(self):
        """Test adding error with context information."""
        result = ValidationResult()
        context = {"tag": "0010,0010", "value": "invalid"}

        result.add_error("Invalid tag value", context=context)

        assert result.is_valid is False
        assert "Invalid tag value" in result.errors
        assert result.info["Invalid tag value"] == context

    def test_add_warning_does_not_mark_invalid(self):
        """Test that adding warning doesn't mark result as invalid."""
        result = ValidationResult()

        result.add_warning("Test warning")

        assert result.is_valid is True
        assert len(result.warnings) == 1
        assert "Test warning" in result.warnings

    def test_add_warning_with_context(self):
        """Test adding warning with context information."""
        result = ValidationResult()
        context = {"count": 150}

        result.add_warning("Many private tags", context=context)

        assert result.is_valid is True
        assert "Many private tags" in result.warnings
        assert result.info["Many private tags"] == context

    def test_multiple_errors_and_warnings(self):
        """Test adding multiple errors and warnings."""
        result = ValidationResult()

        result.add_error("Error 1")
        result.add_error("Error 2")
        result.add_warning("Warning 1")
        result.add_warning("Warning 2")

        assert result.is_valid is False
        assert len(result.errors) == 2
        assert len(result.warnings) == 2

    def test_bool_conversion_for_valid_result(self):
        """Test using ValidationResult in boolean context (valid)."""
        result = ValidationResult()

        assert bool(result) is True
        assert result  # Direct boolean evaluation

    def test_bool_conversion_for_invalid_result(self):
        """Test using ValidationResult in boolean context (invalid)."""
        result = ValidationResult()
        result.add_error("Test error")

        assert bool(result) is False
        assert not result  # Direct boolean evaluation

    def test_str_representation_valid(self):
        """Test string representation for valid result."""
        result = ValidationResult()

        output = str(result)

        assert "[PASS]" in output
        assert "Validation passed" in output

    def test_str_representation_with_errors(self):
        """Test string representation with errors."""
        result = ValidationResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        output = str(result)

        assert "[FAIL]" in output
        assert "2 error(s)" in output
        assert "Error 1" in output
        assert "Error 2" in output

    def test_str_representation_with_warnings(self):
        """Test string representation with warnings."""
        result = ValidationResult()
        result.add_warning("Warning 1")

        output = str(result)

        assert "[WARN]" in output
        assert "1 warning(s)" in output
        assert "Warning 1" in output

    def test_str_representation_with_errors_and_warnings(self):
        """Test string representation with both errors and warnings."""
        result = ValidationResult()
        result.add_error("Error 1")
        result.add_warning("Warning 1")

        output = str(result)

        assert "[FAIL]" in output
        assert "[WARN]" in output
        assert "Error 1" in output
        assert "Warning 1" in output


class TestDicomValidatorInit:
    """Test DicomValidator initialization."""

    def test_default_initialization(self):
        """Test validator with default parameters."""
        validator = DicomValidator()

        assert validator.strict_mode is False
        assert validator.max_file_size == 100 * 1024 * 1024  # 100MB

    def test_initialization_strict_mode(self):
        """Test validator with strict mode enabled."""
        validator = DicomValidator(strict_mode=True)

        assert validator.strict_mode is True

    def test_initialization_custom_file_size(self):
        """Test validator with custom max file size."""
        custom_size = 50 * 1024 * 1024  # 50MB
        validator = DicomValidator(max_file_size=custom_size)

        assert validator.max_file_size == custom_size

    def test_initialization_all_parameters(self):
        """Test validator with all parameters specified."""
        validator = DicomValidator(strict_mode=True, max_file_size=10 * 1024 * 1024)

        assert validator.strict_mode is True
        assert validator.max_file_size == 10 * 1024 * 1024


class TestStructureValidation:
    """Test basic DICOM structure validation."""

    def test_validate_none_dataset(self):
        """Test validation with None dataset."""
        validator = DicomValidator()

        result = validator.validate(None)

        assert result.is_valid is False
        assert "Dataset is None" in result.errors

    def test_validate_empty_dataset(self):
        """Test validation with empty dataset."""
        validator = DicomValidator()
        dataset = Dataset()

        result = validator.validate(dataset)

        assert result.is_valid is False
        assert "Dataset is empty" in result.errors

    def test_validate_minimal_valid_dataset(self, sample_dicom_file):
        """Test validation with minimal valid dataset."""
        from dicom_fuzzer.core.dicom.parser import DicomParser

        validator = DicomValidator(strict_mode=False)
        parser = DicomParser(sample_dicom_file)

        result = validator.validate(parser.dataset)

        # Should pass structure validation at minimum
        assert "Dataset is None" not in result.errors
        assert "Dataset is empty" not in result.errors

    def test_validate_dataset_without_file_meta(self):
        """Test validation with dataset missing file meta."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        result = validator.validate(dataset)

        # Should have warning about missing file meta
        assert any("file meta" in w.lower() for w in result.warnings)


class TestRequiredTagsValidation:
    """Test required DICOM tags validation."""

    def test_validate_with_all_required_tags(self, sample_dicom_file):
        """Test validation with all required tags present."""
        from dicom_fuzzer.core.dicom.parser import DicomParser

        validator = DicomValidator(strict_mode=False)
        parser = DicomParser(sample_dicom_file)

        result = validator.validate(parser.dataset, check_required_tags=True)

        # Minimal DICOM should have basic tags
        # Some tags might be missing but should not cause failure in non-strict
        if not result.is_valid:
            # If invalid, it should not be due to required tags in non-strict
            assert not any("missing" in e.lower() for e in result.errors)

    def test_validate_missing_patient_tags_non_strict(self):
        """Test missing patient tags in non-strict mode."""
        validator = DicomValidator(strict_mode=False)
        dataset = Dataset()
        dataset.StudyInstanceUID = "1.2.3.4.5"
        dataset.StudyDate = "20250930"
        dataset.SeriesInstanceUID = "1.2.3.4.5.6"
        dataset.Modality = "CT"

        result = validator.validate(dataset, check_required_tags=True)

        # Should have warnings, not errors
        assert result.is_valid is True
        assert any("Patient" in w for w in result.warnings)

    def test_validate_missing_patient_tags_strict(self):
        """Test missing patient tags in strict mode."""
        validator = DicomValidator(strict_mode=True)
        dataset = Dataset()
        dataset.StudyInstanceUID = "1.2.3.4.5"
        dataset.StudyDate = "20250930"

        result = validator.validate(dataset, check_required_tags=True)

        # Should have errors in strict mode
        assert result.is_valid is False
        assert any("Patient" in e for e in result.errors)

    def test_validate_skip_required_tags_check(self):
        """Test validation with required tags check disabled."""
        validator = DicomValidator(strict_mode=True)
        dataset = Dataset()
        dataset.StudyDate = "20250930"

        result = validator.validate(dataset, check_required_tags=False)

        # Should not check for required tags
        assert not any("missing" in e.lower() for e in result.errors)
        assert not any("missing" in w.lower() for w in result.warnings)


class TestTagValuesValidation:
    """Test DICOM tag values validation."""

    def test_validate_normal_tag_values(self):
        """Test validation with normal tag values."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "Doe^John"
        dataset.PatientID = "PAT001"

        result = validator.validate(dataset, check_values=True)

        # Normal values should not trigger warnings
        assert not any("long value" in w.lower() for w in result.warnings)

    def test_validate_extremely_long_string_value(self):
        """Test validation with extremely long string (potential DoS)."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "A" * 15000  # > 10KB

        result = validator.validate(dataset, check_values=True)

        # Should have warning about long value
        assert any(
            "long value" in w.lower() or "long" in w.lower() for w in result.warnings
        )

    def test_validate_null_byte_in_string(self):
        """Test validation with null byte in string (potential attack)."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "Test\x00Patient"  # Null byte in middle

        result = validator.validate(dataset, check_values=True)

        # Should have error about null bytes
        assert result.is_valid is False
        assert any("null" in e.lower() for e in result.errors)

    def test_validate_empty_tag_values(self):
        """Test validation with empty tag values (line 327)."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = ""  # Empty string
        dataset.PatientID = None  # None value

        result = validator.validate(dataset, check_values=True)

        # Should handle empty values gracefully (skip them)
        # No warnings or errors about the empty values themselves
        assert result is not None

    def test_validate_trailing_null_allowed(self):
        """Test that trailing null byte is allowed (DICOM padding)."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "TestPatient\x00"  # Trailing null is OK

        result = validator.validate(dataset, check_values=True)

        # Should not have error about null bytes
        assert not any("null" in e.lower() for e in result.errors)

    def test_validate_skip_values_check(self):
        """Test validation with value check disabled."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "A" * 15000  # Long value
        dataset.PatientID = "Test\x00ID"  # Null byte

        result = validator.validate(dataset, check_values=False, check_security=False)

        # Should not check values or security
        assert not any("long" in e.lower() for e in result.errors)
        assert not any("null" in e.lower() for e in result.errors)


class TestSecurityValidation:
    """Test security-focused validation."""

    def test_validate_normal_element_count(self):
        """Test validation with normal number of elements."""
        validator = DicomValidator()
        dataset = Dataset()
        for i in range(50):
            dataset.add_new(Tag(0x0010, i), "LO", f"Value{i}")

        result = validator.validate(dataset, check_security=True)

        # Normal count should not trigger warnings
        assert not any("large number" in w.lower() for w in result.warnings)

    def test_validate_suspicious_element_count(self):
        """Test validation with suspiciously large element count."""
        validator = DicomValidator()
        dataset = Dataset()
        for i in range(10001):  # > 10000
            dataset.add_new(Tag(0x0010, i % 65536), "LO", f"Value{i}")

        result = validator.validate(dataset, check_security=True)

        # Should have warning about element count
        assert any(
            "large number" in w.lower() or "elements" in w.lower()
            for w in result.warnings
        )

    def test_validate_deeply_nested_sequences(self):
        """Test validation with deeply nested sequences."""
        validator = DicomValidator()
        dataset = Dataset()

        # Create deeply nested sequence (> 10 levels)
        current = dataset
        for i in range(12):
            seq = Sequence()
            inner_dataset = Dataset()
            seq.append(inner_dataset)
            current.add_new(Tag(0x0040, 0x0260 + i), "SQ", seq)
            current = inner_dataset

        result = validator.validate(dataset, check_security=True)

        # Should have warning about depth
        assert any(
            "nested" in w.lower() or "depth" in w.lower() for w in result.warnings
        )

    def test_validate_normal_private_tags(self):
        """Test validation with normal private tags."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.add_new(Tag(0x0009, 0x0010), "LO", "Private Creator")
        dataset.add_new(Tag(0x0009, 0x1001), "LO", "Private Data")

        result = validator.validate(dataset, check_security=True)

        # Normal private tags should not trigger warnings
        assert not any("private" in w.lower() for w in result.warnings)

    def test_validate_excessive_private_tags(self):
        """Test validation with excessive private tags."""
        validator = DicomValidator()
        dataset = Dataset()

        # Add > 100 private tags
        for i in range(150):
            dataset.add_new(Tag(0x0009, 0x1000 + i), "LO", f"Private{i}")

        result = validator.validate(dataset, check_security=True)

        # Should have warning about many private tags
        assert any("private" in w.lower() for w in result.warnings)

    def test_validate_large_private_tag_data(self):
        """Test validation with large private tag data."""
        validator = DicomValidator()
        dataset = Dataset()
        large_data = b"X" * (2 * 1024 * 1024)  # 2MB
        dataset.add_new(Tag(0x0009, 0x1001), "OB", large_data)

        result = validator.validate(dataset, check_security=True)

        # Should have warning about large private data
        assert any(
            "large data" in w.lower() or "private" in w.lower() for w in result.warnings
        )

    def test_validate_skip_security_check(self):
        """Test validation with security check disabled."""
        validator = DicomValidator()
        dataset = Dataset()
        for i in range(10001):  # > 10000 elements
            dataset.add_new(Tag(0x0010, i % 65536), "LO", f"Value{i}")

        result = validator.validate(dataset, check_security=False)

        # Should not check security
        assert not any("element" in w.lower() for w in result.warnings)


class TestFileValidation:
    """Test file-based validation."""

    def test_validate_nonexistent_file(self, temp_dir):
        """Test validation with nonexistent file."""
        validator = DicomValidator()
        nonexistent = temp_dir / "does_not_exist.dcm"

        result, dataset = validator.validate_file(nonexistent)

        assert result.is_valid is False
        assert any("does not exist" in e.lower() for e in result.errors)
        assert dataset is None

    def test_validate_empty_file(self, temp_dir):
        """Test validation with empty file."""
        validator = DicomValidator()
        empty_file = temp_dir / "empty.dcm"
        empty_file.touch()

        result, dataset = validator.validate_file(empty_file)

        assert result.is_valid is False
        assert any("empty" in e.lower() for e in result.errors)
        assert dataset is None

    def test_validate_oversized_file(self, temp_dir):
        """Test validation with file exceeding max size."""
        validator = DicomValidator(max_file_size=1024)  # 1KB limit
        large_file = temp_dir / "large.dcm"
        large_file.write_bytes(b"X" * 2048)  # 2KB

        result, dataset = validator.validate_file(large_file)

        assert result.is_valid is False
        assert any("exceeds" in e.lower() for e in result.errors)
        assert dataset is None

    def test_validate_invalid_dicom_file(self, temp_dir):
        """Test validation with invalid DICOM file."""
        validator = DicomValidator(strict_mode=True)
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"Not a DICOM file")

        result, dataset = validator.validate_file(invalid_file)

        # pydicom with force=True is very forgiving and might parse it
        # But validation should still fail due to missing required tags
        # or parse failure
        assert result.is_valid is False
        has_error = len(result.errors) > 0
        has_parse_or_structure_error = any(
            "parse" in e.lower() or "failed" in e.lower() or "missing" in e.lower()
            for e in result.errors
        )
        assert has_error
        assert has_parse_or_structure_error

    def test_validate_file_parse_exception(self, temp_dir):
        """Test file validation with parse exception (lines 257-261)."""
        from unittest.mock import patch

        validator = DicomValidator()
        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"dummy")

        # Mock dcmread to raise an exception
        with patch("pydicom.dcmread") as mock_dcmread:
            mock_dcmread.side_effect = Exception("Parse error")

            result, dataset = validator.validate_file(test_file, parse_dataset=True)

            # Should catch exception and return error
            assert result.is_valid is False
            assert any("Failed to parse DICOM file" in e for e in result.errors)
            assert dataset is None

    def test_validate_valid_dicom_file(self, sample_dicom_file):
        """Test validation with valid DICOM file."""
        validator = DicomValidator(strict_mode=False)

        result, dataset = validator.validate_file(sample_dicom_file)

        # Should parse successfully
        assert dataset is not None

    def test_validate_file_without_parsing(self, sample_dicom_file):
        """Test file validation without parsing dataset."""
        validator = DicomValidator()

        result, dataset = validator.validate_file(
            sample_dicom_file, parse_dataset=False
        )

        # Should check file existence and size only
        assert result.is_valid is True
        assert dataset is None


class TestBatchValidation:
    """Test batch validation functionality."""

    def test_validate_batch_empty_list(self):
        """Test batch validation with empty list."""
        validator = DicomValidator()

        results = validator.validate_batch([])

        assert len(results) == 0

    def test_validate_batch_single_dataset(self):
        """Test batch validation with single dataset."""
        validator = DicomValidator()
        dataset = Dataset()
        dataset.PatientName = "Test"

        results = validator.validate_batch([dataset])

        assert len(results) == 1
        assert isinstance(results[0], ValidationResult)

    def test_validate_batch_multiple_datasets(self, sample_dicom_file):
        """Test batch validation with multiple datasets."""
        from dicom_fuzzer.core.dicom.parser import DicomParser

        validator = DicomValidator(strict_mode=False)
        parser = DicomParser(sample_dicom_file)
        datasets = [parser.dataset.copy() for _ in range(5)]

        results = validator.validate_batch(datasets)

        assert len(results) == 5
        assert all(isinstance(r, ValidationResult) for r in results)

    def test_validate_batch_mixed_validity(self):
        """Test batch validation with mix of valid and invalid datasets."""
        validator = DicomValidator()
        datasets = [
            Dataset(),  # Empty - invalid
            None,  # None - invalid
        ]
        valid_ds = Dataset()
        valid_ds.PatientName = "Test"
        datasets.append(valid_ds)

        results = validator.validate_batch(datasets)

        assert len(results) == 3
        assert results[0].is_valid is False  # Empty
        assert results[1].is_valid is False  # None

    def test_validate_batch_stop_on_first_error(self):
        """Test batch validation with stop on first error."""
        validator = DicomValidator()
        datasets = [
            Dataset(),  # Empty - invalid (should stop here)
            None,  # Should not reach this
        ]

        results = validator.validate_batch(datasets, stop_on_first_error=True)

        # Should stop after first error
        assert len(results) == 1
        assert results[0].is_valid is False

    def test_validate_batch_continue_on_errors(self):
        """Test batch validation continuing through errors."""
        validator = DicomValidator()
        datasets = [
            Dataset(),  # Empty - invalid
            None,  # None - invalid
        ]

        results = validator.validate_batch(datasets, stop_on_first_error=False)

        # Should process all datasets
        assert len(results) == 2
        assert all(not r.is_valid for r in results)


class TestStrictMode:
    """Test strict vs non-strict mode differences."""

    def test_missing_tags_strict_mode(self):
        """Test that missing required tags cause errors in strict mode."""
        validator = DicomValidator(strict_mode=True)
        dataset = Dataset()
        dataset.PatientName = "Test"  # Missing Patient ID

        result = validator.validate(dataset)

        # Should have errors
        assert result.is_valid is False
        assert any("missing" in e.lower() for e in result.errors)

    def test_missing_tags_non_strict_mode(self):
        """Test that missing required tags cause warnings in non-strict mode."""
        validator = DicomValidator(strict_mode=False)
        dataset = Dataset()
        dataset.PatientName = "Test"  # Missing Patient ID

        result = validator.validate(dataset)

        # Should have warnings, not errors
        assert any("missing" in w.lower() for w in result.warnings)


class TestPropertyBasedTesting:
    """Property-based tests for robustness."""

    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(max_size=st.integers(min_value=1024, max_value=100 * 1024 * 1024))
    def test_max_file_size_configuration(self, max_size):
        """Property test: max_file_size is correctly configured."""
        validator = DicomValidator(max_file_size=max_size)

        assert validator.max_file_size == max_size

    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(strict=st.booleans())
    def test_strict_mode_configuration(self, strict):
        """Property test: strict_mode is correctly configured."""
        validator = DicomValidator(strict_mode=strict)

        assert validator.strict_mode == strict


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_validation_workflow(self, sample_dicom_file):
        """Test complete validation workflow from file to result."""
        # Create validator
        validator = DicomValidator(strict_mode=False)

        # Validate file
        file_result, dataset = validator.validate_file(sample_dicom_file)

        # Should successfully parse
        assert dataset is not None

        # Validate dataset directly
        dataset_result = validator.validate(dataset)

        # Both should produce similar results
        assert isinstance(dataset_result, ValidationResult)

    def test_validator_with_mutated_dataset(self, sample_dicom_file):
        """Test validator with mutated DICOM dataset."""
        from dicom_fuzzer.core.engine.generator import DICOMGenerator

        validator = DicomValidator(strict_mode=False)

        # Generate mutated file
        output_dir = Path(sample_dicom_file).parent / "validator_test_output"
        generator = DICOMGenerator(output_dir=str(output_dir), skip_write_errors=True)
        mutated_files = generator.generate_batch(
            sample_dicom_file,
            count=25,
            strategies=["metadata", "pixel", "reference"],
        )

        assert len(mutated_files) >= 1, (
            "Expected at least 1 mutated file from 25 attempts"
        )

        # Validate each mutated file
        for mutated_file in mutated_files:
            result, dataset = validator.validate_file(mutated_file)

            # Should be parseable (may have warnings)
            assert dataset is not None

        # Cleanup
        import shutil

        shutil.rmtree(output_dir)

    def test_batch_validation_workflow(self, sample_dicom_file):
        """Test batch validation with multiple datasets."""
        from dicom_fuzzer.core.dicom.parser import DicomParser

        validator = DicomValidator(strict_mode=False)
        parser = DicomParser(sample_dicom_file)

        # Create multiple datasets
        datasets = [parser.dataset.copy() for _ in range(10)]

        # Validate batch
        results = validator.validate_batch(datasets)

        # All should be valid or have only warnings
        assert len(results) == 10

    def test_validator_integration_with_security_logger(
        self, sample_dicom_file, tmp_path
    ):
        """Test validator integration with security logging."""
        from dicom_fuzzer.utils.logger import configure_logging

        # Configure logging
        log_file = tmp_path / "validator_test.log"
        configure_logging(json_format=True, log_file=log_file)

        validator = DicomValidator(strict_mode=True)

        # Validate invalid dataset
        invalid_dataset = Dataset()
        result = validator.validate(invalid_dataset)

        # Should log security event
        assert result.is_valid is False
        assert log_file.exists()

        # Check log contains validation failure
        log_content = log_file.read_text()
        assert "validation" in log_content.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
