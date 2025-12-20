"""Coverage-focused tests for ConfigValidator.

These tests execute actual code paths without excessive mocking to improve coverage.
"""

import sys
import tempfile
import warnings
from pathlib import Path

import numpy as np
import pytest
from pydicom.dataset import FileDataset, FileMetaDataset
from pydicom.uid import CTImageStorage, ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.core.config_validator import ConfigValidator, ValidationResult


def create_test_dicom(output_path: Path) -> Path:
    """Create a minimal valid DICOM file for testing."""
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = CTImageStorage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = FileDataset(str(output_path), {}, file_meta=file_meta, preamble=b"\0" * 128)
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST001"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.Modality = "CT"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = np.zeros((64, 64), dtype=np.uint16).tobytes()

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        ds.save_as(output_path)

    return output_path


class TestValidationResultCoverage:
    """Test ValidationResult class coverage."""

    def test_validation_result_passed_true(self):
        """Test ValidationResult with passed=True."""
        result = ValidationResult(passed=True, message="Success")
        assert result.passed is True
        assert result.message == "Success"
        assert result.severity == "error"  # Default
        assert bool(result) is True

    def test_validation_result_passed_false(self):
        """Test ValidationResult with passed=False."""
        result = ValidationResult(passed=False, message="Failed", severity="warning")
        assert result.passed is False
        assert result.message == "Failed"
        assert result.severity == "warning"
        assert bool(result) is False

    def test_validation_result_info_severity(self):
        """Test ValidationResult with info severity."""
        result = ValidationResult(passed=True, message="Info", severity="info")
        assert result.severity == "info"


class TestConfigValidatorRealExecution:
    """Test ConfigValidator with real file operations."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def validator(self):
        """Create ConfigValidator instance."""
        return ConfigValidator(strict=False)

    def test_python_version_check_current(self, validator):
        """Test Python version check with current interpreter."""
        # This runs the actual check - we're running on Python 3.11+
        validator._check_python_version()

        # Should add info (not error) since we're on a supported version
        assert len(validator.info) > 0
        assert any("Python version" in info.message for info in validator.info)

    def test_dependencies_check_real(self, validator):
        """Test dependency check with real installed packages."""
        # This runs the actual check - pydicom and pytest should be installed
        validator._check_dependencies()

        # pydicom and pytest should be found (no errors for required)
        # We may or may not have tqdm/psutil warnings
        required_error = [
            e
            for e in validator.errors
            if "pydicom" in e.message or "pytest" in e.message
        ]
        assert len(required_error) == 0  # Required deps are installed

    def test_validate_input_file_real_dicom(self, temp_dir, validator):
        """Test input file validation with real DICOM file."""
        dicom_file = temp_dir / "test.dcm"
        create_test_dicom(dicom_file)

        validator._validate_input_file(dicom_file)

        # Should add info (validated successfully)
        assert any("validated" in info.message.lower() for info in validator.info)
        assert len(validator.errors) == 0

    def test_validate_input_file_nonexistent(self, temp_dir, validator):
        """Test input file validation with nonexistent file."""
        nonexistent = temp_dir / "nonexistent.dcm"

        validator._validate_input_file(nonexistent)

        assert len(validator.errors) > 0
        assert "not found" in validator.errors[0].message.lower()

    def test_validate_input_file_directory(self, temp_dir, validator):
        """Test input file validation with directory instead of file."""
        directory = temp_dir / "subdir"
        directory.mkdir()

        validator._validate_input_file(directory)

        assert len(validator.errors) > 0
        assert "not a file" in validator.errors[0].message.lower()

    def test_validate_input_file_empty(self, temp_dir, validator):
        """Test input file validation with empty file."""
        empty_file = temp_dir / "empty.dcm"
        empty_file.touch()

        validator._validate_input_file(empty_file)

        assert len(validator.warnings) > 0
        assert "empty" in validator.warnings[0].message.lower()

    def test_validate_input_file_too_small(self, temp_dir, validator):
        """Test input file validation with file too small for DICOM."""
        small_file = temp_dir / "small.dcm"
        small_file.write_bytes(b"tiny")

        validator._validate_input_file(small_file)

        assert len(validator.warnings) > 0
        assert "too small" in validator.warnings[0].message.lower()

    def test_validate_input_file_invalid_dicom(self, temp_dir, validator):
        """Test input file validation with invalid DICOM content."""
        invalid_file = temp_dir / "invalid.dcm"
        # Write content that passes size check but isn't valid DICOM
        invalid_file.write_bytes(b"X" * 200)

        validator._validate_input_file(invalid_file)

        assert len(validator.warnings) > 0
        assert "not be valid DICOM" in validator.warnings[0].message

    def test_validate_output_dir_new_directory(self, temp_dir, validator):
        """Test output directory validation for new directory to be created."""
        new_dir = temp_dir / "new_output"

        validator._validate_output_dir(new_dir)

        assert any("will be created" in info.message.lower() for info in validator.info)
        assert len(validator.errors) == 0

    def test_validate_output_dir_existing(self, temp_dir, validator):
        """Test output directory validation for existing directory."""
        existing_dir = temp_dir / "existing"
        existing_dir.mkdir()

        validator._validate_output_dir(existing_dir)

        assert any("validated" in info.message.lower() for info in validator.info)
        assert len(validator.errors) == 0

    def test_validate_output_dir_parent_missing(self, temp_dir, validator):
        """Test output directory validation when parent doesn't exist."""
        deep_dir = temp_dir / "nonexistent" / "deep" / "output"

        validator._validate_output_dir(deep_dir)

        assert len(validator.errors) > 0
        assert "parent doesn't exist" in validator.errors[0].message.lower()

    def test_validate_output_dir_is_file(self, temp_dir, validator):
        """Test output directory validation when path is a file."""
        file_path = temp_dir / "file.txt"
        file_path.touch()

        validator._validate_output_dir(file_path)

        assert len(validator.errors) > 0
        assert "not a directory" in validator.errors[0].message.lower()

    def test_validate_target_executable_exists(self, temp_dir, validator):
        """Test target executable validation for existing file."""
        target = temp_dir / "target.exe"
        target.touch()

        validator._validate_target_executable(target)

        # On Windows, should validate successfully
        if sys.platform == "win32":
            assert any("validated" in info.message.lower() for info in validator.info)
        assert (
            len([e for e in validator.errors if "not found" in e.message.lower()]) == 0
        )

    def test_validate_target_executable_nonexistent(self, temp_dir, validator):
        """Test target executable validation for nonexistent file."""
        nonexistent = temp_dir / "nonexistent.exe"

        validator._validate_target_executable(nonexistent)

        assert len(validator.errors) > 0
        assert "not found" in validator.errors[0].message.lower()

    def test_validate_target_executable_is_directory(self, temp_dir, validator):
        """Test target executable validation when path is directory."""
        directory = temp_dir / "dir"
        directory.mkdir()

        validator._validate_target_executable(directory)

        assert len(validator.errors) > 0
        assert "not a file" in validator.errors[0].message.lower()

    def test_check_disk_space_real(self, temp_dir, validator):
        """Test disk space check with real filesystem."""
        validator._check_disk_space(temp_dir, min_mb=1, num_files=10)

        # Should succeed - we have more than 1MB available
        assert (
            len([e for e in validator.errors if "disk space" in e.message.lower()]) == 0
        )

    def test_check_disk_space_high_requirement(self, temp_dir, validator):
        """Test disk space check with unreasonably high requirement."""
        # Request 1TB minimum - should fail on most systems
        validator._check_disk_space(temp_dir, min_mb=1_000_000, num_files=10)

        # Should add error or warning about disk space
        space_issues = [
            e
            for e in validator.errors + validator.warnings
            if "disk space" in e.message.lower()
        ]
        assert len(space_issues) > 0

    def test_check_system_resources_real(self, validator):
        """Test system resource check with real psutil."""
        validator._check_system_resources()

        # Should have info about memory and CPU
        assert len(validator.info) > 0
        has_memory = any("memory" in info.message.lower() for info in validator.info)
        has_cpu = any("cpu" in info.message.lower() for info in validator.info)
        # If psutil is installed, we should have both
        # If not, we should have "Install 'psutil'" message
        assert (
            has_memory
            or has_cpu
            or any("psutil" in info.message.lower() for info in validator.info)
        )


class TestValidateAllRealExecution:
    """Test validate_all with real file operations."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_validate_all_no_params(self):
        """Test validate_all with no parameters."""
        validator = ConfigValidator(strict=False)
        result = validator.validate_all()

        # Should pass with just environment checks
        assert result is True

    def test_validate_all_with_valid_input(self, temp_dir):
        """Test validate_all with valid DICOM input file."""
        validator = ConfigValidator(strict=False)

        dicom_file = temp_dir / "test.dcm"
        create_test_dicom(dicom_file)

        result = validator.validate_all(input_file=dicom_file)

        assert result is True
        assert len(validator.errors) == 0

    def test_validate_all_with_valid_output(self, temp_dir):
        """Test validate_all with valid output directory."""
        validator = ConfigValidator(strict=False)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        result = validator.validate_all(output_dir=output_dir)

        assert result is True
        assert len(validator.errors) == 0

    def test_validate_all_with_disk_check(self, temp_dir):
        """Test validate_all with disk space check."""
        validator = ConfigValidator(strict=False)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        result = validator.validate_all(
            output_dir=output_dir, num_files=10, min_disk_space_mb=1
        )

        assert result is True

    def test_validate_all_errors_cause_failure(self, temp_dir):
        """Test validate_all returns False when errors present."""
        validator = ConfigValidator(strict=True)

        nonexistent = temp_dir / "nonexistent.dcm"

        result = validator.validate_all(input_file=nonexistent)

        assert result is False
        assert len(validator.errors) > 0

    def test_validate_all_strict_mode_warnings(self, temp_dir):
        """Test validate_all in strict mode treats warnings as errors."""
        validator = ConfigValidator(strict=True)

        # Empty file generates warning
        empty_file = temp_dir / "empty.dcm"
        empty_file.touch()

        result = validator.validate_all(input_file=empty_file)

        assert result is False
        assert len(validator.warnings) > 0

    def test_validate_all_non_strict_warnings_pass(self, temp_dir):
        """Test validate_all in non-strict mode allows warnings."""
        validator = ConfigValidator(strict=False)

        # Empty file generates warning
        empty_file = temp_dir / "empty.dcm"
        empty_file.touch()

        result = validator.validate_all(input_file=empty_file)

        # May still pass since warnings don't fail in non-strict mode
        # unless there are also errors
        assert len(validator.warnings) > 0

    def test_validate_all_full_workflow(self, temp_dir):
        """Test validate_all with full set of parameters."""
        validator = ConfigValidator(strict=False)

        # Create valid DICOM input
        dicom_file = temp_dir / "input.dcm"
        create_test_dicom(dicom_file)

        # Create output directory
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Create fake executable
        target = temp_dir / "target.exe"
        target.write_bytes(b"fake executable")

        result = validator.validate_all(
            input_file=dicom_file,
            output_dir=output_dir,
            target_executable=target,
            min_disk_space_mb=1,
            num_files=10,
        )

        assert result is True
        assert len(validator.errors) == 0


class TestGetSummaryCoverage:
    """Test get_summary method coverage."""

    def test_get_summary_empty(self):
        """Test summary with no results."""
        validator = ConfigValidator()
        summary = validator.get_summary()

        assert "Pre-flight Validation Summary" in summary
        assert "=" in summary

    def test_get_summary_with_errors(self):
        """Test summary includes errors."""
        validator = ConfigValidator()
        validator.errors.append(ValidationResult(passed=False, message="Test error 1"))
        validator.errors.append(ValidationResult(passed=False, message="Test error 2"))

        summary = validator.get_summary()

        assert "[X] Errors: 2" in summary
        assert "Test error 1" in summary
        assert "Test error 2" in summary

    def test_get_summary_with_warnings(self):
        """Test summary includes warnings."""
        validator = ConfigValidator()
        validator.warnings.append(
            ValidationResult(passed=False, message="Test warning", severity="warning")
        )

        summary = validator.get_summary()

        assert "[!] Warnings: 1" in summary
        assert "Test warning" in summary

    def test_get_summary_with_info(self):
        """Test summary includes info."""
        validator = ConfigValidator()
        for i in range(3):
            validator.info.append(
                ValidationResult(
                    passed=True, message=f"Info message {i}", severity="info"
                )
            )

        summary = validator.get_summary()

        assert "[i] Info: 3" in summary
        assert "Info message 0" in summary

    def test_get_summary_truncates_long_info(self):
        """Test summary truncates info list beyond 5 items."""
        validator = ConfigValidator()
        for i in range(10):
            validator.info.append(
                ValidationResult(passed=True, message=f"Info {i}", severity="info")
            )

        summary = validator.get_summary()

        assert "and 5 more" in summary

    def test_get_summary_full_results(self):
        """Test summary with all result types."""
        validator = ConfigValidator()
        validator.errors.append(ValidationResult(passed=False, message="Error"))
        validator.warnings.append(
            ValidationResult(passed=False, message="Warning", severity="warning")
        )
        validator.info.append(
            ValidationResult(passed=True, message="Info", severity="info")
        )

        summary = validator.get_summary()

        assert "Errors:" in summary
        assert "Warnings:" in summary
        assert "Info:" in summary


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_validator_strict_vs_non_strict(self):
        """Test difference between strict and non-strict modes."""
        strict_validator = ConfigValidator(strict=True)
        non_strict_validator = ConfigValidator(strict=False)

        assert strict_validator.strict is True
        assert non_strict_validator.strict is False

    def test_validator_collects_all_results(self, temp_dir):
        """Test that validator collects all result types."""
        validator = ConfigValidator(strict=False)

        # Create inputs that generate different result types
        dicom_file = temp_dir / "test.dcm"
        create_test_dicom(dicom_file)

        output_dir = temp_dir / "output"
        # Don't create it - will be "to be created" info

        nonexistent_target = temp_dir / "missing.exe"

        validator.validate_all(
            input_file=dicom_file,
            output_dir=output_dir,
            target_executable=nonexistent_target,
        )

        # Should have errors (target not found)
        assert len(validator.errors) > 0
        # Should have info (various passed checks)
        assert len(validator.info) > 0

    def test_validate_input_readable_file_check(self, temp_dir):
        """Test that readable file check is performed."""
        validator = ConfigValidator(strict=False)

        # Create a file that exists and is readable
        readable_file = temp_dir / "readable.dcm"
        create_test_dicom(readable_file)

        validator._validate_input_file(readable_file)

        # Should not have "not readable" error
        assert not any("not readable" in e.message.lower() for e in validator.errors)

    def test_check_disk_space_output_dir_not_exists(self, temp_dir):
        """Test disk space check when output dir doesn't exist yet."""
        validator = ConfigValidator(strict=False)

        # Directory that doesn't exist
        new_dir = temp_dir / "new_output"

        # Should check parent directory instead
        validator._check_disk_space(new_dir, min_mb=1, num_files=10)

        # Should succeed checking parent
        disk_errors = [e for e in validator.errors if "disk" in e.message.lower()]
        # With only 1MB requirement, should pass
        assert len(disk_errors) == 0


class TestIntegrationWithRealFiles:
    """Integration tests using real DICOM files."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_full_validation_pipeline(self, temp_dir):
        """Test full validation pipeline with real files."""
        validator = ConfigValidator(strict=False)

        # Set up complete test environment
        input_file = temp_dir / "input.dcm"
        create_test_dicom(input_file)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        target = temp_dir / "app.exe"
        target.write_bytes(b"fake app")

        # Run full validation
        result = validator.validate_all(
            input_file=input_file,
            output_dir=output_dir,
            target_executable=target,
            min_disk_space_mb=1,
            num_files=5,
        )

        # Check results
        assert result is True
        assert len(validator.errors) == 0

        # Get and verify summary
        summary = validator.get_summary()
        assert "Pre-flight Validation Summary" in summary

    def test_validation_with_multiple_issues(self, temp_dir):
        """Test validation that finds multiple issues."""
        validator = ConfigValidator(strict=False)

        # Empty input file (warning)
        empty_input = temp_dir / "empty.dcm"
        empty_input.touch()

        # Valid output
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Nonexistent target (error)
        nonexistent_target = temp_dir / "missing.exe"

        result = validator.validate_all(
            input_file=empty_input,
            output_dir=output_dir,
            target_executable=nonexistent_target,
        )

        # Should fail due to error
        assert result is False
        # Should have both errors and warnings
        assert len(validator.errors) >= 1
        assert len(validator.warnings) >= 1
