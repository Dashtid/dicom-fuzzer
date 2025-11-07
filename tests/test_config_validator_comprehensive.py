"""Comprehensive tests for dicom_fuzzer.core.config_validator module.

This test suite provides thorough coverage of configuration validation,
pre-flight checks, and system resource validation.
"""

from unittest.mock import Mock, patch

from dicom_fuzzer.core.config_validator import ConfigValidator, ValidationResult


class TestValidationResult:
    """Test suite for ValidationResult dataclass."""

    def test_initialization_default_severity(self):
        """Test ValidationResult with default severity."""
        result = ValidationResult(passed=True, message="Test message")

        assert result.passed is True
        assert result.message == "Test message"
        assert result.severity == "error"

    def test_initialization_custom_severity(self):
        """Test ValidationResult with custom severity."""
        result = ValidationResult(
            passed=False, message="Warning message", severity="warning"
        )

        assert result.passed is False
        assert result.severity == "warning"

    def test_boolean_evaluation_passed(self):
        """Test boolean evaluation returns passed value."""
        result = ValidationResult(passed=True, message="Success")

        assert bool(result) is True

    def test_boolean_evaluation_failed(self):
        """Test boolean evaluation for failed result."""
        result = ValidationResult(passed=False, message="Failed")

        assert bool(result) is False


class TestConfigValidatorInitialization:
    """Test suite for ConfigValidator initialization."""

    def test_initialization_strict_mode(self):
        """Test ConfigValidator in strict mode."""
        validator = ConfigValidator(strict=True)

        assert validator.strict is True
        assert validator.errors == []
        assert validator.warnings == []
        assert validator.info == []

    def test_initialization_non_strict_mode(self):
        """Test ConfigValidator in non-strict mode."""
        validator = ConfigValidator(strict=False)

        assert validator.strict is False


class TestCheckPythonVersion:
    """Test suite for Python version checking."""

    def test_check_python_version_meets_requirement(self):
        """Test Python version check passes for supported versions."""
        validator = ConfigValidator()

        with patch("sys.version_info", (3, 11, 0)):
            validator._check_python_version()

        assert len(validator.errors) == 0
        assert len(validator.info) > 0

    def test_check_python_version_below_requirement(self):
        """Test Python version check fails for old versions."""
        validator = ConfigValidator()

        with patch("sys.version_info", (3, 10, 0)):
            validator._check_python_version()

        assert len(validator.errors) > 0
        assert "Python 3.11+ required" in validator.errors[0].message


class TestCheckDependencies:
    """Test suite for dependency checking."""

    def test_check_dependencies_all_present(self):
        """Test dependency check passes when all installed."""
        validator = ConfigValidator()

        # Mock successful imports
        with patch("builtins.__import__") as mock_import:
            mock_import.return_value = Mock()
            validator._check_dependencies()

        assert len(validator.errors) == 0

    def test_check_dependencies_missing_required(self):
        """Test dependency check fails for missing required deps."""
        validator = ConfigValidator()

        # Mock ImportError for required dependency
        def mock_import_side_effect(name):
            if name == "pydicom":
                raise ImportError(f"No module named '{name}'")
            return Mock()

        with patch("builtins.__import__", side_effect=mock_import_side_effect):
            validator._check_dependencies()

        assert len(validator.errors) > 0
        assert "pydicom" in validator.errors[0].message

    def test_check_dependencies_missing_optional(self):
        """Test dependency check warns for missing optional deps."""
        validator = ConfigValidator()

        # Mock ImportError for optional dependency
        def mock_import_side_effect(name):
            if name in ["tqdm", "psutil"]:
                raise ImportError(f"No module named '{name}'")
            return Mock()

        with patch("builtins.__import__", side_effect=mock_import_side_effect):
            validator._check_dependencies()

        assert len(validator.warnings) > 0


class TestValidateInputFile:
    """Test suite for input file validation."""

    def test_validate_input_file_not_exists(self, tmp_path):
        """Test validation fails for non-existent file."""
        validator = ConfigValidator()
        non_existent = tmp_path / "nonexistent.dcm"

        validator._validate_input_file(non_existent)

        assert len(validator.errors) > 0
        assert "not found" in validator.errors[0].message.lower()

    def test_validate_input_file_is_directory(self, tmp_path):
        """Test validation fails for directory instead of file."""
        validator = ConfigValidator()
        directory = tmp_path / "dir"
        directory.mkdir()

        validator._validate_input_file(directory)

        assert len(validator.errors) > 0
        assert "not a file" in validator.errors[0].message.lower()

    def test_validate_input_file_not_readable(self, tmp_path):
        """Test validation fails for unreadable file."""
        validator = ConfigValidator()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # Mock os.access to return False
        with patch("os.access", return_value=False):
            validator._validate_input_file(test_file)

        assert len(validator.errors) > 0
        assert "not readable" in validator.errors[0].message.lower()

    def test_validate_input_file_empty(self, tmp_path):
        """Test validation warns for empty file."""
        validator = ConfigValidator()
        test_file = tmp_path / "empty.dcm"
        test_file.touch()

        validator._validate_input_file(test_file)

        assert len(validator.warnings) > 0
        assert "empty" in validator.warnings[0].message.lower()

    def test_validate_input_file_too_small(self, tmp_path):
        """Test validation warns for file too small to be DICOM."""
        validator = ConfigValidator()
        test_file = tmp_path / "small.dcm"
        test_file.write_bytes(b"short")

        validator._validate_input_file(test_file)

        assert len(validator.warnings) > 0
        assert "too small" in validator.warnings[0].message.lower()

    def test_validate_input_file_valid_dicom(self, tmp_path):
        """Test validation passes for valid DICOM file."""
        validator = ConfigValidator()
        test_file = tmp_path / "valid.dcm"
        # Create minimal DICOM structure
        file_data = bytearray(200)
        file_data[128:132] = b"DICM"
        test_file.write_bytes(file_data)

        # Mock pydicom.dcmread to succeed
        with patch("pydicom.dcmread"):
            validator._validate_input_file(test_file)

        assert len(validator.info) > 0
        assert "validated" in validator.info[0].message.lower()

    def test_validate_input_file_invalid_dicom(self, tmp_path):
        """Test validation warns for invalid DICOM file."""
        validator = ConfigValidator()
        test_file = tmp_path / "invalid.dcm"
        test_file.write_bytes(b"X" * 200)

        # Mock pydicom.dcmread to raise exception
        with patch("pydicom.dcmread", side_effect=Exception("Invalid DICOM")):
            validator._validate_input_file(test_file)

        assert len(validator.warnings) > 0
        assert "not be valid DICOM" in validator.warnings[0].message


class TestValidateOutputDir:
    """Test suite for output directory validation."""

    def test_validate_output_dir_parent_not_exists(self, tmp_path):
        """Test validation fails when parent doesn't exist."""
        validator = ConfigValidator()
        output_dir = tmp_path / "nonexistent" / "output"

        validator._validate_output_dir(output_dir)

        assert len(validator.errors) > 0
        assert "parent doesn't exist" in validator.errors[0].message.lower()

    def test_validate_output_dir_parent_not_writable(self, tmp_path):
        """Test validation fails when parent not writable."""
        validator = ConfigValidator()
        output_dir = tmp_path / "output"

        # Mock os.access to return False for write check
        with patch("os.access", return_value=False):
            validator._validate_output_dir(output_dir)

        assert len(validator.errors) > 0
        assert "not writable" in validator.errors[0].message.lower()

    def test_validate_output_dir_will_be_created(self, tmp_path):
        """Test validation succeeds when directory can be created."""
        validator = ConfigValidator()
        output_dir = tmp_path / "new_output"

        validator._validate_output_dir(output_dir)

        assert len(validator.info) > 0
        assert "will be created" in validator.info[0].message.lower()

    def test_validate_output_dir_exists_not_directory(self, tmp_path):
        """Test validation fails when path exists but is not directory."""
        validator = ConfigValidator()
        output_file = tmp_path / "file.txt"
        output_file.touch()

        validator._validate_output_dir(output_file)

        assert len(validator.errors) > 0
        assert "not a directory" in validator.errors[0].message.lower()

    def test_validate_output_dir_exists_not_writable(self, tmp_path):
        """Test validation fails when directory not writable."""
        validator = ConfigValidator()
        output_dir = tmp_path / "readonly"
        output_dir.mkdir()

        # Mock os.access to return False for write check
        with patch("os.access", return_value=False):
            validator._validate_output_dir(output_dir)

        assert len(validator.errors) > 0
        assert "not writable" in validator.errors[0].message.lower()

    def test_validate_output_dir_exists_valid(self, tmp_path):
        """Test validation passes for valid writable directory."""
        validator = ConfigValidator()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        validator._validate_output_dir(output_dir)

        assert len(validator.info) > 0
        assert "validated" in validator.info[0].message.lower()


class TestValidateTargetExecutable:
    """Test suite for target executable validation."""

    def test_validate_target_not_exists(self, tmp_path):
        """Test validation fails for non-existent executable."""
        validator = ConfigValidator()
        target = tmp_path / "nonexistent.exe"

        validator._validate_target_executable(target)

        assert len(validator.errors) > 0
        assert "not found" in validator.errors[0].message.lower()

    def test_validate_target_is_directory(self, tmp_path):
        """Test validation fails for directory instead of file."""
        validator = ConfigValidator()
        target = tmp_path / "dir"
        target.mkdir()

        validator._validate_target_executable(target)

        assert len(validator.errors) > 0
        assert "not a file" in validator.errors[0].message.lower()

    def test_validate_target_not_executable_unix(self, tmp_path):
        """Test validation warns for non-executable file on Unix."""
        validator = ConfigValidator()
        target = tmp_path / "target.exe"
        target.touch()

        # Mock Unix platform and non-executable
        with patch("sys.platform", "linux"):
            with patch("os.access", return_value=False):
                validator._validate_target_executable(target)

        assert len(validator.warnings) > 0
        assert "not be executable" in validator.warnings[0].message.lower()

    def test_validate_target_valid_windows(self, tmp_path):
        """Test validation passes on Windows."""
        validator = ConfigValidator()
        target = tmp_path / "target.exe"
        target.touch()

        # Mock Windows platform
        with patch("sys.platform", "win32"):
            validator._validate_target_executable(target)

        assert len(validator.info) > 0
        assert "validated" in validator.info[0].message.lower()

    def test_validate_target_valid_unix(self, tmp_path):
        """Test validation passes for executable file on Unix."""
        validator = ConfigValidator()
        target = tmp_path / "target"
        target.touch()

        # Mock Unix platform and executable
        with patch("sys.platform", "linux"):
            with patch("os.access", return_value=True):
                validator._validate_target_executable(target)

        assert len(validator.info) > 0
        assert "validated" in validator.info[0].message.lower()


class TestCheckDiskSpace:
    """Test suite for disk space checking."""

    def test_check_disk_space_insufficient(self, tmp_path):
        """Test disk space check fails when insufficient."""
        validator = ConfigValidator()
        output_dir = tmp_path

        # Mock disk_usage to return low free space
        mock_stat = Mock()
        mock_stat.free = 500 * 1024 * 1024  # 500MB
        with patch("shutil.disk_usage", return_value=mock_stat):
            validator._check_disk_space(output_dir, min_mb=1024, num_files=100)

        assert len(validator.errors) > 0
        assert "Insufficient disk space" in validator.errors[0].message

    def test_check_disk_space_tight(self, tmp_path):
        """Test disk space check warns when tight."""
        validator = ConfigValidator()
        output_dir = tmp_path

        # Mock disk_usage to return borderline space
        mock_stat = Mock()
        mock_stat.free = 100 * 1024 * 1024  # 100MB
        with patch("shutil.disk_usage", return_value=mock_stat):
            validator._check_disk_space(output_dir, min_mb=50, num_files=100)

        assert len(validator.warnings) > 0
        assert "may be tight" in validator.warnings[0].message

    def test_check_disk_space_sufficient(self, tmp_path):
        """Test disk space check passes with sufficient space."""
        validator = ConfigValidator()
        output_dir = tmp_path

        # Mock disk_usage to return plenty of space
        mock_stat = Mock()
        mock_stat.free = 10000 * 1024 * 1024  # 10GB
        with patch("shutil.disk_usage", return_value=mock_stat):
            validator._check_disk_space(output_dir, min_mb=1024, num_files=100)

        assert len(validator.info) > 0
        assert "available" in validator.info[0].message.lower()

    def test_check_disk_space_exception(self, tmp_path):
        """Test disk space check handles exceptions."""
        validator = ConfigValidator()
        output_dir = tmp_path

        # Mock disk_usage to raise exception
        with patch("shutil.disk_usage", side_effect=Exception("Disk error")):
            validator._check_disk_space(output_dir, min_mb=1024, num_files=100)

        assert len(validator.warnings) > 0
        assert "Could not check disk space" in validator.warnings[0].message


class TestCheckSystemResources:
    """Test suite for system resource checking."""

    def test_check_system_resources_with_psutil(self):
        """Test system resource check with psutil available."""
        validator = ConfigValidator()

        # Mock psutil
        mock_psutil = Mock()
        mock_mem = Mock()
        mock_mem.available = 2048 * 1024 * 1024  # 2GB
        mock_psutil.virtual_memory.return_value = mock_mem
        mock_psutil.cpu_count.return_value = 8

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            validator._check_system_resources()

        assert len(validator.info) >= 2
        assert any("memory" in info.message.lower() for info in validator.info)
        assert any("cpu" in info.message.lower() for info in validator.info)

    def test_check_system_resources_low_memory(self):
        """Test system resource check warns for low memory."""
        validator = ConfigValidator()

        # Mock psutil with low memory
        mock_psutil = Mock()
        mock_mem = Mock()
        mock_mem.available = 256 * 1024 * 1024  # 256MB
        mock_psutil.virtual_memory.return_value = mock_mem
        mock_psutil.cpu_count.return_value = 4

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            validator._check_system_resources()

        assert len(validator.warnings) > 0
        assert "Low available memory" in validator.warnings[0].message

    def test_check_system_resources_without_psutil(self):
        """Test system resource check without psutil."""
        validator = ConfigValidator()

        # Mock ImportError for psutil
        with patch.dict("sys.modules", {"psutil": None}):
            validator._check_system_resources()

        assert len(validator.info) > 0
        assert "Install 'psutil'" in validator.info[0].message


class TestValidateAll:
    """Test suite for validate_all integration."""

    def test_validate_all_minimal(self):
        """Test validate_all with minimal parameters."""
        validator = ConfigValidator(strict=False)

        # Mock version check to pass
        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all()

        assert result is True

    def test_validate_all_with_input_file(self, tmp_path):
        """Test validate_all with input file."""
        validator = ConfigValidator(strict=False)
        input_file = tmp_path / "test.dcm"
        file_data = bytearray(200)
        file_data[128:132] = b"DICM"
        input_file.write_bytes(file_data)

        with patch("sys.version_info", (3, 11, 0)):
            with patch("pydicom.dcmread"):
                result = validator.validate_all(input_file=input_file)

        assert result is True

    def test_validate_all_with_output_dir(self, tmp_path):
        """Test validate_all with output directory."""
        validator = ConfigValidator(strict=False)
        output_dir = tmp_path / "output"

        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all(output_dir=output_dir)

        assert result is True

    def test_validate_all_with_target(self, tmp_path):
        """Test validate_all with target executable."""
        validator = ConfigValidator(strict=False)
        target = tmp_path / "target.exe"
        target.touch()

        with patch("sys.version_info", (3, 11, 0)):
            with patch("sys.platform", "win32"):
                result = validator.validate_all(target_executable=target)

        assert result is True

    def test_validate_all_with_disk_check(self, tmp_path):
        """Test validate_all with disk space check."""
        validator = ConfigValidator(strict=False)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_stat = Mock()
        mock_stat.free = 10000 * 1024 * 1024
        with patch("sys.version_info", (3, 11, 0)):
            with patch("shutil.disk_usage", return_value=mock_stat):
                result = validator.validate_all(
                    output_dir=output_dir, num_files=100, min_disk_space_mb=1024
                )

        assert result is True

    def test_validate_all_fails_with_errors(self, tmp_path):
        """Test validate_all returns False when errors present."""
        validator = ConfigValidator()
        non_existent = tmp_path / "nonexistent.dcm"

        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all(input_file=non_existent)

        assert result is False
        assert len(validator.errors) > 0

    def test_validate_all_strict_mode_warnings_fail(self, tmp_path):
        """Test validate_all fails in strict mode with warnings."""
        validator = ConfigValidator(strict=True)
        empty_file = tmp_path / "empty.dcm"
        empty_file.touch()

        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all(input_file=empty_file)

        assert result is False

    def test_validate_all_non_strict_mode_warnings_pass(self, tmp_path):
        """Test validate_all passes in non-strict mode with warnings."""
        validator = ConfigValidator(strict=False)
        empty_file = tmp_path / "empty.dcm"
        empty_file.touch()

        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all(input_file=empty_file)

        # Should pass (warnings don't fail in non-strict mode)
        assert len(validator.warnings) > 0

    def test_validate_all_logs_info(self, tmp_path, caplog):
        """Test validate_all logs info messages."""
        import logging

        caplog.set_level(logging.INFO)

        validator = ConfigValidator(strict=False)

        with patch("sys.version_info", (3, 11, 0)):
            validator.validate_all()

        # Check log contains expected messages
        assert any(
            "Pre-flight" in record.message or "pre-flight" in record.message.lower()
            for record in caplog.records
        )

    def test_validate_all_logs_warnings(self, tmp_path, caplog):
        """Test validate_all logs warning messages."""
        validator = ConfigValidator(strict=False)
        empty_file = tmp_path / "empty.dcm"
        empty_file.touch()

        with patch("sys.version_info", (3, 11, 0)):
            validator.validate_all(input_file=empty_file)

        # Check warnings are logged
        assert any(
            record.levelname == "WARNING" for record in caplog.records if record.message
        )

    def test_validate_all_logs_errors(self, tmp_path, caplog):
        """Test validate_all logs error messages."""
        validator = ConfigValidator()
        non_existent = tmp_path / "nonexistent.dcm"

        with patch("sys.version_info", (3, 11, 0)):
            validator.validate_all(input_file=non_existent)

        # Check errors are logged
        assert any(
            record.levelname == "ERROR" for record in caplog.records if record.message
        )


class TestGetSummary:
    """Test suite for get_summary method."""

    def test_get_summary_empty(self):
        """Test summary with no validation results."""
        validator = ConfigValidator()

        summary = validator.get_summary()

        assert "Pre-flight Validation Summary" in summary
        assert "=" in summary

    def test_get_summary_with_errors(self):
        """Test summary includes errors."""
        validator = ConfigValidator()
        validator.errors.append(
            ValidationResult(passed=False, message="Error 1", severity="error")
        )
        validator.errors.append(
            ValidationResult(passed=False, message="Error 2", severity="error")
        )

        summary = validator.get_summary()

        assert "[X] Errors: 2" in summary
        assert "Error 1" in summary
        assert "Error 2" in summary

    def test_get_summary_with_warnings(self):
        """Test summary includes warnings."""
        validator = ConfigValidator()
        validator.warnings.append(
            ValidationResult(passed=False, message="Warning 1", severity="warning")
        )

        summary = validator.get_summary()

        assert "[!] Warnings: 1" in summary
        assert "Warning 1" in summary

    def test_get_summary_with_info(self):
        """Test summary includes info messages."""
        validator = ConfigValidator()
        for i in range(3):
            validator.info.append(
                ValidationResult(passed=True, message=f"Info {i}", severity="info")
            )

        summary = validator.get_summary()

        assert "[i] Info: 3" in summary
        assert "Info 0" in summary

    def test_get_summary_truncates_long_info(self):
        """Test summary truncates long info list."""
        validator = ConfigValidator()
        for i in range(10):
            validator.info.append(
                ValidationResult(passed=True, message=f"Info {i}", severity="info")
            )

        summary = validator.get_summary()

        assert "and 5 more" in summary


class TestIntegrationScenarios:
    """Test suite for complete validation workflows."""

    def test_complete_validation_workflow_success(self, tmp_path):
        """Test complete validation workflow that passes."""
        validator = ConfigValidator(strict=False)

        # Set up test files
        input_file = tmp_path / "input.dcm"
        file_data = bytearray(200)
        file_data[128:132] = b"DICM"
        input_file.write_bytes(file_data)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        target = tmp_path / "target.exe"
        target.touch()

        # Mock system resources
        mock_stat = Mock()
        mock_stat.free = 10000 * 1024 * 1024
        mock_psutil = Mock()
        mock_mem = Mock()
        mock_mem.available = 4096 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_mem
        mock_psutil.cpu_count.return_value = 8

        with patch("sys.version_info", (3, 11, 0)):
            with patch("sys.platform", "win32"):
                with patch("pydicom.dcmread"):
                    with patch("shutil.disk_usage", return_value=mock_stat):
                        with patch.dict("sys.modules", {"psutil": mock_psutil}):
                            result = validator.validate_all(
                                input_file=input_file,
                                output_dir=output_dir,
                                target_executable=target,
                                num_files=100,
                            )

        assert result is True
        assert len(validator.errors) == 0
        summary = validator.get_summary()
        assert "Pre-flight Validation Summary" in summary

    def test_complete_validation_workflow_failures(self, tmp_path):
        """Test complete validation workflow with failures."""
        validator = ConfigValidator()

        # Use non-existent files to trigger errors
        input_file = tmp_path / "nonexistent.dcm"
        output_dir = tmp_path / "nonexistent" / "output"
        target = tmp_path / "nonexistent_target.exe"

        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all(
                input_file=input_file,
                output_dir=output_dir,
                target_executable=target,
            )

        assert result is False
        assert len(validator.errors) >= 3
        summary = validator.get_summary()
        assert "Errors:" in summary

    def test_validation_with_mixed_results(self, tmp_path):
        """Test validation with mix of errors, warnings, and info."""
        validator = ConfigValidator(strict=False)

        # Create input that will generate warnings (empty file)
        input_file = tmp_path / "empty.dcm"
        input_file.touch()

        # Create valid output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Non-existent target (error)
        target = tmp_path / "nonexistent.exe"

        with patch("sys.version_info", (3, 11, 0)):
            result = validator.validate_all(
                input_file=input_file,
                output_dir=output_dir,
                target_executable=target,
            )

        assert result is False  # Due to target error
        assert len(validator.errors) >= 1  # Target not found
        assert len(validator.warnings) >= 1  # Empty file
        assert len(validator.info) >= 1  # Output dir validated

        summary = validator.get_summary()
        assert "[X]" in summary or "Errors" in summary
        assert "[!]" in summary or "Warnings" in summary
        assert "[i]" in summary or "Info" in summary
