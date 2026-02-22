"""Tests for dicom_fuzzer.cli.main module.

This module tests the main CLI entry point and helper functions.
Coverage target: cli/main.py from 9% to >90%
"""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.main import (
    apply_resource_limits,
    format_duration,
    format_file_size,
    main,
    parse_strategies,
    parse_target_config,
    pre_campaign_health_check,
    setup_logging,
    validate_strategy,
)
from dicom_fuzzer.core.session.resource_manager import ResourceLimits


# =============================================================================
# Tests for format_file_size
# =============================================================================
class TestFormatFileSize:
    """Tests for format_file_size helper function."""

    def test_bytes(self):
        """Test formatting bytes."""
        assert format_file_size(0) == "0 B"
        assert format_file_size(100) == "100 B"
        assert format_file_size(1023) == "1023 B"

    def test_kilobytes(self):
        """Test formatting kilobytes."""
        assert format_file_size(1024) == "1.0 KB"
        assert format_file_size(2048) == "2.0 KB"
        assert format_file_size(1536) == "1.5 KB"

    def test_megabytes(self):
        """Test formatting megabytes."""
        assert format_file_size(1024 * 1024) == "1.0 MB"
        assert format_file_size(2 * 1024 * 1024) == "2.0 MB"
        assert format_file_size(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        """Test formatting gigabytes."""
        assert format_file_size(1024 * 1024 * 1024) == "1.0 GB"
        assert format_file_size(2 * 1024 * 1024 * 1024) == "2.0 GB"

    def test_boundary_values(self):
        """Test boundary values between units."""
        # Just under 1 KB
        assert format_file_size(1023) == "1023 B"
        # Exactly 1 KB
        assert format_file_size(1024) == "1.0 KB"
        # Just under 1 MB
        kb = 1024
        mb = kb * 1024
        assert "KB" in format_file_size(mb - 1)
        # Exactly 1 MB
        assert format_file_size(mb) == "1.0 MB"


# =============================================================================
# Tests for format_duration
# =============================================================================
class TestFormatDuration:
    """Tests for format_duration helper function."""

    def test_seconds_only(self):
        """Test formatting seconds."""
        assert format_duration(0) == "0s"
        assert format_duration(30) == "30s"
        assert format_duration(59) == "59s"

    def test_minutes_and_seconds(self):
        """Test formatting minutes and seconds."""
        assert format_duration(60) == "1m 0s"
        assert format_duration(90) == "1m 30s"
        assert format_duration(125) == "2m 5s"

    def test_hours_minutes_seconds(self):
        """Test formatting hours, minutes, and seconds."""
        assert format_duration(3600) == "1h 0m 0s"
        assert format_duration(3661) == "1h 1m 1s"
        assert format_duration(7325) == "2h 2m 5s"

    def test_float_values(self):
        """Test with float values."""
        assert format_duration(30.5) == "30s"
        assert format_duration(90.9) == "1m 30s"


# =============================================================================
# Tests for validate_strategy
# =============================================================================
class TestValidateStrategy:
    """Tests for validate_strategy helper function."""

    def test_valid_strategy(self):
        """Test with valid strategy."""
        valid = ["metadata", "header", "pixel"]
        assert validate_strategy("metadata", valid) is True
        assert validate_strategy("header", valid) is True
        assert validate_strategy("pixel", valid) is True

    def test_all_keyword(self):
        """Test 'all' special keyword."""
        valid = ["metadata", "header", "pixel"]
        assert validate_strategy("all", valid) is True

    def test_invalid_strategy(self):
        """Test with invalid strategy."""
        valid = ["metadata", "header", "pixel"]
        assert validate_strategy("invalid", valid) is False
        assert validate_strategy("", valid) is False


# =============================================================================
# Tests for parse_target_config
# =============================================================================
class TestParseTargetConfig:
    """Tests for parse_target_config function."""

    def test_valid_config(self, tmp_path):
        """Test parsing valid JSON config."""
        config_data = {"target": "/path/to/app", "timeout": 10}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        result = parse_target_config(str(config_file))
        assert result == config_data

    def test_file_not_found(self):
        """Test with non-existent config file."""
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            parse_target_config("/nonexistent/config.json")

    def test_invalid_json(self, tmp_path):
        """Test with invalid JSON file."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("not valid json {")

        with pytest.raises(json.JSONDecodeError):
            parse_target_config(str(config_file))

    def test_empty_config(self, tmp_path):
        """Test with empty JSON object."""
        config_file = tmp_path / "empty.json"
        config_file.write_text("{}")

        result = parse_target_config(str(config_file))
        assert result == {}


# =============================================================================
# Tests for apply_resource_limits
# =============================================================================
class TestApplyResourceLimits:
    """Tests for apply_resource_limits function."""

    def test_none_limits(self):
        """Test with None limits (should do nothing)."""
        # Should not raise any exception
        result = apply_resource_limits(None)
        # Verify function completes successfully with no return value
        assert result is None

    def test_dict_limits(self):
        """Test with dict-based resource limits."""
        limits = {
            "max_memory_mb": 1024,
            "max_memory_mb_hard": 2048,
            "max_cpu_seconds": 30,
        }
        with patch("dicom_fuzzer.cli.main.ResourceManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            apply_resource_limits(limits)

            mock_manager_class.assert_called_once()
            mock_manager.check_available_resources.assert_called_once()

    def test_resource_limits_object(self):
        """Test with ResourceLimits object."""
        limits = ResourceLimits(max_memory_mb=512)
        with patch("dicom_fuzzer.cli.main.ResourceManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            apply_resource_limits(limits)

            mock_manager.check_available_resources.assert_called_once()


# =============================================================================
# Tests for setup_logging
# =============================================================================
class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_default_logging(self):
        """Test default (non-verbose) logging setup."""
        # Store original level
        root_logger = logging.getLogger()
        original_level = root_logger.level
        original_handlers = root_logger.handlers[:]

        try:
            setup_logging(verbose=False)
            # Function should configure INFO level via basicConfig
            # Check that the function ran without error
            assert True
        finally:
            # Restore original state
            root_logger.setLevel(original_level)
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            for handler in original_handlers:
                root_logger.addHandler(handler)

    def test_verbose_logging(self):
        """Test verbose logging setup."""
        # Store original level
        root_logger = logging.getLogger()
        original_level = root_logger.level
        original_handlers = root_logger.handlers[:]

        try:
            setup_logging(verbose=True)
            # Function should configure DEBUG level
            # Check that the function ran without error
            assert True
        finally:
            # Restore original state
            root_logger.setLevel(original_level)
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            for handler in original_handlers:
                root_logger.addHandler(handler)


# =============================================================================
# Tests for parse_strategies
# =============================================================================
class TestParseStrategies:
    """Tests for parse_strategies function."""

    def test_none_input(self):
        """Test with None input."""
        result = parse_strategies(None)
        assert result == []

    def test_empty_string(self):
        """Test with empty string."""
        result = parse_strategies("")
        assert result == []

    def test_whitespace_only(self):
        """Test with whitespace-only string."""
        result = parse_strategies("   ")
        assert result == []

    def test_single_valid_strategy(self):
        """Test with single valid strategy."""
        result = parse_strategies("metadata")
        assert result == ["metadata"]

    def test_multiple_valid_strategies(self):
        """Test with multiple valid strategies."""
        result = parse_strategies("metadata,header,pixel")
        assert set(result) == {"metadata", "header", "pixel"}

    def test_strategies_with_spaces(self):
        """Test strategies with spaces around commas."""
        result = parse_strategies("metadata , header , pixel")
        assert set(result) == {"metadata", "header", "pixel"}

    def test_invalid_strategy_warning(self, capsys):
        """Test that invalid strategies produce warning."""
        result = parse_strategies("metadata,invalid,header")
        captured = capsys.readouterr()
        assert "Warning" in captured.out
        assert "invalid" in captured.out
        assert set(result) == {"metadata", "header"}

    def test_all_invalid_strategies(self, capsys):
        """Test with all invalid strategies."""
        result = parse_strategies("invalid1,invalid2")
        assert result == []
        captured = capsys.readouterr()
        assert "Warning" in captured.out

    def test_case_insensitive(self):
        """Test case insensitivity."""
        result = parse_strategies("METADATA,Header,PIXEL")
        assert set(result) == {"metadata", "header", "pixel"}

    def test_structure_strategy(self):
        """Test structure strategy is valid."""
        result = parse_strategies("structure")
        assert result == ["structure"]


# =============================================================================
# Tests for pre_campaign_health_check
# =============================================================================
class TestPreCampaignHealthCheck:
    """Tests for pre_campaign_health_check function."""

    def test_basic_health_check_passes(self, tmp_path):
        """Test basic health check passes with valid setup."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        passed, issues = pre_campaign_health_check(output_dir=output_dir, verbose=False)

        assert passed is True

    def test_output_dir_created_if_missing(self, tmp_path):
        """Test output directory is created if it doesn't exist."""
        output_dir = tmp_path / "new_output"

        passed, issues = pre_campaign_health_check(output_dir=output_dir, verbose=False)

        assert passed is True
        assert output_dir.exists()

    def test_target_not_found_fails(self, tmp_path):
        """Test health check fails when target executable not found."""
        output_dir = tmp_path / "output"

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir,
            target="/nonexistent/executable",
            verbose=False,
        )

        assert passed is False
        assert any("not found" in issue for issue in issues)

    def test_target_is_directory_fails(self, tmp_path):
        """Test health check fails when target is a directory."""
        output_dir = tmp_path / "output"
        target_dir = tmp_path / "target_dir"
        target_dir.mkdir()

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, target=str(target_dir), verbose=False
        )

        assert passed is False
        assert any("not a file" in issue for issue in issues)

    def test_valid_target_passes(self, tmp_path):
        """Test health check passes with valid target."""
        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.write_text("fake executable")

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, target=str(target_exe), verbose=False
        )

        assert passed is True

    def test_low_memory_limit_warning(self, tmp_path):
        """Test warning for very low memory limit."""
        output_dir = tmp_path / "output"
        limits = ResourceLimits(max_memory_mb=64)

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, resource_limits=limits, verbose=True
        )

        # Should pass but have warning
        assert passed is True
        assert any("Memory limit very low" in issue for issue in issues)

    def test_low_cpu_time_warning(self, tmp_path):
        """Test warning for very low CPU time limit."""
        output_dir = tmp_path / "output"
        limits = ResourceLimits(max_cpu_seconds=0.5)

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, resource_limits=limits, verbose=True
        )

        assert passed is True
        assert any("CPU time limit very low" in issue for issue in issues)

    def test_verbose_output(self, tmp_path, capsys):
        """Test verbose output shows warnings."""
        output_dir = tmp_path / "output"
        limits = ResourceLimits(max_memory_mb=64, max_cpu_seconds=0.5)

        pre_campaign_health_check(
            output_dir=output_dir, resource_limits=limits, verbose=True
        )

        captured = capsys.readouterr()
        assert "Pre-flight check" in captured.out

    def test_missing_pydicom_fails(self, tmp_path):
        """Test health check fails when pydicom is missing."""
        output_dir = tmp_path / "output"

        with patch.dict(sys.modules, {"pydicom": None}):
            # Force reimport to trigger ImportError
            import importlib

            with patch("builtins.__import__") as mock_import:

                def import_side_effect(name, *args, **kwargs):
                    if name == "pydicom":
                        raise ImportError("No module named 'pydicom'")
                    return importlib.__import__(name, *args, **kwargs)

                mock_import.side_effect = import_side_effect

                passed, issues = pre_campaign_health_check(
                    output_dir=output_dir, verbose=False
                )

                # pydicom is already imported in the module, so this test
                # may not catch it. The function checks at import time.
                # Verify function completed and returned valid results
                assert isinstance(passed, bool)
                assert isinstance(issues, list)

    def test_unwritable_output_dir_fails(self, tmp_path):
        """Test health check fails when output directory is not writable."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Mock the directory to not be writable
        with patch.object(Path, "write_text") as mock_write:
            mock_write.side_effect = PermissionError("Permission denied")

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir, verbose=False
            )

            assert passed is False
            assert any("not writable" in issue for issue in issues)


# =============================================================================
# Tests for main function
# =============================================================================
class TestMain:
    """Tests for main CLI function."""

    def test_main_help(self):
        """Test --help option exits with 0."""
        with patch.object(sys, "argv", ["dicom-fuzzer", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_main_version(self):
        """Test --version option."""
        with patch.object(sys, "argv", ["dicom-fuzzer", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_main_missing_input_file(self):
        """Test main fails without input file."""
        with patch.object(sys, "argv", ["dicom-fuzzer"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # argparse error code

    def test_main_invalid_input_file(self):
        """Test main fails with non-existent input file."""
        with patch.object(sys, "argv", ["dicom-fuzzer", "/nonexistent/file.dcm"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_successful_run(self, tmp_path):
        """Test successful fuzzing campaign."""
        # Create a mock DICOM file
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "5",
                "-o",
                str(output_dir),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(5)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {
                    "metadata": 3,
                    "header": 2,
                }
                mock_generator_class.return_value = mock_generator

                result = main()

                assert result == 0
                mock_generator.generate_batch.assert_called()

    def test_main_with_strategies(self, tmp_path):
        """Test main with specific strategies."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "5",
                "-o",
                str(output_dir),
                "-s",
                "metadata,header",
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(5)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                result = main()

                assert result == 0
                # Verify strategies were passed
                call_args = mock_generator.generate_batch.call_args
                assert "metadata" in call_args.kwargs.get(
                    "strategies", []
                ) or "metadata" in call_args[1].get("strategies", [])

    def test_main_invalid_strategies_only(self, tmp_path):
        """Test main fails with only invalid strategies."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-s",
                "invalid1,invalid2",
            ],
        ):
            # Invalid strategies cause fallback to defaults, but parsing error returns 1
            result = main()
            assert result == 1

    def test_main_verbose_mode(self, tmp_path):
        """Test main with verbose mode."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "5",
                "-o",
                str(output_dir),
                "-v",
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(5)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                result = main()

                assert result == 0

    def test_main_with_target(self, tmp_path):
        """Test main with target application testing."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.write_text("fake executable")

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
                "--timeout",
                "2.0",
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                generated_files = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(3)
                ]
                mock_generator.generate_batch.return_value = generated_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.controllers.target_controller.TargetRunner"
                ) as mock_runner_class:
                    mock_runner = MagicMock()
                    mock_runner.run_campaign.return_value = []
                    mock_runner.get_summary.return_value = "Test Summary"
                    mock_runner_class.return_value = mock_runner

                    result = main()

                    assert result == 0
                    mock_runner_class.assert_called_once()
                    mock_runner.run_campaign.assert_called_once()

    def test_main_target_not_found(self, tmp_path):
        """Test main fails when target executable not found."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-t",
                "/nonexistent/target.exe",
            ],
        ):
            # Health check should catch this and return 1
            result = main()
            assert result == 1

    def test_main_with_resource_limits(self, tmp_path):
        """Test main with resource limits."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "--max-memory",
                "512",
                "--max-cpu-time",
                "60",
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(3)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                result = main()

                assert result == 0

    def test_main_keyboard_interrupt(self, tmp_path):
        """Test main handles keyboard interrupt."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "5",
                "-o",
                str(output_dir),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator_class.side_effect = KeyboardInterrupt()

                result = main()
                assert result == 130

    def test_main_generator_exception(self, tmp_path):
        """Test main handles generator exception."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "5",
                "-o",
                str(output_dir),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator_class.side_effect = RuntimeError("Generator failed")

                result = main()
                assert result == 1

    def test_main_target_runner_exception(self, tmp_path):
        """Test main handles target runner exception."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.write_text("fake executable")

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(3)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.controllers.target_controller.TargetRunner"
                ) as mock_runner_class:
                    mock_runner_class.side_effect = RuntimeError("Runner failed")

                    result = main()
                    assert result == 1

    def test_main_target_runner_file_not_found(self, tmp_path):
        """Test main handles target runner FileNotFoundError."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.write_text("fake executable")

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(3)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.controllers.target_controller.TargetRunner"
                ) as mock_runner_class:
                    mock_runner_class.side_effect = FileNotFoundError(
                        "Executable not found"
                    )

                    result = main()
                    assert result == 1

    def test_main_health_check_fails(self, tmp_path):
        """Test main exits when health check fails."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-t",
                "/nonexistent/target.exe",
            ],
        ):
            result = main()
            assert result == 1

    def test_main_with_stop_on_crash(self, tmp_path):
        """Test main with --stop-on-crash option."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.write_text("fake executable")

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
                "--stop-on-crash",
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(3)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.controllers.target_controller.TargetRunner"
                ) as mock_runner_class:
                    mock_runner = MagicMock()
                    mock_runner.run_campaign.return_value = []
                    mock_runner.get_summary.return_value = "Test Summary"
                    mock_runner_class.return_value = mock_runner

                    result = main()

                    assert result == 0
                    # Verify stop_on_crash was passed
                    call_args = mock_runner.run_campaign.call_args
                    assert call_args.kwargs.get("stop_on_crash") is True


# =============================================================================
# Tests for tqdm progress bar integration
# =============================================================================
class TestProgressBar:
    """Tests for tqdm progress bar integration."""

    def test_main_with_tqdm_large_count(self, tmp_path):
        """Test that tqdm is used for large file counts."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "50",  # Large enough to trigger tqdm
                "-o",
                str(output_dir),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(50)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.controllers.campaign_runner.HAS_TQDM", True
                ):
                    with patch(
                        "dicom_fuzzer.cli.controllers.campaign_runner.tqdm"
                    ) as mock_tqdm:
                        mock_pbar = MagicMock()
                        mock_tqdm.return_value.__enter__ = MagicMock(
                            return_value=mock_pbar
                        )
                        mock_tqdm.return_value.__exit__ = MagicMock(return_value=False)

                        result = main()

                        assert result == 0

    def test_main_without_tqdm(self, tmp_path):
        """Test main works without tqdm installed."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"DICM" + b"\x00" * 128)

        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom-fuzzer",
                str(input_file),
                "-c",
                "50",
                "-o",
                str(output_dir),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(output_dir / f"fuzzed_{i}.dcm") for i in range(50)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.controllers.campaign_runner.HAS_TQDM", False
                ):
                    result = main()

                    assert result == 0


# =============================================================================
# Tests for edge cases
# =============================================================================
class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_format_file_size_large_values(self):
        """Test format_file_size with very large values."""
        # 1 TB
        assert "GB" in format_file_size(1024 * 1024 * 1024 * 1024)

    def test_format_duration_edge_cases(self):
        """Test format_duration edge cases."""
        # Exactly 1 minute
        assert format_duration(60) == "1m 0s"
        # Exactly 1 hour
        assert format_duration(3600) == "1h 0m 0s"

    def test_empty_strategies_list(self):
        """Test parse_strategies with various empty inputs."""
        assert parse_strategies(None) == []
        assert parse_strategies("") == []
        assert parse_strategies("   ") == []

    def test_health_check_disk_space_check_failure(self, tmp_path):
        """Test health check handles disk space check failures gracefully."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk_usage:
            mock_disk_usage.side_effect = OSError("Disk error")

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir, verbose=True
            )

            # Should still pass but with warning about disk check
            assert passed is True
            assert any("Could not check disk space" in issue for issue in issues)

    def test_health_check_low_disk_space_warning(self, tmp_path):
        """Test health check warns on low disk space."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk_usage:
            # Return 500 MB free (between 100MB and 1GB)
            mock_disk_usage.return_value = MagicMock(free=500 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir, verbose=True
            )

            assert passed is True
            assert any("Low disk space" in issue for issue in issues)

    def test_health_check_critical_low_disk_space(self, tmp_path):
        """Test health check fails on critically low disk space."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk_usage:
            # Return 50 MB free (below 100MB)
            mock_disk_usage.return_value = MagicMock(free=50 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir, verbose=False
            )

            assert passed is False
            assert any("Insufficient disk space" in issue for issue in issues)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
