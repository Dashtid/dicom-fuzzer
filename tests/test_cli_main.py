"""Comprehensive tests for dicom_fuzzer.cli.main module.

Tests CLI helper functions, argument parsing, validation, and main entry point.
"""

import json
import logging
import sys
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
    validate_input_file,
    validate_strategy,
)
from dicom_fuzzer.core.resource_manager import ResourceLimits


class TestFormatFileSize:
    """Tests for format_file_size function."""

    def test_format_bytes(self):
        """Test formatting bytes (< 1 KB)."""
        assert format_file_size(0) == "0 B"
        assert format_file_size(100) == "100 B"
        assert format_file_size(1023) == "1023 B"

    def test_format_kilobytes(self):
        """Test formatting kilobytes (1 KB - 1 MB)."""
        assert format_file_size(1024) == "1.0 KB"
        assert format_file_size(1536) == "1.5 KB"
        assert format_file_size(10240) == "10.0 KB"
        assert format_file_size(1024 * 1023) == "1023.0 KB"

    def test_format_megabytes(self):
        """Test formatting megabytes (1 MB - 1 GB)."""
        assert format_file_size(1024 * 1024) == "1.0 MB"
        assert format_file_size(1024 * 1024 * 1.5) == "1.5 MB"
        assert format_file_size(1024 * 1024 * 100) == "100.0 MB"

    def test_format_gigabytes(self):
        """Test formatting gigabytes (>= 1 GB)."""
        assert format_file_size(1024 * 1024 * 1024) == "1.0 GB"
        assert format_file_size(1024 * 1024 * 1024 * 2.5) == "2.5 GB"


class TestFormatDuration:
    """Tests for format_duration function."""

    def test_format_seconds(self):
        """Test formatting seconds (< 60s)."""
        assert format_duration(0) == "0s"
        assert format_duration(30) == "30s"
        assert format_duration(59) == "59s"

    def test_format_minutes(self):
        """Test formatting minutes (1-59 min)."""
        assert format_duration(60) == "1m 0s"
        assert format_duration(90) == "1m 30s"
        assert format_duration(3599) == "59m 59s"

    def test_format_hours(self):
        """Test formatting hours (>= 1 hour)."""
        assert format_duration(3600) == "1h 0m 0s"
        assert format_duration(3661) == "1h 1m 1s"
        assert format_duration(7200) == "2h 0m 0s"
        assert format_duration(7265) == "2h 1m 5s"

    def test_format_fractional_seconds(self):
        """Test that fractional seconds are truncated."""
        assert format_duration(30.5) == "30s"
        assert format_duration(90.9) == "1m 30s"


class TestValidateStrategy:
    """Tests for validate_strategy function."""

    def test_valid_strategy(self):
        """Test validation of valid strategies."""
        valid_strategies = ["metadata", "header", "pixel", "structure"]
        assert validate_strategy("metadata", valid_strategies) is True
        assert validate_strategy("header", valid_strategies) is True
        assert validate_strategy("pixel", valid_strategies) is True
        assert validate_strategy("structure", valid_strategies) is True

    def test_all_keyword(self):
        """Test that 'all' is always valid."""
        assert validate_strategy("all", []) is True
        assert validate_strategy("all", ["metadata"]) is True

    def test_invalid_strategy(self):
        """Test validation of invalid strategies."""
        valid_strategies = ["metadata", "header"]
        assert validate_strategy("invalid", valid_strategies) is False
        assert validate_strategy("pixel", valid_strategies) is False


class TestParseTargetConfig:
    """Tests for parse_target_config function."""

    def test_parse_valid_config(self, tmp_path):
        """Test parsing a valid JSON config file."""
        config_file = tmp_path / "config.json"
        config_data = {"target": "/path/to/app", "timeout": 5.0}
        config_file.write_text(json.dumps(config_data))

        result = parse_target_config(str(config_file))
        assert result == config_data

    def test_config_file_not_found(self):
        """Test error when config file doesn't exist."""
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            parse_target_config("/nonexistent/config.json")

    def test_invalid_json(self, tmp_path):
        """Test error when config file has invalid JSON."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("{ invalid json }")

        with pytest.raises(json.JSONDecodeError):
            parse_target_config(str(config_file))


class TestApplyResourceLimits:
    """Tests for apply_resource_limits function."""

    def test_none_limits(self):
        """Test that None limits don't raise errors."""
        apply_resource_limits(None)  # Should not raise

    def test_dict_limits(self):
        """Test applying resource limits from dict."""
        limits_dict = {
            "max_memory_mb": 1024,
            "max_cpu_seconds": 30,
        }
        # Should not raise - just validates resources are available
        apply_resource_limits(limits_dict)

    def test_resource_limits_instance(self):
        """Test applying ResourceLimits instance."""
        limits = ResourceLimits(max_memory_mb=1024, max_cpu_seconds=30)
        apply_resource_limits(limits)  # Should not raise


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_verbose_logging(self):
        """Test verbose logging sets DEBUG level."""
        # Reset root logger level to allow basicConfig to work
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.NOTSET)
        # Remove all handlers to allow basicConfig to work
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        setup_logging(verbose=True)
        # basicConfig sets level directly on root logger
        assert root_logger.level == logging.DEBUG

    def test_normal_logging(self):
        """Test normal logging sets INFO level."""
        # Reset root logger level to allow basicConfig to work
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.NOTSET)
        # Remove all handlers to allow basicConfig to work
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        setup_logging(verbose=False)
        assert root_logger.level == logging.INFO


class TestValidateInputFile:
    """Tests for validate_input_file function."""

    def test_valid_file(self, tmp_path):
        """Test validation of existing file."""
        test_file = tmp_path / "test.dcm"
        test_file.write_text("test content")

        result = validate_input_file(str(test_file))
        assert result == test_file

    def test_file_not_found(self):
        """Test error when file doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            validate_input_file("/nonexistent/file.dcm")
        assert exc_info.value.code == 1

    def test_path_is_directory(self, tmp_path):
        """Test error when path is a directory."""
        with pytest.raises(SystemExit) as exc_info:
            validate_input_file(str(tmp_path))
        assert exc_info.value.code == 1


class TestParseStrategies:
    """Tests for parse_strategies function."""

    def test_parse_single_strategy(self):
        """Test parsing a single strategy."""
        result = parse_strategies("metadata")
        assert result == ["metadata"]

    def test_parse_multiple_strategies(self):
        """Test parsing multiple comma-separated strategies."""
        result = parse_strategies("metadata,header,pixel")
        assert result == ["metadata", "header", "pixel"]

    def test_parse_with_whitespace(self):
        """Test parsing handles whitespace correctly."""
        result = parse_strategies("metadata, header , pixel")
        assert result == ["metadata", "header", "pixel"]

    def test_parse_case_insensitive(self):
        """Test parsing is case-insensitive."""
        result = parse_strategies("METADATA,Header,PIXEL")
        assert result == ["metadata", "header", "pixel"]

    def test_parse_none_input(self):
        """Test parsing None returns empty list."""
        result = parse_strategies(None)
        assert result == []

    def test_parse_empty_string(self):
        """Test parsing empty string returns empty list."""
        result = parse_strategies("")
        assert result == []

    def test_parse_whitespace_only(self):
        """Test parsing whitespace-only returns empty list."""
        result = parse_strategies("   ")
        assert result == []

    def test_parse_filters_invalid(self, capsys):
        """Test that invalid strategies are filtered with warning."""
        result = parse_strategies("metadata,invalid,header")
        assert result == ["metadata", "header"]
        captured = capsys.readouterr()
        assert "Unknown strategies" in captured.out
        assert "invalid" in captured.out


class TestPreCampaignHealthCheck:
    """Tests for pre_campaign_health_check function."""

    def test_successful_check(self, tmp_path):
        """Test successful health check."""
        output_dir = tmp_path / "output"
        passed, issues = pre_campaign_health_check(output_dir=output_dir)
        assert passed is True
        assert output_dir.exists()

    def test_creates_output_directory(self, tmp_path):
        """Test that health check creates output directory."""
        output_dir = tmp_path / "new_output"
        assert not output_dir.exists()

        passed, _ = pre_campaign_health_check(output_dir=output_dir)
        assert passed is True
        assert output_dir.exists()

    def test_target_not_found(self, tmp_path):
        """Test failure when target executable not found."""
        output_dir = tmp_path / "output"
        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, target="/nonexistent/target"
        )
        assert passed is False
        assert any("not found" in issue for issue in issues)

    def test_target_not_file(self, tmp_path):
        """Test failure when target is not a file."""
        output_dir = tmp_path / "output"
        target_dir = tmp_path / "target_dir"
        target_dir.mkdir()

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, target=str(target_dir)
        )
        assert passed is False
        assert any("not a file" in issue for issue in issues)

    def test_low_memory_warning(self, tmp_path):
        """Test warning for very low memory limits."""
        output_dir = tmp_path / "output"
        limits = ResourceLimits(max_memory_mb=64)  # Very low

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, resource_limits=limits, verbose=True
        )
        # Should still pass but have warnings
        assert passed is True
        assert any("Memory limit very low" in issue for issue in issues)

    def test_low_cpu_warning(self, tmp_path):
        """Test warning for very low CPU time limits."""
        output_dir = tmp_path / "output"
        limits = ResourceLimits(max_cpu_seconds=0.5)  # Very low

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, resource_limits=limits, verbose=True
        )
        assert passed is True
        assert any("CPU time limit very low" in issue for issue in issues)

    def test_verbose_output(self, tmp_path, capsys):
        """Test verbose output includes warnings."""
        output_dir = tmp_path / "output"
        passed, _ = pre_campaign_health_check(output_dir=output_dir, verbose=True)

        captured = capsys.readouterr()
        # Should have some output in verbose mode
        assert "Pre-flight" in captured.out


class TestMainFunction:
    """Tests for main CLI entry point."""

    @pytest.fixture
    def sample_dicom(self, tmp_path):
        """Create a sample DICOM file for testing."""
        from pydicom.dataset import Dataset, FileMetaDataset

        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.Modality = "CT"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.5.6"
        ds.SOPInstanceUID = "1.2.3.4.5.6.7"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"
        ds.file_meta = file_meta

        dcm_path = tmp_path / "test.dcm"
        ds.save_as(str(dcm_path), write_like_original=False)
        return dcm_path

    def test_main_basic_execution(self, sample_dicom, tmp_path):
        """Test basic main execution."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            ["dicom_fuzzer", str(sample_dicom), "-o", str(output_dir), "-c", "5"],
        ):
            result = main()
            assert result == 0

    def test_main_with_strategies(self, sample_dicom, tmp_path):
        """Test main with strategy selection."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom_fuzzer",
                str(sample_dicom),
                "-o",
                str(output_dir),
                "-c",
                "3",
                "-s",
                "metadata,header",
            ],
        ):
            result = main()
            assert result == 0

    def test_main_verbose_mode(self, sample_dicom, tmp_path):
        """Test main with verbose logging."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            ["dicom_fuzzer", str(sample_dicom), "-o", str(output_dir), "-c", "3", "-v"],
        ):
            result = main()
            assert result == 0

    def test_main_file_not_found(self, tmp_path):
        """Test main exits when input file not found."""
        with patch.object(sys, "argv", ["dicom_fuzzer", "/nonexistent.dcm"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_invalid_strategies(self, sample_dicom, tmp_path):
        """Test main exits when no valid strategies specified."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom_fuzzer",
                str(sample_dicom),
                "-o",
                str(output_dir),
                "-s",
                "invalid_only",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_with_resource_limits(self, sample_dicom, tmp_path):
        """Test main with resource limits."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom_fuzzer",
                str(sample_dicom),
                "-o",
                str(output_dir),
                "-c",
                "3",
                "--max-memory",
                "512",
            ],
        ):
            result = main()
            assert result == 0

    def test_main_keyboard_interrupt(self, sample_dicom, tmp_path):
        """Test main handles keyboard interrupt."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            ["dicom_fuzzer", str(sample_dicom), "-o", str(output_dir), "-c", "100"],
        ):
            with patch(
                "dicom_fuzzer.cli.main.DICOMGenerator.generate_batch",
                side_effect=KeyboardInterrupt,
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 130

    def test_main_general_exception(self, sample_dicom, tmp_path):
        """Test main handles general exceptions."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            ["dicom_fuzzer", str(sample_dicom), "-o", str(output_dir), "-c", "5"],
        ):
            with patch(
                "dicom_fuzzer.cli.main.DICOMGenerator.generate_batch",
                side_effect=RuntimeError("Test error"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1


class TestMainWithTarget:
    """Tests for main CLI with target testing."""

    @pytest.fixture
    def sample_dicom(self, tmp_path):
        """Create a sample DICOM file for testing."""
        from pydicom.dataset import Dataset, FileMetaDataset

        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.Modality = "CT"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.5.6"
        ds.SOPInstanceUID = "1.2.3.4.5.6.7"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"
        ds.file_meta = file_meta

        dcm_path = tmp_path / "test.dcm"
        ds.save_as(str(dcm_path), write_like_original=False)
        return dcm_path

    @pytest.fixture
    def mock_target(self, tmp_path):
        """Create a mock target executable."""
        if sys.platform == "win32":
            target = tmp_path / "target.bat"
            target.write_text("@echo off\necho OK")
        else:
            target = tmp_path / "target.sh"
            target.write_text("#!/bin/bash\necho OK")
            target.chmod(0o755)
        return target

    def test_main_with_target(self, sample_dicom, tmp_path, mock_target):
        """Test main with target application testing."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom_fuzzer",
                str(sample_dicom),
                "-o",
                str(output_dir),
                "-c",
                "3",
                "-t",
                str(mock_target),
                "--timeout",
                "2.0",
            ],
        ):
            # Mock TargetRunner to avoid actual execution
            with patch("dicom_fuzzer.cli.main.TargetRunner") as mock_runner:
                mock_instance = MagicMock()
                mock_runner.return_value = mock_instance
                mock_instance.run_campaign.return_value = []
                mock_instance.get_summary.return_value = "Test summary"

                result = main()
                assert result == 0

    def test_main_target_not_found(self, sample_dicom, tmp_path):
        """Test main fails when target not found during health check."""
        output_dir = tmp_path / "output"

        with patch.object(
            sys,
            "argv",
            [
                "dicom_fuzzer",
                str(sample_dicom),
                "-o",
                str(output_dir),
                "-c",
                "3",
                "-t",
                "/nonexistent/target",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


class TestHasTqdm:
    """Tests for tqdm availability detection."""

    def test_tqdm_import(self):
        """Test that HAS_TQDM is correctly set."""
        from dicom_fuzzer.cli.main import HAS_TQDM

        # tqdm should be available in the test environment
        assert isinstance(HAS_TQDM, bool)
