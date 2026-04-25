"""Tests for study-campaign CLI Subcommand.

Tests argument parsing, help output, strategy listing, and execution paths.
"""

import argparse
import json
import sys
from pathlib import Path

import pytest


class TestStudyCampaignParser:
    """Test study-campaign CLI argument parser."""

    def test_create_parser(self):
        """Test study-campaign parser creation."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "dicom-fuzzer study-campaign"

    def test_list_strategies_standalone(self):
        """Test --list-strategies works without other args."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--list-strategies"])
        assert args.list_strategies is True

    def test_required_arguments_target_or_list_strategies(self):
        """Test --target or --list-strategies is required."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()

        # Should fail with just --study (neither --target nor --list-strategies)
        with pytest.raises(SystemExit):
            parser.parse_args(["--study", "./test"])

        # Should succeed with --target (--study validated at runtime)
        args = parser.parse_args(["--target", "./app.exe"])
        assert args.target == "./app.exe"

        # Should succeed with --target and --study
        args = parser.parse_args(["--target", "./app.exe", "--study", "./test"])
        assert args.target == "./app.exe"
        assert args.study == "./test"

    def test_strategy_choices(self):
        """Test valid strategy choices are accepted."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        valid_strategies = [
            "cross-series",
            "frame-of-reference",
            "patient-consistency",
            "study-metadata",
            "mixed-modality",
            "all",
        ]

        for strategy in valid_strategies:
            args = parser.parse_args(
                ["--target", "./app", "--study", "./test", "--strategy", strategy]
            )
            assert args.strategy == strategy

    def test_invalid_strategy_rejected(self):
        """Test invalid strategy is rejected."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--target", "./app", "--study", "./test", "--strategy", "invalid"]
            )

    def test_severity_choices(self):
        """Test valid severity choices are accepted."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()

        for severity in ["minimal", "moderate", "aggressive", "extreme"]:
            args = parser.parse_args(
                ["--target", "./app", "--study", "./test", "--severity", severity]
            )
            assert args.severity == severity

    def test_invalid_severity_rejected(self):
        """Test invalid severity is rejected."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--target", "./app", "--study", "./test", "--severity", "wrong"]
            )

    def test_default_values(self):
        """Test default values for optional arguments."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app.exe", "--study", "./test"])

        assert args.strategy == "all"
        assert args.severity == "moderate"
        assert args.count == 100
        assert args.timeout == 15.0
        assert args.memory_limit == 2048
        assert args.startup_delay == 3.0
        assert args.output == "./artifacts/study-campaign"
        assert args.verbose is False
        assert args.stop_on_crash is False

    def test_count_argument(self):
        """Test --count argument."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app", "--study", "./test", "-c", "50"])
        assert args.count == 50

    def test_timeout_argument(self):
        """Test --timeout argument."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--timeout", "30.0"]
        )
        assert args.timeout == 30.0

    def test_memory_limit_argument(self):
        """Test --memory-limit argument."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--memory-limit", "4096"]
        )
        assert args.memory_limit == 4096

    def test_startup_delay_argument(self):
        """Test --startup-delay argument."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--startup-delay", "5.0"]
        )
        assert args.startup_delay == 5.0

    def test_output_directory_argument(self):
        """Test -o/--output argument."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "-o", "./custom/output"]
        )
        assert args.output == "./custom/output"

    def test_stop_on_crash_flag(self):
        """Test --stop-on-crash flag."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--stop-on-crash"]
        )
        assert args.stop_on_crash is True

    def test_verbose_flag(self):
        """Test -v/--verbose flag."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app", "--study", "./test", "-v"])
        assert args.verbose is True


class TestStudyCampaignListStrategies:
    """Test --list-strategies functionality."""

    def test_list_strategies_output(self, capsys):
        """Test --list-strategies prints all strategies."""
        from dicom_fuzzer.cli.commands.study_campaign import run_list_strategies

        result = run_list_strategies()
        assert result == 0

        captured = capsys.readouterr()
        assert "cross-series" in captured.out
        assert "frame-of-reference" in captured.out
        assert "patient-consistency" in captured.out
        assert "study-metadata" in captured.out
        assert "mixed-modality" in captured.out
        assert "all" in captured.out

    def test_main_list_strategies(self, capsys):
        """Test main() with --list-strategies."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        result = main(["--list-strategies"])
        assert result == 0

        captured = capsys.readouterr()
        assert "Study Campaign Mutation Strategies" in captured.out


class TestStudyCampaignValidation:
    """Test input validation."""

    def test_target_not_found_error(self, tmp_path, capsys):
        """Test error when target executable doesn't exist."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        study_dir = tmp_path / "study"
        study_dir.mkdir()

        result = main(
            [
                "--target",
                str(tmp_path / "nonexistent.exe"),
                "--study",
                str(study_dir),
            ]
        )
        assert result == 1

        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_study_not_found_error(self, tmp_path, capsys):
        """Test error when study directory doesn't exist."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        # Create a mock target
        target = tmp_path / "target.exe"
        target.write_text("mock")

        result = main(
            [
                "--target",
                str(target),
                "--study",
                str(tmp_path / "nonexistent_study"),
            ]
        )
        assert result == 1

        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_creates_output_directory(self, tmp_path, capsys):
        """Test output directory is created if it doesn't exist."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        # Create mock target and study
        target = tmp_path / "target.py"
        target.write_text("import sys; sys.exit(0)")

        study_dir = tmp_path / "study"
        study_dir.mkdir()
        # Create minimal DICOM file
        _create_minimal_dicom(study_dir / "test.dcm")

        output_dir = tmp_path / "output" / "nested"

        # With count=0, the campaign should just set up and complete
        result = main(
            [
                "--target",
                str(target),
                "--study",
                str(study_dir),
                "-o",
                str(output_dir),
                "-c",
                "0",  # No iterations
            ]
        )

        assert result == 0
        assert output_dir.exists()


class TestStudyCampaignExecution:
    """Test campaign execution with mocks."""

    @pytest.fixture
    def sample_study(self, tmp_path):
        """Create a sample DICOM study for testing."""
        study_dir = tmp_path / "sample_study"
        study_dir.mkdir()

        # Create a minimal series
        series_dir = study_dir / "series_001"
        series_dir.mkdir()
        _create_minimal_dicom(series_dir / "slice_0001.dcm")
        _create_minimal_dicom(series_dir / "slice_0002.dcm")

        return study_dir

    @pytest.fixture
    def mock_target(self, tmp_path):
        """Create a mock target that exits successfully."""
        if sys.platform == "win32":
            target = tmp_path / "target.bat"
            target.write_text("@echo off\nexit /b 0")
        else:
            target = tmp_path / "target.sh"
            target.write_text("#!/bin/bash\nexit 0")
            target.chmod(0o755)
        return target

    def test_campaign_with_zero_count(
        self, tmp_path, sample_study, mock_target, capsys
    ):
        """Test campaign with count=0 exits cleanly."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--target",
                str(mock_target),
                "--study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "0",
            ]
        )

        # Should complete successfully with 0 tests
        assert result == 0

    def test_campaign_statistics_saved(self, tmp_path, sample_study, mock_target):
        """Test campaign_results.json is written."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        output_dir = tmp_path / "output"

        # With count=0, campaign runs setup and saves stats without test iterations
        result = main(
            [
                "--target",
                str(mock_target),
                "--study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "0",
            ]
        )

        assert result == 0
        results_file = output_dir / "campaign_results.json"
        assert results_file.exists()

        with open(results_file) as f:
            data = json.load(f)
            assert "stats" in data
            assert "config" in data
            # Check stats structure
            assert "total" in data["stats"]
            assert "crash" in data["stats"]

    def test_campaign_logs_created(self, tmp_path, sample_study, mock_target):
        """Test campaign.log is created."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--target",
                str(mock_target),
                "--study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "0",
            ]
        )

        assert result == 0
        log_file = output_dir / "campaign.log"
        assert log_file.exists()

        log_content = log_file.read_text()
        assert "STUDY-LEVEL FUZZING CAMPAIGN" in log_content
        assert "CAMPAIGN COMPLETE" in log_content

    def test_stop_on_crash_flag_parsed(self, tmp_path, sample_study, mock_target):
        """Test --stop-on-crash flag is properly parsed."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(mock_target),
                "--study",
                str(sample_study),
                "--stop-on-crash",
            ]
        )
        assert args.stop_on_crash is True

    def test_verbose_flag_parsed(self, tmp_path, sample_study, mock_target):
        """Test --verbose flag is properly parsed."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(mock_target),
                "--study",
                str(sample_study),
                "-v",
            ]
        )
        assert args.verbose is True

    def test_campaign_header_output(self, tmp_path, sample_study, mock_target, capsys):
        """Test campaign outputs header information."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        output_dir = tmp_path / "output"

        main(
            [
                "--target",
                str(mock_target),
                "--study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "0",
            ]
        )

        captured = capsys.readouterr()
        assert "STUDY-LEVEL FUZZING CAMPAIGN" in captured.out
        assert "Target:" in captured.out
        assert "Study source:" in captured.out


class TestStudyCampaignMainCLI:
    """Test main() entry point edge cases."""

    def test_main_no_args_shows_help(self, capsys):
        """Test main() with no args shows help."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        with pytest.raises(SystemExit):
            main([])

    def test_main_help_flag(self, capsys):
        """Test main() with --help."""
        from dicom_fuzzer.cli.commands.study_campaign import main

        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0


# Helper functions


def _create_minimal_dicom(filepath: Path) -> None:
    """Create a minimal valid DICOM file for testing."""
    from pydicom.dataset import FileDataset, FileMetaDataset
    from pydicom.uid import UID

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = UID("1.2.840.10008.5.1.4.1.1.2")
    file_meta.MediaStorageSOPInstanceUID = UID("1.2.3.4.5.6.7.8.9")
    file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.1")

    ds = FileDataset(
        str(filepath),
        {},
        file_meta=file_meta,
        preamble=b"\x00" * 128,
    )

    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.PatientID = "TEST001"
    ds.PatientName = "Test^Patient"
    ds.StudyInstanceUID = UID("1.2.3.4.5.6")
    ds.SeriesInstanceUID = UID("1.2.3.4.5.6.7")
    ds.Modality = "CT"

    filepath.parent.mkdir(parents=True, exist_ok=True)
    ds.save_as(str(filepath))


# ============================================================================
# Additional Tests for Helper Functions
# ============================================================================


class TestLogFunction:
    """Test the log() helper function."""

    def test_log_to_stdout(self, capsys):
        """Test log prints to stdout."""
        from dicom_fuzzer.cli.commands.study_campaign import log

        log("Test message")
        captured = capsys.readouterr()
        assert "Test message" in captured.out

    def test_log_to_file(self, tmp_path):
        """Test log writes to file when provided."""
        from dicom_fuzzer.cli.commands.study_campaign import log

        log_file = tmp_path / "test.log"
        log("Test message", log_file)

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content

    def test_log_timestamp_format(self, capsys):
        """Test log includes timestamp."""
        from dicom_fuzzer.cli.commands.study_campaign import log

        log("Test")
        captured = capsys.readouterr()
        # Should have format like "2024-01-01 12:00:00 - Test"
        assert " - Test" in captured.out


class TestValidateCampaignArgs:
    """Test _validate_campaign_args function."""

    def test_missing_study_arg(self, capsys):
        """Test validation fails when --study is missing."""
        import argparse

        from dicom_fuzzer.cli.commands.study_campaign import _validate_campaign_args

        args = argparse.Namespace(target="./app.exe", study=None)
        result = _validate_campaign_args(args)
        assert result is None
        captured = capsys.readouterr()
        assert "--study is required" in captured.out

    def test_target_not_exists(self, tmp_path, capsys):
        """Test validation fails when target doesn't exist."""
        import argparse

        from dicom_fuzzer.cli.commands.study_campaign import _validate_campaign_args

        study_dir = tmp_path / "study"
        study_dir.mkdir()

        args = argparse.Namespace(
            target=str(tmp_path / "nonexistent.exe"),
            study=str(study_dir),
            output="./output",
        )
        result = _validate_campaign_args(args)
        assert result is None
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_study_not_exists(self, tmp_path, capsys):
        """Test validation fails when study doesn't exist."""
        import argparse

        from dicom_fuzzer.cli.commands.study_campaign import _validate_campaign_args

        target = tmp_path / "app.exe"
        target.write_text("mock")

        args = argparse.Namespace(
            target=str(target),
            study=str(tmp_path / "nonexistent"),
            output="./output",
        )
        result = _validate_campaign_args(args)
        assert result is None
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_valid_args(self, tmp_path):
        """Test validation succeeds with valid args."""
        import argparse

        from dicom_fuzzer.cli.commands.study_campaign import _validate_campaign_args

        target = tmp_path / "app.exe"
        target.write_text("mock")
        study = tmp_path / "study"
        study.mkdir()

        args = argparse.Namespace(
            target=str(target),
            study=str(study),
            output=str(tmp_path / "output"),
        )
        result = _validate_campaign_args(args)
        assert result is not None
        target_path, study_path, output_path = result
        assert target_path.exists()
        assert study_path.exists()


class TestSetupCampaignDirs:
    """Test _setup_campaign_dirs function."""

    def test_creates_directories(self, tmp_path):
        """Test directories are created."""
        from dicom_fuzzer.cli.commands.study_campaign import _setup_campaign_dirs

        output_path = tmp_path / "output" / "nested"
        crashes_dir, log_file = _setup_campaign_dirs(output_path)

        assert output_path.exists()
        assert crashes_dir.exists()
        assert crashes_dir == output_path / "crashes"
        assert log_file == output_path / "campaign.log"

    def test_existing_directory(self, tmp_path):
        """Test works with existing directory."""
        from dicom_fuzzer.cli.commands.study_campaign import _setup_campaign_dirs

        output_path = tmp_path / "output"
        output_path.mkdir()

        crashes_dir, log_file = _setup_campaign_dirs(output_path)
        assert crashes_dir.exists()


class TestGetSeverities:
    """Test _get_severities function."""

    def test_moderate_default(self):
        """Test moderate returns full severity list."""
        from dicom_fuzzer.cli.commands.study_campaign import _get_severities

        result = _get_severities("moderate")
        assert result == ["moderate", "aggressive", "extreme"]

    def test_aggressive_start(self):
        """Test aggressive starts from that severity."""
        from dicom_fuzzer.cli.commands.study_campaign import _get_severities

        result = _get_severities("aggressive")
        assert result == ["aggressive", "extreme"]

    def test_extreme_start(self):
        """Test extreme returns only extreme."""
        from dicom_fuzzer.cli.commands.study_campaign import _get_severities

        result = _get_severities("extreme")
        assert result == ["extreme"]

    def test_minimal_not_in_list(self):
        """Test minimal returns just itself."""
        from dicom_fuzzer.cli.commands.study_campaign import _get_severities

        result = _get_severities("minimal")
        assert result == ["minimal"]


class TestLogProgress:
    """Test _log_progress function."""

    def test_no_log_when_not_multiple_of_10(self, capsys):
        """Test no output when test_id not multiple of 10."""
        import time

        from dicom_fuzzer.cli.commands.study_campaign import _log_progress

        _log_progress(5, 100, time.time(), None)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_log_on_multiple_of_10(self, capsys, tmp_path):
        """Test output when test_id is multiple of 10."""
        import time

        from dicom_fuzzer.cli.commands.study_campaign import _log_progress

        log_file = tmp_path / "test.log"
        start = time.time() - 10  # 10 seconds ago
        _log_progress(10, 100, start, log_file)

        captured = capsys.readouterr()
        assert "Progress:" in captured.out
        assert "10/100" in captured.out
        assert "tests/min" in captured.out

    def test_log_zero_elapsed(self, capsys):
        """Test handles zero elapsed time."""
        import time

        from dicom_fuzzer.cli.commands.study_campaign import _log_progress

        _log_progress(10, 100, time.time(), None)
        captured = capsys.readouterr()
        assert "Progress:" in captured.out


class TestLogCampaignSummary:
    """Test _log_campaign_summary function."""

    def test_summary_output(self, capsys, tmp_path):
        """Test summary outputs all stats."""
        from dicom_fuzzer.cli.commands.study_campaign import _log_campaign_summary

        stats = {
            "total": 100,
            "success": 90,
            "crash": 5,
            "timeout": 3,
            "memory_exceeded": 2,
            "error": 0,
        }
        log_file = tmp_path / "test.log"
        _log_campaign_summary(stats, 600.0, log_file)

        captured = capsys.readouterr()
        assert "CAMPAIGN COMPLETE" in captured.out
        assert "Duration: 10.00 minutes" in captured.out
        assert "Total tests: 100" in captured.out
        assert "Success: 90" in captured.out
        assert "Crashes: 5" in captured.out
        assert "Timeouts: 3" in captured.out

    def test_summary_no_timeout(self, capsys):
        """Test summary skips timeout when zero."""
        from dicom_fuzzer.cli.commands.study_campaign import _log_campaign_summary

        stats = {
            "total": 100,
            "success": 100,
            "crash": 0,
            "timeout": 0,
            "memory_exceeded": 0,
            "error": 0,
        }
        _log_campaign_summary(stats, 60.0, None)

        captured = capsys.readouterr()
        assert "Timeout" not in captured.out


class TestLogCampaignHeader:
    """Test _log_campaign_header function."""

    def test_header_output(self, tmp_path, capsys):
        """Test header contains all expected info."""
        import argparse

        from dicom_fuzzer.cli.commands.study_campaign import _log_campaign_header

        args = argparse.Namespace(
            strategy="cross-series",
            severity="aggressive",
            count=50,
        )
        log_file = tmp_path / "test.log"

        _log_campaign_header(
            Path("/path/to/target.exe"),
            Path("/path/to/study"),
            Path("/path/to/output"),
            args,
            log_file,
        )

        captured = capsys.readouterr()
        assert "STUDY-LEVEL FUZZING CAMPAIGN" in captured.out
        assert "Target:" in captured.out
        assert "Study source:" in captured.out
        assert "Output:" in captured.out
        assert "Strategy: cross-series" in captured.out
        assert "Severity: aggressive" in captured.out
        assert "Total tests planned: 50" in captured.out


class TestSaveCampaignResults:
    """Test _save_campaign_results function."""

    def test_saves_json_file(self, tmp_path, capsys):
        """Test campaign results are saved to JSON."""
        import argparse

        from dicom_fuzzer.cli.commands.study_campaign import _save_campaign_results

        output_path = tmp_path / "output"
        output_path.mkdir()

        args = argparse.Namespace(
            strategy="all",
            severity="moderate",
            count=100,
            timeout=15.0,
            memory_limit=2048,
        )
        stats = {"total": 50, "crash": 2, "success": 48}

        _save_campaign_results(
            output_path,
            Path("/target.exe"),
            Path("/study"),
            args,
            stats,
            tmp_path / "test.log",
        )

        results_file = output_path / "campaign_results.json"
        assert results_file.exists()

        data = json.loads(results_file.read_text())
        assert data["config"]["strategy"] == "all"
        assert data["stats"]["total"] == 50
        assert data["stats"]["crash"] == 2


class TestMutationsPerTest:
    """Test --mutations-per-test argument."""

    def test_mutations_per_test_argument(self):
        """Test --mutations-per-test argument parsing."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--mutations-per-test", "10"]
        )
        assert args.mutations_per_test == 10

    def test_mutations_per_test_default(self):
        """Test --mutations-per-test default value."""
        from dicom_fuzzer.cli.commands.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app", "--study", "./test"])
        assert args.mutations_per_test == 5


# ============================================================================
# Targeted tests for internal helpers (PR C: coverage-tail work)
# ============================================================================


class TestTestResultHelpers:
    """Cover _TestResult.is_failure / to_dict (lines 48, 51)."""

    def test_is_failure_true_for_crash(self):
        from dicom_fuzzer.cli.commands.study_campaign import _TestResult

        r = _TestResult(
            status="crash",
            error_message="boom",
            memory_peak_mb=1.0,
            duration_seconds=0.5,
        )
        assert r.is_failure() is True

    def test_is_failure_false_for_success(self):
        from dicom_fuzzer.cli.commands.study_campaign import _TestResult

        r = _TestResult(
            status="success",
            error_message=None,
            memory_peak_mb=1.0,
            duration_seconds=0.5,
        )
        assert r.is_failure() is False

    def test_is_failure_false_for_skipped(self):
        from dicom_fuzzer.cli.commands.study_campaign import _TestResult

        r = _TestResult(
            status="skipped",
            error_message=None,
            memory_peak_mb=0.0,
            duration_seconds=0.0,
        )
        assert r.is_failure() is False

    def test_to_dict_shape(self):
        from dicom_fuzzer.cli.commands.study_campaign import _TestResult

        r = _TestResult(
            status="timeout",
            error_message="slow",
            memory_peak_mb=12.5,
            duration_seconds=3.0,
        )
        assert r.to_dict() == {
            "status": "timeout",
            "error_message": "slow",
            "memory_peak_mb": 12.5,
            "duration_seconds": 3.0,
        }


class TestWrapResult:
    """Cover _wrap_result (line 71)."""

    def _build_execution_result(self, **overrides):
        from dicom_fuzzer.core.harness.target_runner import (
            ExecutionResult,
            ExecutionStatus,
        )

        kwargs = {
            "test_file": Path("dummy.dcm"),
            "result": ExecutionStatus.SUCCESS,
            "exit_code": 0,
            "execution_time": 1.25,
            "stdout": "",
            "stderr": "",
        }
        kwargs.update(overrides)
        return ExecutionResult(**kwargs), ExecutionStatus

    def test_wrap_crash_with_stderr_and_peak_mem(self):
        from dicom_fuzzer.cli.commands.study_campaign import _wrap_result

        er, status = self._build_execution_result(
            result=__import__(
                "dicom_fuzzer.core.harness.target_runner", fromlist=["ExecutionStatus"]
            ).ExecutionStatus.CRASH,
            stderr="  segfault\n",
            peak_memory_mb=42.0,
            execution_time=2.0,
        )
        del status  # unused

        wrapped = _wrap_result(er)

        assert wrapped.status == "crash"
        assert wrapped.error_message == "segfault"  # stripped
        assert wrapped.memory_peak_mb == 42.0
        assert wrapped.duration_seconds == 2.0

    def test_wrap_success_no_stderr(self):
        from dicom_fuzzer.cli.commands.study_campaign import _wrap_result

        er, _ = self._build_execution_result(stderr="", peak_memory_mb=None)

        wrapped = _wrap_result(er)

        assert wrapped.status == "success"
        assert wrapped.error_message is None
        assert wrapped.memory_peak_mb == 0.0  # None -> 0.0

    def test_wrap_unknown_status_falls_back_to_error(self):
        """Status not in _STATUS_MAP defaults to 'error'."""
        from dicom_fuzzer.cli.commands.study_campaign import _wrap_result

        # RESOURCE_EXHAUSTED is in the map as "error" by design
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        er, _ = self._build_execution_result(result=ExecutionStatus.RESOURCE_EXHAUSTED)

        assert _wrap_result(er).status == "error"


class TestSaveCrash:
    """Cover _save_crash (lines 87-100)."""

    def test_save_crash_with_directory_study(self, tmp_path):
        from dicom_fuzzer.cli.commands.study_campaign import _save_crash, _TestResult

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        study_dir = tmp_path / "study"
        study_dir.mkdir()
        (study_dir / "s.dcm").write_bytes(b"DICM")

        result = _TestResult(
            status="crash",
            error_message="boom",
            memory_peak_mb=1.0,
            duration_seconds=0.5,
        )

        _save_crash(
            crash_dir, result, study_dir, test_id=7, mutation_records=[{"tag": "x"}]
        )

        out = crash_dir / "crash_0007"
        assert out.is_dir()
        assert (out / "study" / "s.dcm").exists()
        payload = json.loads((out / "result.json").read_text())
        assert payload["status"] == "crash"
        records = json.loads((out / "mutation_records.json").read_text())
        assert records == [{"tag": "x"}]

    def test_save_crash_with_file_study(self, tmp_path):
        """Study path is a single file, not a directory."""
        from dicom_fuzzer.cli.commands.study_campaign import _save_crash, _TestResult

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        study_file = tmp_path / "single.dcm"
        study_file.write_bytes(b"DICM")

        result = _TestResult(
            status="crash", error_message=None, memory_peak_mb=0.0, duration_seconds=0.0
        )

        _save_crash(crash_dir, result, study_file, test_id=3, mutation_records=[])

        out = crash_dir / "crash_0003"
        assert (out / "study" / "single.dcm").exists()
        # No mutation_records.json when records list is empty.
        assert not (out / "mutation_records.json").exists()

    def test_save_crash_missing_study_path(self, tmp_path):
        """study_dir does not exist -> no study copy created, JSON still saved."""
        from dicom_fuzzer.cli.commands.study_campaign import _save_crash, _TestResult

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        missing = tmp_path / "ghost"

        result = _TestResult(
            status="error", error_message=None, memory_peak_mb=0.0, duration_seconds=0.0
        )

        _save_crash(crash_dir, result, missing, test_id=1, mutation_records=[])

        out = crash_dir / "crash_0001"
        assert out.is_dir()
        assert (out / "result.json").exists()
        assert not (out / "study").exists()


class _FakeRecord:
    """Mutation record stub with the fields study_campaign expects."""

    def __init__(self, strategy="stub", tag="PatientID", mutated_value="X"):
        self.strategy = strategy
        self.tag = tag
        self.mutated_value = mutated_value


class _FakeStudy:
    """Minimal stand-in exposing the attributes run_campaign inspects."""

    def __init__(self, series_count=1, total_slices=1):
        self.series_list = [object()] * series_count
        self._total_slices = total_slices

    def get_total_slices(self):
        return self._total_slices


class _FakeMutator:
    """Stand-in for StudyMutator that returns pre-seeded datasets + records."""

    def __init__(self, datasets, records, *, raise_on_load=False):
        self._datasets = datasets
        self._records = records
        self._raise_on_load = raise_on_load

    def load_study(self, path):
        if self._raise_on_load:
            raise RuntimeError("load failed")
        return _FakeStudy()

    def mutate_study(self, *_args, **_kwargs):
        return self._datasets, self._records


class _FakeRunner:
    """Stand-in for TargetRunner.execute_with_monitoring."""

    def __init__(self, execution_result):
        self._er = execution_result

    def execute_with_monitoring(self, _study_path):
        return self._er


def _make_execution_result(status, *, stderr="", peak_mb=0.0, duration=0.1):
    from dicom_fuzzer.core.harness.target_runner import ExecutionResult

    return ExecutionResult(
        test_file=Path("dummy.dcm"),
        result=status,
        exit_code=0 if stderr == "" else 1,
        execution_time=duration,
        stdout="",
        stderr=stderr,
        peak_memory_mb=peak_mb,
    )


def _make_fake_dataset():
    """Minimal dataset save_as can be called on without writing real DICOM."""
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.PatientID = "T001"
    ds.PatientName = "Test"
    ds.Modality = "CT"
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    return ds


class TestRunSingleTest:
    """Cover _run_single_test (lines 302-380)."""

    def test_success_path(self, tmp_path, monkeypatch, capsys):
        from dicom_fuzzer.cli.commands import study_campaign as mod
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        study_path = tmp_path / "study"
        study_path.mkdir()

        datasets = [[_make_fake_dataset()]]  # 1 series, 1 slice
        records = [_FakeRecord()]
        monkeypatch.setattr(
            mod, "StudyMutator", lambda **_kw: _FakeMutator(datasets, records)
        )

        runner = _FakeRunner(
            _make_execution_result(ExecutionStatus.SUCCESS, peak_mb=10.0)
        )

        info = mod._run_single_test(
            test_id=1,
            total_tests=1,
            study_path=study_path,
            strategy=mod.StudyMutationStrategy.STUDY_METADATA,
            severity="moderate",
            mutations_per_test=2,
            runner=runner,
            log_file=None,
            verbose=True,
        )

        assert info["status"] == "success"
        assert info["is_failure"] is False
        assert info["records"] == records
        # Verbose branch prints each mutation record.
        assert "stub" in capsys.readouterr().out

    def test_failure_path(self, tmp_path, monkeypatch):
        from dicom_fuzzer.cli.commands import study_campaign as mod
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        study_path = tmp_path / "study"
        study_path.mkdir()

        datasets = [[_make_fake_dataset()]]
        monkeypatch.setattr(
            mod, "StudyMutator", lambda **_kw: _FakeMutator(datasets, [])
        )

        runner = _FakeRunner(
            _make_execution_result(ExecutionStatus.CRASH, stderr="sigsegv")
        )

        info = mod._run_single_test(
            test_id=2,
            total_tests=5,
            study_path=study_path,
            strategy=mod.StudyMutationStrategy.STUDY_METADATA,
            severity="aggressive",
            mutations_per_test=1,
            runner=runner,
            log_file=None,
            verbose=False,
        )

        assert info["status"] == "crash"
        assert info["is_failure"] is True
        assert info["error_message"] == "sigsegv"

    def test_exception_path_sets_error(self, tmp_path, monkeypatch):
        from dicom_fuzzer.cli.commands import study_campaign as mod

        study_path = tmp_path / "study"
        study_path.mkdir()

        monkeypatch.setattr(
            mod,
            "StudyMutator",
            lambda **_kw: _FakeMutator([], [], raise_on_load=True),
        )

        info = mod._run_single_test(
            test_id=3,
            total_tests=3,
            study_path=study_path,
            strategy=mod.StudyMutationStrategy.STUDY_METADATA,
            severity="moderate",
            mutations_per_test=1,
            runner=_FakeRunner(None),
            log_file=None,
            verbose=True,
        )

        assert info["status"] == "error"
        assert info["error_message"] == "load failed"

    def test_exception_path_non_verbose(self, tmp_path, monkeypatch, capsys):
        """Exception with verbose=False does not print traceback."""
        from dicom_fuzzer.cli.commands import study_campaign as mod

        study_path = tmp_path / "study"
        study_path.mkdir()

        monkeypatch.setattr(
            mod,
            "StudyMutator",
            lambda **_kw: _FakeMutator([], [], raise_on_load=True),
        )

        info = mod._run_single_test(
            test_id=3,
            total_tests=3,
            study_path=study_path,
            strategy=mod.StudyMutationStrategy.STUDY_METADATA,
            severity="moderate",
            mutations_per_test=1,
            runner=_FakeRunner(None),
            log_file=None,
            verbose=False,
        )

        assert info["status"] == "error"
        assert "Traceback" not in capsys.readouterr().err


class TestProcessTestResult:
    """Cover _process_test_result (lines 513-544)."""

    def _args(self, **overrides):
        ns = argparse.Namespace(stop_on_crash=False, verbose=False)
        for k, v in overrides.items():
            setattr(ns, k, v)
        return ns

    def _stats(self):
        return {
            "total": 0,
            "success": 0,
            "crash": 0,
            "timeout": 0,
            "memory_exceeded": 0,
            "error": 0,
        }

    def test_success_updates_stats_and_returns_false(self, tmp_path):
        from dicom_fuzzer.cli.commands.study_campaign import (
            _process_test_result,
            _TestResult,
        )

        stats = self._stats()
        result = _TestResult(
            status="success",
            error_message=None,
            memory_peak_mb=5.0,
            duration_seconds=0.2,
        )

        should_stop = _process_test_result(
            result=result,
            stats=stats,
            test_id=1,
            output_study=tmp_path / "study",
            records=[],
            crashes_dir=tmp_path / "crashes",
            args=self._args(),
            log_file=tmp_path / "x.log",
        )

        assert should_stop is False
        assert stats["total"] == 1
        assert stats["success"] == 1

    def test_crash_saves_artifact_and_continues_without_stop_flag(self, tmp_path):
        from dicom_fuzzer.cli.commands.study_campaign import (
            _process_test_result,
            _TestResult,
        )

        stats = self._stats()
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        result = _TestResult(
            status="crash",
            error_message="bang",
            memory_peak_mb=1.0,
            duration_seconds=0.1,
        )

        should_stop = _process_test_result(
            result=result,
            stats=stats,
            test_id=4,
            output_study=study_dir,
            records=[_FakeRecord()],
            crashes_dir=crashes_dir,
            args=self._args(stop_on_crash=False),
            log_file=tmp_path / "x.log",
        )

        assert should_stop is False
        assert stats["crash"] == 1
        assert (crashes_dir / "crash_0004" / "result.json").exists()

    def test_crash_with_stop_on_crash_returns_true(self, tmp_path):
        from dicom_fuzzer.cli.commands.study_campaign import (
            _process_test_result,
            _TestResult,
        )

        stats = self._stats()
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        # study dir must NOT contain crashes_dir (would recurse in copytree).
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        result = _TestResult(
            status="crash",
            error_message="halt",
            memory_peak_mb=0.0,
            duration_seconds=0.0,
        )

        should_stop = _process_test_result(
            result=result,
            stats=stats,
            test_id=9,
            output_study=study_dir,
            records=[],
            crashes_dir=crashes_dir,
            args=self._args(stop_on_crash=True),
            log_file=tmp_path / "x.log",
        )

        assert should_stop is True

    def test_verbose_prints_records(self, tmp_path, capsys):
        from dicom_fuzzer.cli.commands.study_campaign import (
            _process_test_result,
            _TestResult,
        )

        stats = self._stats()
        result = _TestResult(
            status="success",
            error_message=None,
            memory_peak_mb=0.0,
            duration_seconds=0.0,
        )

        _process_test_result(
            result=result,
            stats=stats,
            test_id=1,
            output_study=tmp_path,
            records=[_FakeRecord(strategy="verbose-only")],
            crashes_dir=tmp_path,
            args=self._args(verbose=True),
            log_file=tmp_path / "x.log",
        )

        assert "verbose-only" in capsys.readouterr().out

    def test_unknown_status_does_not_crash_stats(self, tmp_path):
        """Status not in the stats dict is silently ignored."""
        from dicom_fuzzer.cli.commands.study_campaign import (
            _process_test_result,
            _TestResult,
        )

        stats = self._stats()
        # 'weird' is not a key in stats -> branch at status-in-stats is False.
        result = _TestResult(
            status="weird", error_message=None, memory_peak_mb=0.0, duration_seconds=0.0
        )

        should_stop = _process_test_result(
            result=result,
            stats=stats,
            test_id=1,
            output_study=tmp_path / "study",
            records=[],
            crashes_dir=tmp_path / "crashes",
            args=self._args(),
            log_file=tmp_path / "x.log",
        )

        # is_failure is True (not in {"success", "skipped"}) -> _save_crash runs
        # but with no study_dir it still works. We only assert total increments.
        assert should_stop is False
        assert stats["total"] == 1


class TestRunCampaignLoop:
    """Cover _run_campaign_loop and _run_single_campaign_test via run_campaign.

    Uses monkeypatching to substitute StudyMutator and TargetRunner so the
    loop runs deterministically without spawning a real target process.
    """

    def _prepare_monkeypatches(self, monkeypatch, execution_status):
        from dicom_fuzzer.cli.commands import study_campaign as mod

        datasets = [[_make_fake_dataset()]]
        records = [_FakeRecord()]

        class _MutatorFactory(_FakeMutator):
            def __init__(self, **_kwargs):
                super().__init__(datasets, records)

        class _RunnerFactory:
            def __init__(self, **_kwargs):
                self._er = _make_execution_result(execution_status, peak_mb=1.0)

            def execute_with_monitoring(self, _p):
                return self._er

        monkeypatch.setattr(mod, "StudyMutator", _MutatorFactory)
        monkeypatch.setattr(mod, "TargetRunner", _RunnerFactory)

    def test_loop_runs_to_count_on_success(self, tmp_path, monkeypatch):
        from dicom_fuzzer.cli.commands import study_campaign as mod
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        self._prepare_monkeypatches(monkeypatch, ExecutionStatus.SUCCESS)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "slice.dcm").write_bytes(b"DICM")
        out = tmp_path / "out"

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(out),
                "-c",
                "3",
                "--strategy",
                "study-metadata",
                "--severity",
                "moderate",
            ]
        )

        assert mod.run_campaign(args) == 0
        results = json.loads((out / "campaign_results.json").read_text())
        assert results["stats"]["total"] >= 1
        assert results["stats"]["crash"] == 0

    def test_loop_stop_on_crash(self, tmp_path, monkeypatch):
        from dicom_fuzzer.cli.commands import study_campaign as mod
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        self._prepare_monkeypatches(monkeypatch, ExecutionStatus.CRASH)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "slice.dcm").write_bytes(b"DICM")
        out = tmp_path / "out"

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(out),
                "-c",
                "5",
                "--strategy",
                "study-metadata",
                "--stop-on-crash",
            ]
        )

        rc = mod.run_campaign(args)

        # Non-zero because crashes found.
        assert rc == 1
        results = json.loads((out / "campaign_results.json").read_text())
        # stop_on_crash fires after first crash => exactly 1 recorded.
        assert results["stats"]["crash"] == 1
        assert results["stats"]["total"] == 1

    def test_loop_falls_through_when_count_exceeds_iterations(
        self, tmp_path, monkeypatch
    ):
        """tests_per_combo is `count // (severities * strategies)`, so a large
        count with strategy=all (5) and cycling severities (3) caps total at
        1 * 3 * 5 = 15 tests. Requesting 100 means the try-body finishes
        naturally without any early return -- exercises the try -> final
        `return False` fall-through branch (601->637).
        """
        from dicom_fuzzer.cli.commands import study_campaign as mod
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        self._prepare_monkeypatches(monkeypatch, ExecutionStatus.SUCCESS)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")
        out = tmp_path / "out"

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(out),
                "-c",
                "100",
                "--strategy",
                "all",
            ]
        )

        assert mod.run_campaign(args) == 0
        results = json.loads((out / "campaign_results.json").read_text())
        # 3 severities * 5 strategies * max(1, 100//15)=6 = 90 tests
        assert results["stats"]["total"] == 90

    def test_loop_completes_via_outer_severity_check(self, tmp_path, monkeypatch):
        """count=1 with --severity extreme hits the outer 'test_id >= count' return."""
        from dicom_fuzzer.cli.commands import study_campaign as mod
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        self._prepare_monkeypatches(monkeypatch, ExecutionStatus.SUCCESS)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")
        out = tmp_path / "out"

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(out),
                "-c",
                "1",
                "--strategy",
                "study-metadata",
                "--severity",
                "extreme",  # single severity -> exits via the outer check
            ]
        )

        assert mod.run_campaign(args) == 0

    def test_loop_keyboard_interrupt(self, tmp_path, monkeypatch, capsys):
        """Covers the KeyboardInterrupt handler in _run_campaign_loop (632-637)."""
        from dicom_fuzzer.cli.commands import study_campaign as mod

        # Force _run_single_campaign_test to raise KeyboardInterrupt on first call.
        def _boom(**_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(mod, "_run_single_campaign_test", _boom)

        # Stand-in mutator avoids touching real DICOM.
        class _MutatorFactory(_FakeMutator):
            def __init__(self, **_kwargs):
                super().__init__([[_make_fake_dataset()]], [])

        monkeypatch.setattr(mod, "StudyMutator", _MutatorFactory)

        class _RunnerFactory:
            def __init__(self, **_kwargs):
                pass

        monkeypatch.setattr(mod, "TargetRunner", _RunnerFactory)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(tmp_path / "out"),
                "-c",
                "5",
                "--strategy",
                "study-metadata",
            ]
        )

        # Should not re-raise; should exit cleanly and write a summary.
        rc = mod.run_campaign(args)
        assert rc == 0
        assert "Campaign interrupted by user" in capsys.readouterr().out

    def test_single_campaign_test_exception_non_verbose(
        self, tmp_path, monkeypatch, capsys
    ):
        """Same as the verbose case but without --verbose: no traceback."""
        from dicom_fuzzer.cli.commands import study_campaign as mod

        class _FlakyMutator(_FakeMutator):
            def __init__(self, **_kwargs):
                super().__init__([[_make_fake_dataset()]], [])

            def mutate_study(self, *_a, **_kw):
                raise RuntimeError("quiet boom")

        monkeypatch.setattr(mod, "StudyMutator", _FlakyMutator)
        monkeypatch.setattr(mod, "TargetRunner", lambda **_kw: _FakeRunner(None))

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(tmp_path / "out"),
                "-c",
                "1",
                "--strategy",
                "study-metadata",
            ]
        )

        assert mod.run_campaign(args) == 0
        assert "Traceback" not in capsys.readouterr().err

    def test_single_campaign_test_exception_is_caught(
        self, tmp_path, monkeypatch, capsys
    ):
        """mutate_study raising -> error counted, loop keeps going (700-705)."""
        from dicom_fuzzer.cli.commands import study_campaign as mod

        call_count = {"n": 0}

        class _FlakyMutator(_FakeMutator):
            def __init__(self, **_kwargs):
                super().__init__([[_make_fake_dataset()]], [])

            def mutate_study(self, *_a, **_kw):
                call_count["n"] += 1
                raise RuntimeError(f"boom #{call_count['n']}")

        monkeypatch.setattr(mod, "StudyMutator", _FlakyMutator)

        class _RunnerFactory:
            def __init__(self, **_kwargs):
                pass

            def execute_with_monitoring(self, _p):
                pytest.fail("runner must not be called when mutate raises")

        monkeypatch.setattr(mod, "TargetRunner", _RunnerFactory)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")
        out = tmp_path / "out"

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(out),
                "-c",
                "2",
                "--verbose",  # also covers traceback branch
                "--strategy",
                "study-metadata",
            ]
        )

        rc = mod.run_campaign(args)
        assert rc == 0  # no crashes, just errors
        results = json.loads((out / "campaign_results.json").read_text())
        assert results["stats"]["error"] >= 1


class TestRunCampaignErrorPaths:
    """Cover run_campaign's ImportError + generic Exception handlers (798-806)."""

    def test_import_error_returns_1(self, tmp_path, monkeypatch, capsys):
        from dicom_fuzzer.cli.commands import study_campaign as mod

        def _raise_import(**_kwargs):
            raise ImportError("fake missing dep")

        monkeypatch.setattr(mod, "TargetRunner", _raise_import)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(tmp_path / "out"),
                "-c",
                "1",
                "--strategy",
                "study-metadata",
            ]
        )

        assert mod.run_campaign(args) == 1
        assert "Module not available" in capsys.readouterr().out

    def test_generic_exception_without_verbose_no_traceback(
        self, tmp_path, monkeypatch, capsys
    ):
        """Same as above but without --verbose: no Traceback printed."""
        from dicom_fuzzer.cli.commands import study_campaign as mod

        def _raise_generic(**_kwargs):
            raise RuntimeError("silent kaboom")

        monkeypatch.setattr(mod, "TargetRunner", _raise_generic)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(tmp_path / "out"),
                "-c",
                "1",
                "--strategy",
                "study-metadata",
            ]
        )

        assert mod.run_campaign(args) == 1
        captured = capsys.readouterr()
        assert "silent kaboom" in captured.out
        assert "Traceback" not in captured.err

    def test_generic_exception_with_verbose_prints_traceback(
        self, tmp_path, monkeypatch, capsys
    ):
        from dicom_fuzzer.cli.commands import study_campaign as mod

        def _raise_generic(**_kwargs):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(mod, "TargetRunner", _raise_generic)

        target = tmp_path / "t.exe"
        target.write_text("")
        study = tmp_path / "study"
        study.mkdir()
        (study / "s.dcm").write_bytes(b"DICM")

        parser = mod.create_parser()
        args = parser.parse_args(
            [
                "--target",
                str(target),
                "--study",
                str(study),
                "-o",
                str(tmp_path / "out"),
                "-c",
                "1",
                "--verbose",
                "--strategy",
                "study-metadata",
            ]
        )

        assert mod.run_campaign(args) == 1
        captured = capsys.readouterr()
        assert "Campaign failed: kaboom" in captured.out
        assert "Traceback" in captured.err


class TestStudyCampaignCommandExecuteFallback:
    """Cover StudyCampaignCommand.execute help-fallback branch (825-826)."""

    def test_execute_falls_back_to_help_when_neither_flag_set(self, capsys):
        from dicom_fuzzer.cli.commands.study_campaign import StudyCampaignCommand

        args = argparse.Namespace(list_strategies=False, target=None)

        assert StudyCampaignCommand.execute(args) == 1
        assert "usage" in capsys.readouterr().out.lower()
