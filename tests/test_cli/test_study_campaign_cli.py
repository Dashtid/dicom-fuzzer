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
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "dicom-fuzzer study-campaign"

    def test_list_strategies_standalone(self):
        """Test --list-strategies works without other args."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--list-strategies"])
        assert args.list_strategies is True

    def test_required_arguments_target_or_list_strategies(self):
        """Test --target or --list-strategies is required."""
        from dicom_fuzzer.cli.study_campaign import create_parser

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
        from dicom_fuzzer.cli.study_campaign import create_parser

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
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--target", "./app", "--study", "./test", "--strategy", "invalid"]
            )

    def test_severity_choices(self):
        """Test valid severity choices are accepted."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()

        for severity in ["minimal", "moderate", "aggressive", "extreme"]:
            args = parser.parse_args(
                ["--target", "./app", "--study", "./test", "--severity", severity]
            )
            assert args.severity == severity

    def test_invalid_severity_rejected(self):
        """Test invalid severity is rejected."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--target", "./app", "--study", "./test", "--severity", "wrong"]
            )

    def test_default_values(self):
        """Test default values for optional arguments."""
        from dicom_fuzzer.cli.study_campaign import create_parser

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
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app", "--study", "./test", "-c", "50"])
        assert args.count == 50

    def test_timeout_argument(self):
        """Test --timeout argument."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--timeout", "30.0"]
        )
        assert args.timeout == 30.0

    def test_memory_limit_argument(self):
        """Test --memory-limit argument."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--memory-limit", "4096"]
        )
        assert args.memory_limit == 4096

    def test_startup_delay_argument(self):
        """Test --startup-delay argument."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--startup-delay", "5.0"]
        )
        assert args.startup_delay == 5.0

    def test_output_directory_argument(self):
        """Test -o/--output argument."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "-o", "./custom/output"]
        )
        assert args.output == "./custom/output"

    def test_stop_on_crash_flag(self):
        """Test --stop-on-crash flag."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--stop-on-crash"]
        )
        assert args.stop_on_crash is True

    def test_verbose_flag(self):
        """Test -v/--verbose flag."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app", "--study", "./test", "-v"])
        assert args.verbose is True


class TestStudyCampaignListStrategies:
    """Test --list-strategies functionality."""

    def test_list_strategies_output(self, capsys):
        """Test --list-strategies prints all strategies."""
        from dicom_fuzzer.cli.study_campaign import run_list_strategies

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
        from dicom_fuzzer.cli.study_campaign import main

        result = main(["--list-strategies"])
        assert result == 0

        captured = capsys.readouterr()
        assert "Study Campaign Mutation Strategies" in captured.out


class TestStudyCampaignValidation:
    """Test input validation."""

    def test_target_not_found_error(self, tmp_path, capsys):
        """Test error when target executable doesn't exist."""
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import create_parser

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
        from dicom_fuzzer.cli.study_campaign import create_parser

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
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import main

        with pytest.raises(SystemExit):
            main([])

    def test_main_help_flag(self, capsys):
        """Test main() with --help."""
        from dicom_fuzzer.cli.study_campaign import main

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
        from dicom_fuzzer.cli.study_campaign import log

        log("Test message")
        captured = capsys.readouterr()
        assert "Test message" in captured.out

    def test_log_to_file(self, tmp_path):
        """Test log writes to file when provided."""
        from dicom_fuzzer.cli.study_campaign import log

        log_file = tmp_path / "test.log"
        log("Test message", log_file)

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content

    def test_log_timestamp_format(self, capsys):
        """Test log includes timestamp."""
        from dicom_fuzzer.cli.study_campaign import log

        log("Test")
        captured = capsys.readouterr()
        # Should have format like "2024-01-01 12:00:00 - Test"
        assert " - Test" in captured.out


class TestListAdapters:
    """Test run_list_adapters function."""

    def test_list_adapters_basic(self, capsys):
        """Test run_list_adapters prints header."""
        from dicom_fuzzer.cli.study_campaign import run_list_adapters

        result = run_list_adapters()
        assert result == 0
        captured = capsys.readouterr()
        assert "Viewer Adapters" in captured.out

    def test_list_adapters_shows_install_hint(self, capsys):
        """Test list adapters shows pywinauto install hint when no adapters."""
        from dicom_fuzzer.cli.study_campaign import run_list_adapters

        result = run_list_adapters()
        assert result == 0
        captured = capsys.readouterr()
        # Either shows adapters or shows install hint
        assert "Viewer Adapters" in captured.out


class TestValidateCampaignArgs:
    """Test _validate_campaign_args function."""

    def test_missing_study_arg(self, capsys):
        """Test validation fails when --study is missing."""
        import argparse

        from dicom_fuzzer.cli.study_campaign import _validate_campaign_args

        args = argparse.Namespace(target="./app.exe", study=None)
        result = _validate_campaign_args(args)
        assert result is None
        captured = capsys.readouterr()
        assert "--study is required" in captured.out

    def test_target_not_exists(self, tmp_path, capsys):
        """Test validation fails when target doesn't exist."""
        import argparse

        from dicom_fuzzer.cli.study_campaign import _validate_campaign_args

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

        from dicom_fuzzer.cli.study_campaign import _validate_campaign_args

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

        from dicom_fuzzer.cli.study_campaign import _validate_campaign_args

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
        from dicom_fuzzer.cli.study_campaign import _setup_campaign_dirs

        output_path = tmp_path / "output" / "nested"
        crashes_dir, log_file = _setup_campaign_dirs(output_path)

        assert output_path.exists()
        assert crashes_dir.exists()
        assert crashes_dir == output_path / "crashes"
        assert log_file == output_path / "campaign.log"

    def test_existing_directory(self, tmp_path):
        """Test works with existing directory."""
        from dicom_fuzzer.cli.study_campaign import _setup_campaign_dirs

        output_path = tmp_path / "output"
        output_path.mkdir()

        crashes_dir, log_file = _setup_campaign_dirs(output_path)
        assert crashes_dir.exists()


class TestGetStrategies:
    """Test _get_strategies function."""

    def test_all_strategies(self):
        """Test 'all' returns all strategies."""
        from dicom_fuzzer.cli.study_campaign import _get_strategies

        strategy_map = {"a": 1, "b": 2, "c": 3}
        result = _get_strategies("all", strategy_map)
        assert result == [1, 2, 3]

    def test_single_strategy(self):
        """Test single strategy selection."""
        from dicom_fuzzer.cli.study_campaign import _get_strategies

        strategy_map = {"a": 1, "b": 2, "c": 3}
        result = _get_strategies("b", strategy_map)
        assert result == [2]


class TestGetSeverities:
    """Test _get_severities function."""

    def test_moderate_default(self):
        """Test moderate returns full severity list."""
        from dicom_fuzzer.cli.study_campaign import _get_severities

        result = _get_severities("moderate")
        assert result == ["moderate", "aggressive", "extreme"]

    def test_aggressive_start(self):
        """Test aggressive starts from that severity."""
        from dicom_fuzzer.cli.study_campaign import _get_severities

        result = _get_severities("aggressive")
        assert result == ["aggressive", "extreme"]

    def test_extreme_start(self):
        """Test extreme returns only extreme."""
        from dicom_fuzzer.cli.study_campaign import _get_severities

        result = _get_severities("extreme")
        assert result == ["extreme"]

    def test_minimal_not_in_list(self):
        """Test minimal returns just itself."""
        from dicom_fuzzer.cli.study_campaign import _get_severities

        result = _get_severities("minimal")
        assert result == ["minimal"]


class TestLogProgress:
    """Test _log_progress function."""

    def test_no_log_when_not_multiple_of_10(self, capsys):
        """Test no output when test_id not multiple of 10."""
        import time

        from dicom_fuzzer.cli.study_campaign import _log_progress

        _log_progress(5, 100, time.time(), None)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_log_on_multiple_of_10(self, capsys, tmp_path):
        """Test output when test_id is multiple of 10."""
        import time

        from dicom_fuzzer.cli.study_campaign import _log_progress

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

        from dicom_fuzzer.cli.study_campaign import _log_progress

        _log_progress(10, 100, time.time(), None)
        captured = capsys.readouterr()
        assert "Progress:" in captured.out


class TestLogCampaignSummary:
    """Test _log_campaign_summary function."""

    def test_summary_output(self, capsys, tmp_path):
        """Test summary outputs all stats."""
        from dicom_fuzzer.cli.study_campaign import _log_campaign_summary

        stats = {
            "total": 100,
            "success": 90,
            "crash": 5,
            "memory_exceeded": 2,
            "render_failed": 3,
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
        assert "Render failed: 3" in captured.out

    def test_summary_no_render_failed(self, capsys):
        """Test summary skips render_failed when zero."""
        from dicom_fuzzer.cli.study_campaign import _log_campaign_summary

        stats = {
            "total": 100,
            "success": 100,
            "crash": 0,
            "memory_exceeded": 0,
            "render_failed": 0,
            "error": 0,
        }
        _log_campaign_summary(stats, 60.0, None)

        captured = capsys.readouterr()
        assert "Render failed" not in captured.out


class TestSetupViewerAdapter:
    """Test _setup_viewer_adapter function."""

    def test_no_adapter_specified(self, tmp_path):
        """Test returns None when no adapter specified."""
        from dicom_fuzzer.cli.study_campaign import _setup_viewer_adapter

        log_file = tmp_path / "test.log"
        adapter, error = _setup_viewer_adapter(None, log_file)
        assert adapter is None
        assert error is None

    def test_adapter_value_error(self, tmp_path, monkeypatch, capsys):
        """Test handles ValueError when adapter not found."""
        from unittest.mock import MagicMock, patch

        from dicom_fuzzer.cli.study_campaign import _setup_viewer_adapter

        log_file = tmp_path / "test.log"

        # Create a mock module that raises ValueError on get_adapter
        mock_adapters = MagicMock()
        mock_adapters.get_adapter.side_effect = ValueError(
            "Unknown adapter: nonexistent"
        )

        # Patch the import by patching sys.modules
        with patch.dict("sys.modules", {"dicom_fuzzer.adapters": mock_adapters}):
            adapter, error = _setup_viewer_adapter("nonexistent", log_file)
            assert adapter is None
            assert error == 1

        # Check that error was logged (either to stdout or file)
        captured = capsys.readouterr()
        log_content = log_file.read_text() if log_file.exists() else ""
        assert "Unknown adapter" in captured.out or "Unknown adapter" in log_content


class TestLogCampaignHeader:
    """Test _log_campaign_header function."""

    def test_header_output(self, tmp_path, capsys):
        """Test header contains all expected info."""
        import argparse

        from dicom_fuzzer.cli.study_campaign import _log_campaign_header

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

        from dicom_fuzzer.cli.study_campaign import _save_campaign_results

        output_path = tmp_path / "output"
        output_path.mkdir()

        args = argparse.Namespace(
            strategy="all",
            severity="moderate",
            count=100,
            timeout=15.0,
            memory_limit=2048,
            adapter=None,
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


class TestMainListAdapters:
    """Test main() with --list-adapters."""

    def test_main_list_adapters(self, capsys):
        """Test main() with --list-adapters option."""
        from dicom_fuzzer.cli.study_campaign import main

        result = main(["--list-adapters"])
        assert result == 0

        captured = capsys.readouterr()
        assert "Viewer Adapters" in captured.out


class TestMutationsPerTest:
    """Test --mutations-per-test argument."""

    def test_mutations_per_test_argument(self):
        """Test --mutations-per-test argument parsing."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--mutations-per-test", "10"]
        )
        assert args.mutations_per_test == 10

    def test_mutations_per_test_default(self):
        """Test --mutations-per-test default value."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(["--target", "./app", "--study", "./test"])
        assert args.mutations_per_test == 5


class TestAdapterArguments:
    """Test adapter-related arguments."""

    def test_adapter_argument(self):
        """Test --adapter argument parsing."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--adapter", "affinity"]
        )
        assert args.adapter == "affinity"

    def test_series_name_argument(self):
        """Test --series-name argument parsing."""
        from dicom_fuzzer.cli.study_campaign import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--target", "./app", "--study", "./test", "--series-name", "CT Series 1"]
        )
        assert args.series_name == "CT Series 1"
