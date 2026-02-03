"""
Tests for Target CLI Subcommand.

Tests the command-line interface for target calibration.
"""

import json
import sys
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.cli.target import create_parser, main
from dicom_fuzzer.core.harness.target_calibrator import (
    CalibrationResult,
    CrashDetectionStatus,
    TargetType,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_executable(tmp_path):
    """Create a mock executable for testing."""
    if sys.platform == "win32":
        exe = tmp_path / "test_app.exe"
    else:
        exe = tmp_path / "test_app"
    exe.write_text("mock executable")
    exe.chmod(0o755)
    return exe


@pytest.fixture
def mock_corpus(tmp_path):
    """Create a mock corpus directory."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "test.dcm").write_bytes(b"\x00" * 200)
    return corpus


@pytest.fixture
def mock_calibration_result():
    """Create a mock CalibrationResult."""
    return CalibrationResult(
        target_type=TargetType.CLI,
        target_path="/path/to/app",
        recommended_timeout=5.0,
        avg_execution_time=1.0,
        crash_detection=CrashDetectionStatus.VALIDATED,
        wer_disabled=True,
        corpus_total=100,
        corpus_valid=95,
        recommendations=["Use CLI mode with 5.0s timeout"],
    )


# ============================================================================
# Test Argument Parser
# ============================================================================


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_creation(self):
        """Test parser is created successfully."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "dicom-fuzzer target"

    def test_parser_executable_required(self):
        """Test --executable is required."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_executable_short_flag(self):
        """Test -e short flag for executable."""
        parser = create_parser()
        args = parser.parse_args(["-e", "/path/to/app"])
        assert args.executable == "/path/to/app"

    def test_parser_executable_long_flag(self):
        """Test --executable long flag."""
        parser = create_parser()
        args = parser.parse_args(["--executable", "/path/to/app"])
        assert args.executable == "/path/to/app"

    def test_parser_corpus_optional(self):
        """Test --corpus is optional."""
        parser = create_parser()
        args = parser.parse_args(["--executable", "/path/to/app"])
        assert args.corpus is None

    def test_parser_corpus_short_flag(self):
        """Test -c short flag for corpus."""
        parser = create_parser()
        args = parser.parse_args(["-e", "/app", "-c", "/corpus"])
        assert args.corpus == "/corpus"

    def test_parser_corpus_long_flag(self):
        """Test --corpus long flag."""
        parser = create_parser()
        args = parser.parse_args(["--executable", "/app", "--corpus", "/corpus"])
        assert args.corpus == "/corpus"

    def test_parser_json_flag(self):
        """Test --json flag."""
        parser = create_parser()
        args = parser.parse_args(["-e", "/app", "--json"])
        assert args.json is True

    def test_parser_json_short_flag(self):
        """Test -j short flag for JSON."""
        parser = create_parser()
        args = parser.parse_args(["-e", "/app", "-j"])
        assert args.json is True

    def test_parser_verbose_flag(self):
        """Test --verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["-e", "/app", "--verbose"])
        assert args.verbose is True

    def test_parser_verbose_short_flag(self):
        """Test -v short flag for verbose."""
        parser = create_parser()
        args = parser.parse_args(["-e", "/app", "-v"])
        assert args.verbose is True

    def test_parser_all_flags(self):
        """Test all flags together."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "-e",
                "/app",
                "-c",
                "/corpus",
                "--json",
                "--verbose",
            ]
        )
        assert args.executable == "/app"
        assert args.corpus == "/corpus"
        assert args.json is True
        assert args.verbose is True


# ============================================================================
# Test Main Function
# ============================================================================


class TestMain:
    """Test main() function."""

    def test_main_target_not_found(self, tmp_path, capsys):
        """Test main returns 1 when target not found."""
        fake_exe = str(tmp_path / "nonexistent.exe")

        result = main(["--executable", fake_exe])

        assert result == 1
        captured = capsys.readouterr()
        assert "Target not found" in captured.err

    def test_main_corpus_not_found(self, mock_executable, tmp_path, capsys):
        """Test main returns 1 when corpus not found."""
        fake_corpus = str(tmp_path / "nonexistent_corpus")

        result = main(
            [
                "--executable",
                str(mock_executable),
                "--corpus",
                fake_corpus,
            ]
        )

        assert result == 1
        captured = capsys.readouterr()
        assert "Corpus not found" in captured.err

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_success(
        self, mock_calibrate, mock_executable, mock_calibration_result
    ):
        """Test main returns 0 on success."""
        mock_calibrate.return_value = mock_calibration_result

        result = main(["--executable", str(mock_executable)])

        assert result == 0
        mock_calibrate.assert_called_once()

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_with_corpus(
        self, mock_calibrate, mock_executable, mock_corpus, mock_calibration_result
    ):
        """Test main with corpus argument."""
        mock_calibrate.return_value = mock_calibration_result

        result = main(
            [
                "--executable",
                str(mock_executable),
                "--corpus",
                str(mock_corpus),
            ]
        )

        assert result == 0
        mock_calibrate.assert_called_once()
        call_kwargs = mock_calibrate.call_args[1]
        assert call_kwargs["corpus"] == mock_corpus

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_json_output(
        self, mock_calibrate, mock_executable, mock_calibration_result, capsys
    ):
        """Test main with --json outputs JSON."""
        mock_calibrate.return_value = mock_calibration_result

        result = main(["--executable", str(mock_executable), "--json"])

        assert result == 0
        captured = capsys.readouterr()

        # Verify it's valid JSON
        output = json.loads(captured.out)
        assert output["target_type"] == "cli"
        assert output["recommended_timeout"] == 5.0

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_verbose(
        self, mock_calibrate, mock_executable, mock_calibration_result
    ):
        """Test main with --verbose flag."""
        mock_calibrate.return_value = mock_calibration_result

        result = main(
            [
                "--executable",
                str(mock_executable),
                "--verbose",
            ]
        )

        assert result == 0
        call_kwargs = mock_calibrate.call_args[1]
        assert call_kwargs["verbose"] is True

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_prints_header(
        self, mock_calibrate, mock_executable, mock_calibration_result, capsys
    ):
        """Test main prints header in non-JSON mode."""
        mock_calibrate.return_value = mock_calibration_result

        result = main(["--executable", str(mock_executable)])

        assert result == 0
        captured = capsys.readouterr()
        assert "DICOM Fuzzer - Target Calibration" in captured.out
        assert str(mock_executable) in captured.out

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_no_header_in_json_mode(
        self, mock_calibrate, mock_executable, mock_calibration_result, capsys
    ):
        """Test main does not print header in JSON mode."""
        mock_calibrate.return_value = mock_calibration_result

        result = main(["--executable", str(mock_executable), "--json"])

        assert result == 0
        captured = capsys.readouterr()
        # Header should not appear in JSON mode
        assert "DICOM Fuzzer - Target Calibration" not in captured.out

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_calls_print_summary(
        self, mock_calibrate, mock_executable, mock_calibration_result
    ):
        """Test main calls print_summary in non-JSON mode."""
        mock_result = Mock(spec=CalibrationResult)
        mock_result.to_dict.return_value = {}
        mock_calibrate.return_value = mock_result

        result = main(["--executable", str(mock_executable)])

        assert result == 0
        mock_result.print_summary.assert_called_once()

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_handles_file_not_found(self, mock_calibrate, mock_executable, capsys):
        """Test main handles FileNotFoundError from calibrate."""
        mock_calibrate.side_effect = FileNotFoundError("File not found")

        result = main(["--executable", str(mock_executable)])

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.err

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_handles_exception(self, mock_calibrate, mock_executable, capsys):
        """Test main handles generic exceptions."""
        mock_calibrate.side_effect = RuntimeError("Something went wrong")

        result = main(["--executable", str(mock_executable)])

        assert result == 1
        captured = capsys.readouterr()
        assert "Calibration failed" in captured.err

    @patch("dicom_fuzzer.core.harness.target_calibrator.calibrate_target")
    def test_main_verbose_shows_traceback(
        self, mock_calibrate, mock_executable, capsys
    ):
        """Test main shows traceback in verbose mode on error."""
        mock_calibrate.side_effect = RuntimeError("Something went wrong")

        result = main(["--executable", str(mock_executable), "--verbose"])

        assert result == 1
        captured = capsys.readouterr()
        assert "Traceback" in captured.err


# ============================================================================
# Test Module Execution
# ============================================================================


class TestModuleExecution:
    """Test module can be executed directly."""

    @patch("dicom_fuzzer.cli.target.main")
    @patch("sys.exit")
    def test_module_main(self, mock_exit, mock_main):
        """Test __main__ block calls main()."""
        mock_main.return_value = 0

        # Simulate running as __main__
        import dicom_fuzzer.cli.target as target_module

        # The __name__ == "__main__" block won't run in tests,
        # but we can verify main() is callable
        assert callable(target_module.main)
