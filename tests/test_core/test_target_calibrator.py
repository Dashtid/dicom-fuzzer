"""
Tests for Target Calibrator Module.

Tests the AFL-style target calibration system that auto-detects
target characteristics and configures optimal fuzzing parameters.
"""

import json
import sys
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.harness.target_calibrator import (
    CalibrationResult,
    CrashDetectionStatus,
    TargetCalibrator,
    TargetType,
    calibrate_target,
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
    """Create a mock corpus directory with test files."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    # Create some test DICOM files
    for i in range(5):
        dcm_file = corpus_dir / f"test_{i}.dcm"
        # Minimal DICOM-like content (128 byte preamble + DICM magic)
        dcm_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

    return corpus_dir


@pytest.fixture
def calibrator(mock_executable, mock_corpus):
    """Create a TargetCalibrator instance for testing."""
    return TargetCalibrator(
        target_executable=mock_executable,
        corpus_dir=mock_corpus,
        verbose=False,
    )


# ============================================================================
# Test Enums
# ============================================================================


class TestTargetType:
    """Test TargetType enumeration."""

    def test_target_type_values(self):
        """Test TargetType enum has correct values."""
        assert TargetType.CLI.value == "cli"
        assert TargetType.GUI.value == "gui"
        assert TargetType.ERROR.value == "error"
        assert TargetType.UNKNOWN.value == "unknown"

    def test_target_type_from_string(self):
        """Test creating TargetType from string value."""
        assert TargetType("cli") == TargetType.CLI
        assert TargetType("gui") == TargetType.GUI
        assert TargetType("error") == TargetType.ERROR
        assert TargetType("unknown") == TargetType.UNKNOWN


class TestCrashDetectionStatus:
    """Test CrashDetectionStatus enumeration."""

    def test_crash_detection_status_values(self):
        """Test CrashDetectionStatus enum has correct values."""
        assert CrashDetectionStatus.VALIDATED.value == "validated"
        assert CrashDetectionStatus.UNTESTED.value == "untested"
        assert CrashDetectionStatus.FAILED.value == "failed"


# ============================================================================
# Test CalibrationResult Dataclass
# ============================================================================


class TestCalibrationResult:
    """Test CalibrationResult dataclass."""

    def test_default_initialization(self):
        """Test CalibrationResult default values."""
        result = CalibrationResult()

        assert result.target_type == TargetType.UNKNOWN
        assert result.target_path == ""
        assert result.recommended_timeout == 10.0
        assert result.avg_execution_time == 0.0
        assert result.min_execution_time == 0.0
        assert result.max_execution_time == 0.0
        assert result.execution_variance == 0.0
        assert result.execution_times == []
        assert result.crash_detection == CrashDetectionStatus.UNTESTED
        assert result.wer_disabled is False
        assert result.corpus_total == 0
        assert result.is_stable is True
        assert result.calibration_version == 2

    def test_custom_initialization(self):
        """Test CalibrationResult with custom values."""
        result = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="/path/to/app",
            recommended_timeout=5.0,
            avg_execution_time=0.5,
            is_stable=True,
        )

        assert result.target_type == TargetType.CLI
        assert result.target_path == "/path/to/app"
        assert result.recommended_timeout == 5.0
        assert result.avg_execution_time == 0.5

    def test_to_dict(self):
        """Test CalibrationResult serialization to dict."""
        result = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="/path/to/app",
            recommended_timeout=5.0,
            avg_execution_time=0.5,
            min_execution_time=0.4,
            max_execution_time=0.6,
            execution_variance=0.05,
            is_stable=True,
            crash_detection=CrashDetectionStatus.VALIDATED,
            wer_disabled=True,
            corpus_total=100,
            corpus_valid=95,
            corpus_errors=5,
            corpus_crashes=0,
            problematic_seeds=["/path/to/seed1", "/path/to/seed2"],
            recommendations=["Use CLI mode"],
            calibration_time=10.5,
            test_runs=20,
        )

        data = result.to_dict()

        assert data["calibration_version"] == 2
        assert data["target_type"] == "cli"
        assert data["target_path"] == "/path/to/app"
        assert data["recommended_timeout"] == 5.0
        assert data["avg_execution_time"] == 0.5
        assert data["min_execution_time"] == 0.4
        assert data["max_execution_time"] == 0.6
        assert data["execution_variance"] == 0.05
        assert data["is_stable"] is True
        assert data["crash_detection"] == "validated"
        assert data["wer_disabled"] is True
        assert data["corpus_health"]["total"] == 100
        assert data["corpus_health"]["valid"] == 95
        assert data["corpus_health"]["errors"] == 5
        assert data["corpus_health"]["crashes"] == 0
        assert len(data["problematic_seeds"]) == 2
        assert data["recommendations"] == ["Use CLI mode"]
        assert data["calibration_time"] == 10.5
        assert data["test_runs"] == 20

    def test_to_dict_limits_problematic_seeds(self):
        """Test that to_dict limits problematic_seeds to 10."""
        result = CalibrationResult(problematic_seeds=[f"/seed_{i}" for i in range(20)])

        data = result.to_dict()
        assert len(data["problematic_seeds"]) == 10

    def test_from_dict(self):
        """Test CalibrationResult deserialization from dict."""
        data = {
            "calibration_version": 2,
            "target_type": "gui",
            "target_path": "/app/gui.exe",
            "recommended_timeout": 10.0,
            "avg_execution_time": 0.0,
            "min_execution_time": 0.0,
            "max_execution_time": 0.0,
            "execution_variance": 0.0,
            "is_stable": True,
            "crash_detection": "validated",
            "wer_disabled": True,
            "corpus_health": {
                "total": 50,
                "valid": 48,
                "errors": 2,
                "crashes": 0,
            },
            "problematic_seeds": [],
            "recommendations": ["Use GUI mode"],
            "calibration_time": 5.0,
            "test_runs": 10,
        }

        result = CalibrationResult.from_dict(data)

        assert result.target_type == TargetType.GUI
        assert result.target_path == "/app/gui.exe"
        assert result.recommended_timeout == 10.0
        assert result.crash_detection == CrashDetectionStatus.VALIDATED
        assert result.wer_disabled is True
        assert result.corpus_total == 50
        assert result.corpus_valid == 48
        assert result.calibration_version == 2

    def test_from_dict_with_minimal_data(self):
        """Test from_dict with minimal/missing data uses defaults."""
        data = {}

        result = CalibrationResult.from_dict(data)

        assert result.target_type == TargetType.UNKNOWN
        assert result.recommended_timeout == 10.0
        assert result.crash_detection == CrashDetectionStatus.UNTESTED
        assert result.calibration_version == 1  # Default for old format

    def test_from_dict_roundtrip(self):
        """Test to_dict -> from_dict preserves data."""
        original = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="/path/to/app",
            recommended_timeout=3.5,
            avg_execution_time=0.7,
            is_stable=True,
            crash_detection=CrashDetectionStatus.VALIDATED,
        )

        data = original.to_dict()
        restored = CalibrationResult.from_dict(data)

        assert restored.target_type == original.target_type
        assert restored.target_path == original.target_path
        assert restored.recommended_timeout == original.recommended_timeout
        assert restored.avg_execution_time == original.avg_execution_time
        assert restored.crash_detection == original.crash_detection

    def test_print_summary_cli(self, capsys):
        """Test print_summary for CLI app."""
        result = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="/path/to/cli_app",
            recommended_timeout=2.5,
            avg_execution_time=0.5,
            execution_variance=0.05,
            is_stable=True,
            crash_detection=CrashDetectionStatus.VALIDATED,
            wer_disabled=True,
            corpus_total=100,
            corpus_valid=95,
            corpus_crashes=2,
            recommendations=["Use CLI mode", "Check corpus"],
        )

        result.print_summary()

        captured = capsys.readouterr()
        assert "TARGET CALIBRATION RESULTS" in captured.out
        assert "/path/to/cli_app" in captured.out
        assert "CLI" in captured.out
        assert "2.5s" in captured.out
        assert "0.500s" in captured.out
        assert "stable" in captured.out
        assert "validated" in captured.out
        assert "95/100 valid" in captured.out
        assert "2 seeds cause crashes" in captured.out

    def test_print_summary_gui(self, capsys):
        """Test print_summary for GUI app shows N/A for exec time."""
        result = CalibrationResult(
            target_type=TargetType.GUI,
            target_path="/path/to/gui_app",
            recommended_timeout=10.0,
            avg_execution_time=0.0,  # Skipped for GUI
            crash_detection=CrashDetectionStatus.VALIDATED,
            recommendations=["Use GUI mode"],
        )

        result.print_summary()

        captured = capsys.readouterr()
        assert "N/A (GUI mode)" in captured.out
        assert "GUI" in captured.out

    def test_print_summary_unstable(self, capsys):
        """Test print_summary shows UNSTABLE warning."""
        result = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="/path/to/app",
            avg_execution_time=1.0,
            execution_variance=0.5,
            is_stable=False,
            recommendations=[],
        )

        result.print_summary()

        captured = capsys.readouterr()
        assert "UNSTABLE" in captured.out


# ============================================================================
# Test TargetCalibrator Initialization
# ============================================================================


class TestTargetCalibratorInit:
    """Test TargetCalibrator initialization."""

    def test_init_with_valid_executable(self, mock_executable):
        """Test initialization with valid executable."""
        calibrator = TargetCalibrator(target_executable=mock_executable)

        assert calibrator.target == mock_executable
        assert calibrator.corpus_dir is None
        assert calibrator.verbose is False
        assert calibrator.result.target_path == str(mock_executable)

    def test_init_with_corpus(self, mock_executable, mock_corpus):
        """Test initialization with corpus directory."""
        calibrator = TargetCalibrator(
            target_executable=mock_executable,
            corpus_dir=mock_corpus,
        )

        assert calibrator.corpus_dir == mock_corpus

    def test_init_with_verbose(self, mock_executable):
        """Test initialization with verbose mode."""
        calibrator = TargetCalibrator(
            target_executable=mock_executable,
            verbose=True,
        )

        assert calibrator.verbose is True

    def test_init_with_nonexistent_executable(self, tmp_path):
        """Test initialization fails with nonexistent executable."""
        fake_exe = tmp_path / "nonexistent.exe"

        with pytest.raises(FileNotFoundError, match="Target not found"):
            TargetCalibrator(target_executable=fake_exe)

    def test_init_with_string_paths(self, mock_executable, mock_corpus):
        """Test initialization with string paths (not Path objects)."""
        calibrator = TargetCalibrator(
            target_executable=str(mock_executable),
            corpus_dir=str(mock_corpus),
        )

        assert calibrator.target == mock_executable
        assert calibrator.corpus_dir == mock_corpus

    def test_calibration_version_constant(self):
        """Test CALIBRATION_VERSION is set correctly."""
        assert TargetCalibrator.CALIBRATION_VERSION == 2

    def test_crash_exit_codes(self):
        """Test CRASH_EXIT_CODES contains expected Windows codes."""
        codes = TargetCalibrator.CRASH_EXIT_CODES

        assert -1073741819 in codes  # Access Violation
        assert -1073741795 in codes  # Illegal Instruction
        assert -1073741676 in codes  # Integer Divide by Zero
        assert -1073741571 in codes  # Stack Overflow
        assert -1073740940 in codes  # Heap Corruption
        assert -1073740791 in codes  # Stack Buffer Overrun
        assert -2147483645 in codes  # Breakpoint
        assert -1073741515 in codes  # DLL Not Found


# ============================================================================
# Test TargetCalibrator Helper Methods
# ============================================================================


class TestTargetCalibratorHelpers:
    """Test TargetCalibrator helper methods."""

    def test_get_test_file_from_corpus(self, calibrator, mock_corpus):
        """Test _get_test_file returns file from corpus."""
        test_file = calibrator._get_test_file()

        assert test_file is not None
        assert test_file.exists()
        assert test_file.suffix == ".dcm"
        assert mock_corpus in test_file.parents

    def test_get_test_file_creates_minimal_dcm(self, mock_executable, tmp_path):
        """Test _get_test_file creates minimal DICOM when no corpus."""
        calibrator = TargetCalibrator(
            target_executable=mock_executable,
            corpus_dir=None,
        )

        test_file = calibrator._get_test_file()

        assert test_file is not None
        assert test_file.exists()
        assert test_file.name == "_calibration_test.dcm"
        # Check it's tracked for cleanup
        assert test_file in calibrator._temp_files

    def test_cleanup_temp_files(self, mock_executable, tmp_path):
        """Test _cleanup_temp_files removes tracked files."""
        calibrator = TargetCalibrator(target_executable=mock_executable)

        # Create some temp files
        temp1 = tmp_path / "temp1.dcm"
        temp2 = tmp_path / "temp2.dcm"
        temp1.write_bytes(b"test1")
        temp2.write_bytes(b"test2")

        calibrator._temp_files = [temp1, temp2]
        calibrator._cleanup_temp_files()

        assert not temp1.exists()
        assert not temp2.exists()
        assert calibrator._temp_files == []

    def test_cleanup_temp_files_handles_missing(self, mock_executable, tmp_path):
        """Test _cleanup_temp_files handles already-deleted files."""
        calibrator = TargetCalibrator(target_executable=mock_executable)

        nonexistent = tmp_path / "nonexistent.dcm"
        calibrator._temp_files = [nonexistent]

        # Should not raise
        calibrator._cleanup_temp_files()
        assert calibrator._temp_files == []


# ============================================================================
# Test Target Execution (_run_target)
# ============================================================================


class TestRunTarget:
    """Test _run_target method."""

    @patch("subprocess.Popen")
    def test_run_target_success(self, mock_popen, calibrator, mock_corpus):
        """Test _run_target with successful execution."""
        # Mock process that exits quickly
        mock_process = Mock()
        mock_process.poll.side_effect = [None, 0]  # Running, then exit 0
        mock_popen.return_value = mock_process

        test_file = list(mock_corpus.glob("*.dcm"))[0]
        exit_code, exec_time, timed_out = calibrator._run_target(test_file, timeout=5.0)

        assert exit_code == 0
        assert exec_time >= 0
        assert timed_out is False
        assert calibrator.result.test_runs == 1

    @patch("subprocess.Popen")
    def test_run_target_timeout(self, mock_popen, calibrator, mock_corpus):
        """Test _run_target with timeout."""
        # Mock process that never exits
        mock_process = Mock()
        mock_process.poll.return_value = None  # Always running
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process

        test_file = list(mock_corpus.glob("*.dcm"))[0]
        exit_code, exec_time, timed_out = calibrator._run_target(
            test_file,
            timeout=0.1,  # Very short timeout
        )

        assert timed_out is True
        mock_process.terminate.assert_called_once()

    @patch("subprocess.Popen")
    def test_run_target_crash(self, mock_popen, calibrator, mock_corpus):
        """Test _run_target with crash exit code."""
        # Mock process that crashes
        mock_process = Mock()
        mock_process.poll.return_value = -1073741819  # Access Violation
        mock_popen.return_value = mock_process

        test_file = list(mock_corpus.glob("*.dcm"))[0]
        exit_code, exec_time, timed_out = calibrator._run_target(test_file, timeout=5.0)

        assert exit_code == -1073741819
        assert timed_out is False

    @patch("subprocess.Popen")
    def test_run_target_increments_test_runs(self, mock_popen, calibrator, mock_corpus):
        """Test _run_target increments test_runs counter."""
        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        test_file = list(mock_corpus.glob("*.dcm"))[0]

        assert calibrator.result.test_runs == 0

        calibrator._run_target(test_file, timeout=5.0)
        assert calibrator.result.test_runs == 1

        calibrator._run_target(test_file, timeout=5.0)
        assert calibrator.result.test_runs == 2

    @patch("subprocess.Popen")
    def test_run_target_exception(self, mock_popen, calibrator, mock_corpus):
        """Test _run_target handles subprocess exceptions."""
        mock_popen.side_effect = OSError("Failed to execute")

        test_file = list(mock_corpus.glob("*.dcm"))[0]
        exit_code, exec_time, timed_out = calibrator._run_target(test_file, timeout=5.0)

        assert exit_code == -1
        assert timed_out is False


# ============================================================================
# Test Phase 1: Target Detection
# ============================================================================


class TestPhase1TargetDetection:
    """Test Phase 1: Target type detection."""

    @patch.object(TargetCalibrator, "_run_target")
    def test_detect_cli_app(self, mock_run, calibrator):
        """Test detection of CLI application."""
        # CLI app exits quickly with code 0
        mock_run.return_value = (0, 0.5, False)

        calibrator._phase1_detect_target_type()

        assert calibrator.result.target_type == TargetType.CLI

    @patch.object(TargetCalibrator, "_run_target")
    def test_detect_gui_app(self, mock_run, calibrator):
        """Test detection of GUI application."""
        # GUI app times out (stays running)
        mock_run.return_value = (None, 2.0, True)

        calibrator._phase1_detect_target_type()

        assert calibrator.result.target_type == TargetType.GUI

    @patch.object(TargetCalibrator, "_run_target")
    def test_detect_error_app(self, mock_run, calibrator):
        """Test detection of error-returning application."""
        # App returns non-zero, non-crash exit code
        mock_run.return_value = (1, 0.5, False)

        calibrator._phase1_detect_target_type()

        assert calibrator.result.target_type == TargetType.ERROR

    @patch.object(TargetCalibrator, "_run_target")
    def test_detect_crashing_app(self, mock_run, calibrator):
        """Test detection of crashing application."""
        # App crashes on valid input
        mock_run.return_value = (-1073741819, 0.1, False)  # Access Violation

        calibrator._phase1_detect_target_type()

        assert calibrator.result.target_type == TargetType.ERROR

    @patch.object(TargetCalibrator, "_run_target")
    def test_detect_unknown_mixed_behavior(self, mock_run, calibrator):
        """Test detection with mixed/inconsistent behavior."""
        # Different results each run
        mock_run.side_effect = [
            (0, 0.5, False),  # Exit 0
            (1, 0.6, False),  # Exit 1
            (None, 2.0, True),  # Timeout
            (0, 0.4, False),  # Exit 0
            (1, 0.7, False),  # Exit 1
        ]

        calibrator._phase1_detect_target_type()

        assert calibrator.result.target_type == TargetType.UNKNOWN

    @patch.object(TargetCalibrator, "_get_test_file")
    def test_detect_no_test_file(self, mock_get_file, calibrator):
        """Test detection when no test file available."""
        mock_get_file.return_value = None

        calibrator._phase1_detect_target_type()

        assert calibrator.result.target_type == TargetType.UNKNOWN


# ============================================================================
# Test Phase 2: Timeout Calibration
# ============================================================================


class TestPhase2TimeoutCalibration:
    """Test Phase 2: Timeout calibration."""

    @patch.object(TargetCalibrator, "_run_target")
    def test_calibrate_cli_timeout(self, mock_run, calibrator):
        """Test timeout calculation for CLI app."""
        calibrator.result.target_type = TargetType.CLI

        # 3 runs with ~0.5s execution time
        mock_run.side_effect = [
            (0, 0.4, False),
            (0, 0.5, False),
            (0, 0.6, False),
        ]

        calibrator._phase2_calibrate_timeout()

        # Average is 0.5s, CLI multiplier is 5x
        assert calibrator.result.avg_execution_time == pytest.approx(0.5, rel=0.01)
        assert calibrator.result.recommended_timeout == pytest.approx(2.5, rel=0.01)

    @patch.object(TargetCalibrator, "_run_target")
    def test_calibrate_records_variance(self, mock_run, calibrator):
        """Test that variance is calculated for stability."""
        calibrator.result.target_type = TargetType.CLI

        mock_run.side_effect = [
            (0, 0.5, False),
            (0, 0.5, False),
            (0, 0.5, False),
        ]

        calibrator._phase2_calibrate_timeout()

        assert calibrator.result.execution_variance == 0.0
        assert calibrator.result.is_stable is True

    @patch.object(TargetCalibrator, "_run_target")
    def test_calibrate_unstable_detection(self, mock_run, calibrator):
        """Test unstable target detection (>20% variance)."""
        calibrator.result.target_type = TargetType.CLI

        # High variance execution times
        mock_run.side_effect = [
            (0, 0.5, False),
            (0, 1.0, False),
            (0, 1.5, False),
        ]

        calibrator._phase2_calibrate_timeout()

        assert calibrator.result.execution_variance > 0
        assert calibrator.result.is_stable is False

    @patch.object(TargetCalibrator, "_run_target")
    def test_calibrate_all_timeout(self, mock_run, calibrator):
        """Test calibration when all runs timeout."""
        calibrator.result.target_type = TargetType.CLI

        mock_run.return_value = (None, 30.0, True)

        calibrator._phase2_calibrate_timeout()

        assert (
            calibrator.result.recommended_timeout
            == TargetCalibrator.DEFAULT_GUI_TIMEOUT
        )

    @patch.object(TargetCalibrator, "_get_test_file")
    def test_calibrate_no_test_file(self, mock_get_file, calibrator):
        """Test calibration when no test file."""
        mock_get_file.return_value = None
        calibrator.result.target_type = TargetType.CLI

        calibrator._phase2_calibrate_timeout()

        assert (
            calibrator.result.recommended_timeout
            == TargetCalibrator.DEFAULT_GUI_TIMEOUT
        )

    @patch.object(TargetCalibrator, "_run_target")
    def test_calibrate_clamps_timeout(self, mock_run, calibrator):
        """Test timeout is clamped to valid range."""
        calibrator.result.target_type = TargetType.CLI

        # Very slow execution
        mock_run.return_value = (0, 20.0, False)

        calibrator._phase2_calibrate_timeout()

        # Should be clamped to MAX_TIMEOUT
        assert calibrator.result.recommended_timeout <= TargetCalibrator.MAX_TIMEOUT


# ============================================================================
# Test Phase 3: Crash Detection Validation
# ============================================================================


class TestPhase3CrashDetection:
    """Test Phase 3: Crash detection validation."""

    @pytest.mark.skipif(
        sys.platform != "win32", reason="Windows-only test (ctypes.windll)"
    )
    @patch.object(TargetCalibrator, "_run_target")
    @patch("sys.platform", "win32")
    @patch("ctypes.windll")
    def test_validates_crash_detection_windows(self, mock_windll, mock_run, calibrator):
        """Test crash detection validation on Windows."""
        mock_kernel32 = Mock()
        mock_windll.kernel32 = mock_kernel32

        mock_run.return_value = (1, 0.1, False)  # Non-zero exit

        calibrator._phase3_validate_crash_detection()

        assert calibrator.result.wer_disabled is True
        assert calibrator.result.crash_detection == CrashDetectionStatus.VALIDATED

    @patch.object(TargetCalibrator, "_run_target")
    @patch("sys.platform", "linux")
    def test_validates_crash_detection_linux(self, mock_run, calibrator):
        """Test crash detection validation on non-Windows."""
        mock_run.return_value = (0, 0.1, False)

        calibrator._phase3_validate_crash_detection()

        assert calibrator.result.crash_detection == CrashDetectionStatus.VALIDATED

    @patch.object(TargetCalibrator, "_run_target")
    def test_crash_on_invalid_input(self, mock_run, calibrator):
        """Test when target crashes on invalid input."""
        mock_run.return_value = (-1073741819, 0.1, False)  # Access Violation

        calibrator._phase3_validate_crash_detection()

        assert calibrator.result.crash_detection == CrashDetectionStatus.VALIDATED

    @patch.object(TargetCalibrator, "_get_test_file")
    def test_no_test_file_untested(self, mock_get_file, calibrator):
        """Test crash detection stays untested when no file."""
        mock_get_file.return_value = None

        calibrator._phase3_validate_crash_detection()

        assert calibrator.result.crash_detection == CrashDetectionStatus.UNTESTED


# ============================================================================
# Test Phase 4: Corpus Validation
# ============================================================================


class TestPhase4CorpusValidation:
    """Test Phase 4: Corpus validation."""

    @patch.object(TargetCalibrator, "_run_target")
    def test_validate_corpus_all_valid(self, mock_run, calibrator, mock_corpus):
        """Test corpus validation with all valid seeds."""
        calibrator.result.recommended_timeout = 5.0
        mock_run.return_value = (0, 0.5, False)

        calibrator._phase4_validate_corpus()

        assert calibrator.result.corpus_total == 5
        assert calibrator.result.corpus_valid > 0
        assert calibrator.result.corpus_crashes == 0

    @patch.object(TargetCalibrator, "_run_target")
    def test_validate_corpus_with_crashes(self, mock_run, calibrator, mock_corpus):
        """Test corpus validation with crashing seeds."""
        calibrator.result.recommended_timeout = 5.0

        # Mix of valid and crashing
        mock_run.side_effect = [
            (0, 0.5, False),
            (-1073741819, 0.1, False),  # Crash
            (0, 0.4, False),
            (0, 0.6, False),
            (-1073741819, 0.1, False),  # Crash
        ]

        calibrator._phase4_validate_corpus()

        assert calibrator.result.corpus_crashes > 0
        assert len(calibrator.result.problematic_seeds) > 0

    @patch.object(TargetCalibrator, "_run_target")
    def test_validate_corpus_respects_sample_limit(
        self, mock_run, calibrator, mock_corpus, tmp_path
    ):
        """Test corpus validation respects MAX_CORPUS_SAMPLE."""
        calibrator.result.recommended_timeout = 5.0
        calibrator.result.target_type = TargetType.GUI

        # Add many more seeds
        for i in range(100):
            f = mock_corpus / f"extra_{i}.dcm"
            f.write_bytes(b"\x00" * 200)

        mock_run.return_value = (0, 0.5, False)

        calibrator._phase4_validate_corpus()

        # Should be capped at MAX_CORPUS_SAMPLE_GUI (20)
        assert calibrator.result.test_runs <= TargetCalibrator.MAX_CORPUS_SAMPLE_GUI

    def test_validate_corpus_no_corpus(self, mock_executable):
        """Test corpus validation skips when no corpus."""
        calibrator = TargetCalibrator(target_executable=mock_executable)

        calibrator._phase4_validate_corpus()

        assert calibrator.result.corpus_total == 0

    def test_validate_corpus_empty(self, mock_executable, tmp_path):
        """Test corpus validation with empty directory."""
        empty_corpus = tmp_path / "empty"
        empty_corpus.mkdir()

        calibrator = TargetCalibrator(
            target_executable=mock_executable,
            corpus_dir=empty_corpus,
        )

        calibrator._phase4_validate_corpus()

        assert calibrator.result.corpus_total == 0


# ============================================================================
# Test Recommendations Generation
# ============================================================================


class TestRecommendations:
    """Test recommendations generation."""

    def test_recommendations_cli(self, calibrator):
        """Test recommendations for CLI app."""
        calibrator.result.target_type = TargetType.CLI
        calibrator.result.recommended_timeout = 2.5

        calibrator._generate_recommendations()

        assert any("CLI mode" in r for r in calibrator.result.recommendations)

    def test_recommendations_gui(self, calibrator):
        """Test recommendations for GUI app."""
        calibrator.result.target_type = TargetType.GUI
        calibrator.result.recommended_timeout = 10.0

        calibrator._generate_recommendations()

        assert any("GUI mode" in r for r in calibrator.result.recommendations)

    def test_recommendations_error(self, calibrator):
        """Test recommendations for error-returning app."""
        calibrator.result.target_type = TargetType.ERROR

        calibrator._generate_recommendations()

        assert any("errors" in r for r in calibrator.result.recommendations)

    def test_recommendations_large_corpus(self, calibrator):
        """Test recommendations for large corpus."""
        calibrator.result.target_type = TargetType.CLI
        calibrator.result.corpus_total = 5000

        calibrator._generate_recommendations()

        assert any("minimization" in r for r in calibrator.result.recommendations)

    def test_recommendations_corpus_crashes(self, calibrator):
        """Test recommendations when corpus has crashes."""
        calibrator.result.target_type = TargetType.CLI
        calibrator.result.corpus_crashes = 10

        calibrator._generate_recommendations()

        assert any("crashes" in r for r in calibrator.result.recommendations)

    def test_recommendations_slow_target(self, calibrator):
        """Test recommendations for slow target."""
        calibrator.result.target_type = TargetType.CLI
        calibrator.result.avg_execution_time = 2.5
        calibrator.result.recommended_timeout = 12.5

        calibrator._generate_recommendations()

        assert any("Slow target" in r for r in calibrator.result.recommendations)


# ============================================================================
# Test Full Calibration
# ============================================================================


class TestFullCalibration:
    """Test complete calibration workflow."""

    @patch.object(TargetCalibrator, "_phase1_detect_target_type")
    @patch.object(TargetCalibrator, "_phase2_calibrate_timeout")
    @patch.object(TargetCalibrator, "_phase3_validate_crash_detection")
    @patch.object(TargetCalibrator, "_phase4_validate_corpus")
    @patch.object(TargetCalibrator, "_generate_recommendations")
    @patch.object(TargetCalibrator, "_cleanup_temp_files")
    def test_calibrate_calls_all_phases(
        self, mock_cleanup, mock_rec, mock_p4, mock_p3, mock_p2, mock_p1, calibrator
    ):
        """Test calibrate() calls all phases in order."""
        calibrator.result.target_type = TargetType.CLI

        result = calibrator.calibrate()

        mock_p1.assert_called_once()
        mock_p2.assert_called_once()
        mock_p3.assert_called_once()
        mock_p4.assert_called_once()
        mock_rec.assert_called_once()
        mock_cleanup.assert_called_once()

        assert result.calibration_time > 0

    @patch.object(TargetCalibrator, "_phase1_detect_target_type")
    @patch.object(TargetCalibrator, "_phase3_validate_crash_detection")
    @patch.object(TargetCalibrator, "_phase4_validate_corpus")
    @patch.object(TargetCalibrator, "_generate_recommendations")
    @patch.object(TargetCalibrator, "_cleanup_temp_files")
    def test_calibrate_skips_phase2_for_gui(
        self, mock_cleanup, mock_rec, mock_p4, mock_p3, mock_p1, calibrator
    ):
        """Test calibrate() skips Phase 2 for GUI apps."""

        def set_gui():
            calibrator.result.target_type = TargetType.GUI

        mock_p1.side_effect = set_gui

        result = calibrator.calibrate()

        # Should use default GUI timeout
        assert result.recommended_timeout == TargetCalibrator.DEFAULT_GUI_TIMEOUT


# ============================================================================
# Test Convenience Function
# ============================================================================


class TestCalibrateTargetFunction:
    """Test calibrate_target convenience function."""

    @patch.object(TargetCalibrator, "calibrate")
    def test_calibrate_target_basic(self, mock_calibrate, mock_executable):
        """Test calibrate_target with basic args."""
        mock_calibrate.return_value = CalibrationResult()

        result = calibrate_target(target=mock_executable)

        assert result is not None
        mock_calibrate.assert_called_once()

    @patch.object(TargetCalibrator, "calibrate")
    def test_calibrate_target_with_corpus(
        self, mock_calibrate, mock_executable, mock_corpus
    ):
        """Test calibrate_target with corpus."""
        mock_calibrate.return_value = CalibrationResult()

        result = calibrate_target(
            target=mock_executable,
            corpus=mock_corpus,
            verbose=True,
        )

        assert result is not None

    def test_calibrate_target_invalid_executable(self, tmp_path):
        """Test calibrate_target with invalid executable."""
        with pytest.raises(FileNotFoundError):
            calibrate_target(target=tmp_path / "nonexistent.exe")


# ============================================================================
# Test JSON Serialization Integration
# ============================================================================


class TestJSONSerialization:
    """Test JSON serialization/deserialization."""

    def test_result_to_json(self):
        """Test CalibrationResult can be serialized to JSON."""
        result = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="C:\\app\\test.exe",
            recommended_timeout=5.0,
        )

        data = result.to_dict()
        json_str = json.dumps(data, indent=2)

        assert "cli" in json_str
        assert "test.exe" in json_str

    def test_result_from_json(self):
        """Test CalibrationResult can be deserialized from JSON."""
        json_str = """
        {
            "calibration_version": 2,
            "target_type": "gui",
            "target_path": "C:\\\\app\\\\gui.exe",
            "recommended_timeout": 10.0,
            "crash_detection": "validated",
            "corpus_health": {"total": 100, "valid": 95, "errors": 5, "crashes": 0}
        }
        """

        data = json.loads(json_str)
        result = CalibrationResult.from_dict(data)

        assert result.target_type == TargetType.GUI
        assert result.recommended_timeout == 10.0
        assert result.corpus_total == 100

    def test_roundtrip_json(self):
        """Test full JSON roundtrip preserves data."""
        original = CalibrationResult(
            target_type=TargetType.CLI,
            target_path="/path/to/app",
            recommended_timeout=3.5,
            avg_execution_time=0.7,
            corpus_total=50,
            corpus_valid=48,
            recommendations=["Use CLI mode", "Fast target"],
        )

        json_str = json.dumps(original.to_dict())
        restored = CalibrationResult.from_dict(json.loads(json_str))

        assert restored.target_type == original.target_type
        assert restored.target_path == original.target_path
        assert restored.recommended_timeout == original.recommended_timeout
        assert restored.corpus_total == original.corpus_total
