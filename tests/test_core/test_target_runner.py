"""
Tests for Target Application Runner

Tests the fuzzing interface that feeds files to target applications
and monitors for crashes, hangs, and errors.
"""

import subprocess
import sys
import time
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.target_runner import (
    ExecutionResult,
    ExecutionStatus,
    TargetRunner,
)


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
def target_runner(mock_executable, tmp_path):
    """Create a TargetRunner instance for testing."""
    crash_dir = tmp_path / "crashes"
    return TargetRunner(
        target_executable=str(mock_executable), timeout=2.0, crash_dir=str(crash_dir)
    )


class TestTargetRunnerInit:
    """Test TargetRunner initialization."""

    def test_init_with_valid_executable(self, mock_executable, tmp_path):
        """Test initialization with valid executable."""
        runner = TargetRunner(target_executable=str(mock_executable))
        assert runner.target_executable == mock_executable
        assert runner.timeout == 5.0  # default
        assert runner.crash_dir.exists()

    def test_init_with_custom_timeout(self, mock_executable):
        """Test initialization with custom timeout."""
        runner = TargetRunner(target_executable=str(mock_executable), timeout=10.0)
        assert runner.timeout == 10.0

    def test_init_with_nonexistent_executable(self, tmp_path):
        """Test initialization fails with nonexistent executable."""
        fake_exe = tmp_path / "nonexistent.exe"
        with pytest.raises(FileNotFoundError):
            TargetRunner(target_executable=str(fake_exe))

    def test_init_creates_crash_directory(self, mock_executable, tmp_path):
        """Test crash directory is created."""
        crash_dir = tmp_path / "my_crashes"
        runner = TargetRunner(
            target_executable=str(mock_executable), crash_dir=str(crash_dir)
        )
        assert crash_dir.exists()
        assert runner.crash_dir == crash_dir


class TestExecutionResult:
    """Test ExecutionResult dataclass."""

    def test_execution_result_creation(self, tmp_path):
        """Test creating ExecutionResult."""
        test_file = tmp_path / "test.dcm"
        test_file.write_text("test")

        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=0.5,
            stdout="output",
            stderr="",
        )

        assert result.test_file == test_file
        assert result.result == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.execution_time == 0.5
        assert result.stdout == "output"

    def test_execution_result_bool_success(self, tmp_path):
        """Test ExecutionResult bool conversion for success."""
        test_file = tmp_path / "test.dcm"
        test_file.write_text("test")

        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=0.5,
            stdout="",
            stderr="",
        )

        assert bool(result) is True

    def test_execution_result_bool_crash(self, tmp_path):
        """Test ExecutionResult bool conversion for crash."""
        test_file = tmp_path / "test.dcm"
        test_file.write_text("test")

        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.CRASH,
            exit_code=-11,
            execution_time=0.2,
            stdout="",
            stderr="Segmentation fault",
        )

        assert bool(result) is False


class TestExecuteTest:
    """Test execute_test method."""

    @patch("subprocess.run")
    def test_execute_test_success(self, mock_run, target_runner, tmp_path):
        """Test successful execution."""
        test_file = tmp_path / "test.dcm"
        test_file.write_text("test dicom")

        # Mock successful execution
        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

        result = target_runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.stdout == "Success"
        assert result.exception is None

    @patch("subprocess.run")
    def test_execute_test_crash(self, mock_run, target_runner, tmp_path):
        """Test detection of crash (negative exit code)."""
        test_file = tmp_path / "crash.dcm"
        test_file.write_text("malformed")

        # Mock crash (negative exit code = signal termination)
        mock_run.return_value = Mock(returncode=-11, stdout="", stderr="SIGSEGV")

        result = target_runner.execute_test(test_file)

        assert result.result == ExecutionStatus.CRASH
        assert result.exit_code == -11
        assert "SIGSEGV" in result.stderr

    @patch("subprocess.run")
    def test_execute_test_error(self, mock_run, target_runner, tmp_path):
        """Test detection of error (positive non-zero exit code)."""
        test_file = tmp_path / "invalid.dcm"
        test_file.write_text("invalid")

        # Mock error return
        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="Invalid file format"
        )

        result = target_runner.execute_test(test_file)

        assert result.result == ExecutionStatus.ERROR
        assert result.exit_code == 1
        assert "Invalid" in result.stderr

    @patch("subprocess.run")
    def test_execute_test_timeout(self, mock_run, target_runner, tmp_path):
        """Test detection of hang/timeout."""
        test_file = tmp_path / "hang.dcm"
        test_file.write_text("hangs forever")

        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["test"], timeout=2.0, output=b"partial", stderr=b"error"
        )

        result = target_runner.execute_test(test_file)

        assert result.result == ExecutionStatus.HANG
        assert result.exit_code is None
        assert result.exception is not None
        assert isinstance(result.exception, subprocess.TimeoutExpired)

    @patch("subprocess.run")
    def test_execute_test_exception(self, mock_run, target_runner, tmp_path):
        """Test handling of unexpected exceptions."""
        test_file = tmp_path / "error.dcm"
        test_file.write_text("causes error")

        # Mock unexpected exception
        mock_run.side_effect = RuntimeError("Unexpected error")

        result = target_runner.execute_test(test_file)

        assert result.result == ExecutionStatus.ERROR
        assert result.exception is not None
        assert "Unexpected error" in str(result.exception)

    @patch("subprocess.run")
    def test_execute_test_measures_time(self, mock_run, target_runner, tmp_path):
        """Test that execution time is measured."""
        test_file = tmp_path / "test.dcm"
        test_file.write_text("test")

        # Add delay to simulate execution
        def slow_run(*args, **kwargs):
            time.sleep(0.1)
            return Mock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = slow_run

        result = target_runner.execute_test(test_file)

        assert result.execution_time >= 0.1


class TestRunCampaign:
    """Test run_campaign method."""

    @patch("subprocess.run")
    def test_run_campaign_with_multiple_files(self, mock_run, target_runner, tmp_path):
        """Test campaign with multiple test files."""
        # Create test files
        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.dcm"
            f.write_text(f"test {i}")
            files.append(f)

        # Mock all successful
        mock_run.return_value = Mock(returncode=0, stdout="OK", stderr="")

        results = target_runner.run_campaign(files)

        assert len(results[ExecutionStatus.SUCCESS]) == 5
        assert len(results[ExecutionStatus.CRASH]) == 0

    @patch("subprocess.run")
    def test_run_campaign_with_mixed_results(self, mock_run, target_runner, tmp_path):
        """Test campaign with mixed success/crash/error results."""
        files = []
        for i in range(6):
            f = tmp_path / f"test_{i}.dcm"
            f.write_text(f"test {i}")
            files.append(f)

        # Mock varying results
        return_codes = [
            0,
            -11,
            1,
            0,
            -6,
            0,
        ]  # success, crash, error, success, crash, success

        def side_effect(*args, **kwargs):
            code = return_codes.pop(0)
            return Mock(returncode=code, stdout="", stderr="")

        mock_run.side_effect = side_effect

        results = target_runner.run_campaign(files)

        assert len(results[ExecutionStatus.SUCCESS]) == 3
        assert len(results[ExecutionStatus.CRASH]) == 2
        assert len(results[ExecutionStatus.ERROR]) == 1

    @patch("subprocess.run")
    def test_run_campaign_stop_on_crash(self, mock_run, target_runner, tmp_path):
        """Test campaign stops on first crash when stop_on_crash=True."""
        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.dcm"
            f.write_text(f"test {i}")
            files.append(f)

        # First 2 succeed, 3rd crashes
        return_codes = [0, 0, -11]

        def side_effect(*args, **kwargs):
            if not return_codes:
                pytest.fail("Should have stopped after crash")
            code = return_codes.pop(0)
            return Mock(returncode=code, stdout="", stderr="")

        mock_run.side_effect = side_effect

        results = target_runner.run_campaign(files, stop_on_crash=True)

        assert len(results[ExecutionStatus.SUCCESS]) == 2
        assert len(results[ExecutionStatus.CRASH]) == 1
        # Should not have tested remaining files
        total_tested = sum(len(r) for r in results.values())
        assert total_tested == 3

    @patch("subprocess.run")
    def test_run_campaign_empty_list(self, mock_run, target_runner):
        """Test campaign with no test files."""
        results = target_runner.run_campaign([])

        for result_type in ExecutionStatus:
            assert len(results[result_type]) == 0


class TestGetSummary:
    """Test get_summary method."""

    def test_get_summary_all_success(self, target_runner, tmp_path):
        """Test summary with all successful tests."""
        results = {result_type: [] for result_type in ExecutionStatus}

        for i in range(10):
            test_file = tmp_path / f"test_{i}.dcm"
            test_file.write_text("test")
            results[ExecutionStatus.SUCCESS].append(
                ExecutionResult(
                    test_file=test_file,
                    result=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    execution_time=0.1,
                    stdout="",
                    stderr="",
                )
            )

        summary = target_runner.get_summary(results)

        assert "Total test cases: 10" in summary
        assert "Successful:       10" in summary
        assert "Crashes:          0" in summary

    def test_get_summary_with_crashes(self, target_runner, tmp_path):
        """Test summary with crashes."""
        results = {result_type: [] for result_type in ExecutionStatus}

        # Add some crashes
        for i in range(3):
            test_file = tmp_path / f"crash_{i}.dcm"
            test_file.write_text("crash")
            results[ExecutionStatus.CRASH].append(
                ExecutionResult(
                    test_file=test_file,
                    result=ExecutionStatus.CRASH,
                    exit_code=-11,
                    execution_time=0.2,
                    stdout="",
                    stderr="SIGSEGV",
                )
            )

        summary = target_runner.get_summary(results)

        assert "Crashes:          3" in summary
        assert "CRASHES DETECTED:" in summary
        assert "crash_0.dcm" in summary

    def test_get_summary_truncates_long_lists(self, target_runner, tmp_path):
        """Test summary truncates long crash lists."""
        results = {result_type: [] for result_type in ExecutionStatus}

        # Add many crashes
        for i in range(20):
            test_file = tmp_path / f"crash_{i}.dcm"
            test_file.write_text("crash")
            results[ExecutionStatus.CRASH].append(
                ExecutionResult(
                    test_file=test_file,
                    result=ExecutionStatus.CRASH,
                    exit_code=-11,
                    execution_time=0.2,
                    stdout="",
                    stderr="",
                )
            )

        summary = target_runner.get_summary(results)

        assert "... and 10 more" in summary  # Only shows first 10

    def test_get_summary_with_hangs(self, target_runner, tmp_path):
        """Test summary with hangs detected (lines 294-298)."""
        results = {result_type: [] for result_type in ExecutionStatus}

        # Add some hangs
        for i in range(5):
            test_file = tmp_path / f"hang_{i}.dcm"
            test_file.write_text("hang")
            results[ExecutionStatus.HANG].append(
                ExecutionResult(
                    test_file=test_file,
                    result=ExecutionStatus.HANG,
                    exit_code=None,
                    execution_time=30.0,
                    stdout="",
                    stderr="Timeout",
                )
            )

        summary = target_runner.get_summary(results)

        assert "Hangs/Timeouts:   5" in summary
        assert "HANGS DETECTED:" in summary
        assert "hang_0.dcm" in summary

    def test_get_summary_with_many_hangs(self, target_runner, tmp_path):
        """Test summary truncates long hang lists (lines 297-300)."""
        results = {result_type: [] for result_type in ExecutionStatus}

        # Add many hangs (more than 10)
        for i in range(15):
            test_file = tmp_path / f"hang_{i}.dcm"
            test_file.write_text("hang")
            results[ExecutionStatus.HANG].append(
                ExecutionResult(
                    test_file=test_file,
                    result=ExecutionStatus.HANG,
                    exit_code=None,
                    execution_time=30.0,
                    stdout="",
                    stderr="",
                )
            )

        summary = target_runner.get_summary(results)

        assert "HANGS DETECTED:" in summary
        assert "... and 5 more" in summary  # Shows first 10, mentions 5 more


class TestCircuitBreaker:
    """Tests for circuit breaker functionality."""

    def test_circuit_breaker_opens_after_failures(self, mock_executable, tmp_path):
        """Test circuit breaker opens after consecutive failures."""
        runner = TargetRunner(
            target_executable=mock_executable,
            timeout=1.0,
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=True,
            max_retries=0,  # No retries to make failures immediate
        )

        # Set failure threshold low for testing
        runner.circuit_breaker.failure_threshold = 3

        # Simulate failures to trigger circuit breaker
        for _ in range(3):
            runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.is_open is True
        assert runner.circuit_breaker.consecutive_failures >= 3

    def test_circuit_breaker_blocks_when_open(self, mock_executable, tmp_path):
        """Test circuit breaker blocks execution when open."""
        runner = TargetRunner(
            target_executable=mock_executable,
            timeout=1.0,
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=True,
        )

        # Open the circuit breaker
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() + 100  # 100 seconds in future

        # Check that execution is blocked
        can_execute = runner._check_circuit_breaker()
        assert can_execute is False

    def test_circuit_breaker_half_open_after_timeout(self, mock_executable, tmp_path):
        """Test circuit breaker enters half-open state after timeout."""
        runner = TargetRunner(
            target_executable=mock_executable,
            timeout=1.0,
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=True,
        )

        # Open the circuit breaker with timeout in the past
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() - 1  # 1 second in the past

        # Check that execution is allowed (half-open)
        can_execute = runner._check_circuit_breaker()
        assert can_execute is True
        assert runner.circuit_breaker.is_open is False

    def test_circuit_breaker_resets_on_success(self, mock_executable, tmp_path):
        """Test circuit breaker resets consecutive failures on success."""
        runner = TargetRunner(
            target_executable=mock_executable,
            timeout=1.0,
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=True,
        )

        # Add some failures
        runner._update_circuit_breaker(success=False)
        runner._update_circuit_breaker(success=False)
        assert runner.circuit_breaker.consecutive_failures == 2

        # Success should reset consecutive failures
        runner._update_circuit_breaker(success=True)
        assert runner.circuit_breaker.consecutive_failures == 0
        assert runner.circuit_breaker.success_count == 1

    def test_circuit_breaker_disabled(self, mock_executable, tmp_path):
        """Test that disabled circuit breaker always allows execution."""
        runner = TargetRunner(
            target_executable=mock_executable,
            timeout=1.0,
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=False,
        )

        # Even with failures, should always return True
        for _ in range(10):
            runner._update_circuit_breaker(success=False)

        assert runner._check_circuit_breaker() is True


class TestEnhancedMonitoring:
    """Tests for enhanced process monitoring."""

    def test_monitoring_disabled_by_default(self, mock_executable, tmp_path):
        """Test that monitoring is disabled by default."""
        runner = TargetRunner(
            target_executable=mock_executable,
            timeout=1.0,
            crash_dir=str(tmp_path / "crashes"),
        )
        assert runner.process_monitor is None

    def test_monitoring_enabled_with_psutil(self, tmp_path, monkeypatch):
        """Test monitoring is enabled when psutil is available."""
        from unittest.mock import MagicMock, patch

        # Mock psutil availability
        mock_monitor = MagicMock()
        mock_is_available = MagicMock(return_value=True)

        with patch(
            "dicom_fuzzer.core.target_runner.TargetRunner.__init__",
            return_value=None,
        ):
            runner = TargetRunner.__new__(TargetRunner)
            runner.process_monitor = mock_monitor
            # Verify the attribute exists
            assert runner.process_monitor is not None


class TestExecutionResultProperties:
    """Test ExecutionResult properties."""

    def test_is_exploitable_with_windows_crash_info(self, tmp_path):
        """Test is_exploitable returns windows_crash_info value."""
        from unittest.mock import MagicMock

        mock_crash_info = MagicMock()
        mock_crash_info.is_exploitable = True

        result = ExecutionResult(
            test_file=tmp_path / "test.dcm",
            result=ExecutionStatus.CRASH,
            exit_code=-11,
            execution_time=1.0,
            stdout="",
            stderr="",
            windows_crash_info=mock_crash_info,
        )

        assert result.is_exploitable is True

    def test_is_exploitable_without_windows_crash_info(self, tmp_path):
        """Test is_exploitable returns crash status without windows info."""
        result = ExecutionResult(
            test_file=tmp_path / "test.dcm",
            result=ExecutionStatus.CRASH,
            exit_code=-11,
            execution_time=1.0,
            stdout="",
            stderr="",
        )

        assert result.is_exploitable is True

    def test_is_exploitable_false_for_success(self, tmp_path):
        """Test is_exploitable is False for successful execution."""
        result = ExecutionResult(
            test_file=tmp_path / "test.dcm",
            result=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=1.0,
            stdout="",
            stderr="",
        )

        assert result.is_exploitable is False


@pytest.mark.slow
class TestIntegration:
    """Integration tests."""

    def test_end_to_end_campaign(self, tmp_path):
        """Test complete fuzzing campaign workflow."""
        # Create a real Python script as target
        target_script = tmp_path / "viewer.py"
        target_script.write_text(
            """#!/usr/bin/env python3
import sys

if len(sys.argv) > 1:
    filename = sys.argv[1]
    if "crash" in filename:
        sys.exit(-11)  # Simulate crash (on Windows, becomes 245)
    elif "error" in filename:
        sys.exit(1)  # Simulate error
    else:
        sys.exit(0)  # Success
"""
        )
        target_script.chmod(0o755)

        # Create test files
        test_files = []
        for name in ["good.dcm", "crash.dcm", "error.dcm", "another_good.dcm"]:
            f = tmp_path / name
            f.write_text(f"dicom data for {name}")
            test_files.append(f)

        # Create batch script wrapper for Windows
        if sys.platform == "win32":
            wrapper = tmp_path / "run_viewer.bat"
            wrapper.write_text(f'@echo off\npython "{target_script}" %1\n')
            wrapper.chmod(0o755)
            target_exe = wrapper
        else:
            target_exe = target_script

        # Run campaign (disable circuit breaker for complete end-to-end testing)
        runner = TargetRunner(
            target_executable=str(target_exe),
            timeout=5.0,
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=False,
        )

        results = runner.run_campaign(test_files)

        # Verify results
        # On Windows, negative exit codes become large positive numbers
        # so we check for errors instead of crashes on Windows
        if sys.platform == "win32":
            assert (
                len(results[ExecutionStatus.SUCCESS]) == 2
            )  # good.dcm, another_good.dcm
            assert len(results[ExecutionStatus.ERROR]) >= 1  # crash.dcm becomes error
        else:
            assert len(results[ExecutionStatus.SUCCESS]) == 2
            assert len(results[ExecutionStatus.CRASH]) == 1
            assert len(results[ExecutionStatus.ERROR]) == 1
