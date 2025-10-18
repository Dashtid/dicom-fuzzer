"""Comprehensive tests for dicom_fuzzer.core.target_runner module.

This test suite provides thorough coverage of target runner functionality,
including execution monitoring, crash detection, circuit breaker pattern, and resource management.
"""

import subprocess
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from dicom_fuzzer.core.target_runner import (
    CircuitBreakerState,
    ExecutionResult,
    ExecutionStatus,
    TargetRunner,
)
from dicom_fuzzer.core.resource_manager import ResourceLimits


class TestExecutionStatus:
    """Test suite for ExecutionStatus enum."""

    def test_all_statuses_defined(self):
        """Test all execution statuses are defined."""
        assert ExecutionStatus.SUCCESS
        assert ExecutionStatus.CRASH
        assert ExecutionStatus.HANG
        assert ExecutionStatus.ERROR
        assert ExecutionStatus.SKIPPED
        assert ExecutionStatus.OOM
        assert ExecutionStatus.RESOURCE_EXHAUSTED

    def test_status_values(self):
        """Test execution status string values."""
        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.CRASH.value == "crash"
        assert ExecutionStatus.HANG.value == "hang"
        assert ExecutionStatus.ERROR.value == "error"
        assert ExecutionStatus.SKIPPED.value == "skipped"
        assert ExecutionStatus.OOM.value == "oom"
        assert ExecutionStatus.RESOURCE_EXHAUSTED.value == "resource_exhausted"


class TestExecutionResult:
    """Test suite for ExecutionResult dataclass."""

    def test_initialization_required_fields(self, tmp_path):
        """Test ExecutionResult with required fields."""
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=1.5,
            stdout="Output",
            stderr="",
        )

        assert result.test_file == test_file
        assert result.result == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.execution_time == 1.5
        assert result.stdout == "Output"
        assert result.stderr == ""

    def test_initialization_defaults(self, tmp_path):
        """Test ExecutionResult default values."""
        test_file = tmp_path / "test.dcm"
        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.CRASH,
            exit_code=-11,
            execution_time=0.5,
            stdout="",
            stderr="Segfault",
        )

        assert result.exception is None
        assert result.crash_hash is None
        assert result.retry_count == 0

    def test_bool_true_on_success(self, tmp_path):
        """Test ExecutionResult is truthy when successful."""
        result = ExecutionResult(
            test_file=tmp_path / "test.dcm",
            result=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=1.0,
            stdout="",
            stderr="",
        )

        assert bool(result) is True

    def test_bool_false_on_failure(self, tmp_path):
        """Test ExecutionResult is falsy when not successful."""
        result = ExecutionResult(
            test_file=tmp_path / "test.dcm",
            result=ExecutionStatus.CRASH,
            exit_code=-11,
            execution_time=1.0,
            stdout="",
            stderr="",
        )

        assert bool(result) is False

    def test_with_exception(self, tmp_path):
        """Test ExecutionResult with exception."""
        exception = Exception("Test exception")
        result = ExecutionResult(
            test_file=tmp_path / "test.dcm",
            result=ExecutionStatus.ERROR,
            exit_code=1,
            execution_time=0.5,
            stdout="",
            stderr="Error occurred",
            exception=exception,
        )

        assert result.exception == exception


class TestCircuitBreakerState:
    """Test suite for CircuitBreakerState dataclass."""

    def test_initialization_defaults(self):
        """Test CircuitBreakerState with default values."""
        state = CircuitBreakerState()

        assert state.failure_count == 0
        assert state.success_count == 0
        assert state.consecutive_failures == 0
        assert state.is_open is False
        assert state.open_until == 0.0
        assert state.failure_threshold == 5
        assert state.reset_timeout == 60.0

    def test_custom_thresholds(self):
        """Test CircuitBreakerState with custom thresholds."""
        state = CircuitBreakerState(failure_threshold=3, reset_timeout=30.0)

        assert state.failure_threshold == 3
        assert state.reset_timeout == 30.0

    def test_state_tracking(self):
        """Test CircuitBreakerState tracks failures and successes."""
        state = CircuitBreakerState()

        state.failure_count = 10
        state.success_count = 5
        state.consecutive_failures = 3

        assert state.failure_count == 10
        assert state.success_count == 5
        assert state.consecutive_failures == 3


class TestTargetRunnerInitialization:
    """Test suite for TargetRunner initialization."""

    def test_initialization_with_valid_executable(self, tmp_path):
        """Test TargetRunner with valid executable."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(
            target_executable=str(exe),
            timeout=10.0,
            crash_dir=str(tmp_path / "crashes"),
        )

        assert runner.target_executable == exe
        assert runner.timeout == 10.0
        assert runner.crash_dir.exists()

    def test_initialization_creates_crash_dir(self, tmp_path):
        """Test that crash directory is created."""
        exe = tmp_path / "target.exe"
        exe.touch()
        crash_dir = tmp_path / "crashes"

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(crash_dir))

        assert crash_dir.exists()

    def test_initialization_nonexistent_executable(self, tmp_path):
        """Test TargetRunner with nonexistent executable raises error."""
        with pytest.raises(FileNotFoundError, match="Target executable not found"):
            TargetRunner(target_executable=str(tmp_path / "nonexistent.exe"))

    def test_initialization_with_resource_limits(self, tmp_path):
        """Test TargetRunner with custom resource limits."""
        exe = tmp_path / "target.exe"
        exe.touch()
        limits = ResourceLimits(max_memory_mb=512, max_cpu_seconds=60)

        runner = TargetRunner(
            target_executable=str(exe), resource_limits=limits, crash_dir=str(tmp_path)
        )

        assert runner.resource_manager.limits.max_memory_mb == 512

    def test_initialization_circuit_breaker_enabled(self, tmp_path):
        """Test circuit breaker is enabled by default."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        assert runner.enable_circuit_breaker is True
        assert isinstance(runner.circuit_breaker, CircuitBreakerState)

    def test_initialization_circuit_breaker_disabled(self, tmp_path):
        """Test circuit breaker can be disabled."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(
            target_executable=str(exe), enable_circuit_breaker=False, crash_dir=str(tmp_path)
        )

        assert runner.enable_circuit_breaker is False


class TestCircuitBreakerLogic:
    """Test suite for circuit breaker logic."""

    def test_check_circuit_breaker_closed(self, tmp_path):
        """Test circuit breaker allows execution when closed."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        assert runner._check_circuit_breaker() is True

    def test_check_circuit_breaker_open(self, tmp_path):
        """Test circuit breaker blocks execution when open."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() + 60

        assert runner._check_circuit_breaker() is False

    def test_check_circuit_breaker_half_open(self, tmp_path):
        """Test circuit breaker transitions to half-open after timeout."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() - 1  # Expired

        assert runner._check_circuit_breaker() is True
        assert runner.circuit_breaker.is_open is False

    def test_update_circuit_breaker_on_success(self, tmp_path):
        """Test circuit breaker update on success."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        runner._update_circuit_breaker(success=True)

        assert runner.circuit_breaker.success_count == 1
        assert runner.circuit_breaker.consecutive_failures == 0

    def test_update_circuit_breaker_on_failure(self, tmp_path):
        """Test circuit breaker update on failure."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.failure_count == 1
        assert runner.circuit_breaker.consecutive_failures == 1

    def test_circuit_breaker_opens_on_threshold(self, tmp_path):
        """Test circuit breaker opens after threshold failures."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Trigger threshold failures
        for _ in range(runner.circuit_breaker.failure_threshold):
            runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.is_open is True

    def test_circuit_breaker_disabled_always_allows(self, tmp_path):
        """Test disabled circuit breaker always allows execution."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(
            target_executable=str(exe), enable_circuit_breaker=False, crash_dir=str(tmp_path)
        )

        runner.circuit_breaker.is_open = True

        assert runner._check_circuit_breaker() is True


class TestErrorClassification:
    """Test suite for error classification."""

    def test_classify_oom_error(self, tmp_path):
        """Test classification of out of memory errors."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        status = runner._classify_error("Out of memory", None)

        assert status == ExecutionStatus.OOM

    def test_classify_resource_exhausted(self, tmp_path):
        """Test classification of resource exhaustion."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        status = runner._classify_error("Resource limit exceeded", None)

        assert status == ExecutionStatus.RESOURCE_EXHAUSTED

    def test_classify_crash_negative_return_code(self, tmp_path):
        """Test classification of crash with negative return code."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        status = runner._classify_error("", -11)

        assert status == ExecutionStatus.CRASH

    def test_classify_generic_error(self, tmp_path):
        """Test classification of generic error."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        status = runner._classify_error("Unknown error", 1)

        assert status == ExecutionStatus.ERROR


class TestExecuteTest:
    """Test suite for execute_test method."""

    @patch("subprocess.run")
    def test_execute_test_success(self, mock_run, tmp_path):
        """Test successful test execution."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SUCCESS
        assert result.exit_code == 0

    @patch("subprocess.run")
    def test_execute_test_crash(self, mock_run, tmp_path):
        """Test test execution with crash."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(returncode=-11, stdout="", stderr="Segfault")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.CRASH
        assert result.exit_code == -11

    @patch("subprocess.run")
    def test_execute_test_timeout(self, mock_run, tmp_path):
        """Test test execution timeout."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["test"], timeout=5.0, output=b"", stderr=b""
        )

        runner = TargetRunner(
            target_executable=str(exe), timeout=5.0, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.HANG
        assert result.exit_code is None

    @patch("subprocess.run")
    def test_execute_test_memory_error(self, mock_run, tmp_path):
        """Test test execution with memory error."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.side_effect = MemoryError("Out of memory")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.OOM

    @patch("subprocess.run")
    def test_execute_test_circuit_breaker_open(self, mock_run, tmp_path):
        """Test execution is skipped when circuit breaker is open."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() + 60

        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SKIPPED
        assert not mock_run.called

    @patch("subprocess.run")
    def test_execute_test_retry_on_error(self, mock_run, tmp_path):
        """Test retry logic on transient errors."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # First call fails, second succeeds
        mock_run.side_effect = [
            Mock(returncode=1, stdout="", stderr="Transient error"),
            Mock(returncode=0, stdout="Success", stderr=""),
        ]

        runner = TargetRunner(
            target_executable=str(exe), max_retries=2, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SUCCESS
        assert result.retry_count == 1


class TestRunCampaign:
    """Test suite for run_campaign method."""

    @patch("subprocess.run")
    def test_run_campaign_all_success(self, mock_run, tmp_path):
        """Test campaign with all successful tests."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(3)]
        for f in test_files:
            f.touch()

        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        results = runner.run_campaign(test_files)

        assert len(results[ExecutionStatus.SUCCESS]) == 3
        assert len(results[ExecutionStatus.CRASH]) == 0

    @patch("subprocess.run")
    def test_run_campaign_with_crashes(self, mock_run, tmp_path):
        """Test campaign with some crashes."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(3)]
        for f in test_files:
            f.touch()

        # First test crashes, others succeed
        mock_run.side_effect = [
            Mock(returncode=-11, stdout="", stderr="Crash"),
            Mock(returncode=0, stdout="Success", stderr=""),
            Mock(returncode=0, stdout="Success", stderr=""),
        ]

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        results = runner.run_campaign(test_files)

        assert len(results[ExecutionStatus.CRASH]) == 1
        assert len(results[ExecutionStatus.SUCCESS]) == 2

    @patch("subprocess.run")
    def test_run_campaign_stop_on_crash(self, mock_run, tmp_path):
        """Test campaign stops on first crash when requested."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(3)]
        for f in test_files:
            f.touch()

        mock_run.return_value = Mock(returncode=-11, stdout="", stderr="Crash")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        results = runner.run_campaign(test_files, stop_on_crash=True)

        assert len(results[ExecutionStatus.CRASH]) == 1


class TestGetSummary:
    """Test suite for get_summary method."""

    def test_get_summary_with_results(self, tmp_path):
        """Test summary generation with results."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        results = {
            ExecutionStatus.SUCCESS: [
                Mock(test_file=Path("test1.dcm"), exit_code=0, retry_count=0)
            ],
            ExecutionStatus.CRASH: [
                Mock(test_file=Path("test2.dcm"), exit_code=-11, retry_count=0)
            ],
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
            ExecutionStatus.OOM: [],
            ExecutionStatus.SKIPPED: [],
            ExecutionStatus.RESOURCE_EXHAUSTED: [],
        }

        summary = runner.get_summary(results)

        assert "Fuzzing Campaign Summary" in summary
        assert "Total test cases: 2" in summary
        assert "Successful:       1" in summary
        assert "Crashes:          1" in summary


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    @patch("subprocess.run")
    def test_complete_fuzzing_workflow(self, mock_run, tmp_path):
        """Test complete fuzzing workflow with mixed results."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(5)]
        for f in test_files:
            f.touch()

        # Mix of results
        mock_run.side_effect = [
            Mock(returncode=0, stdout="OK", stderr=""),  # Success
            Mock(returncode=-11, stdout="", stderr="Crash"),  # Crash
            Mock(returncode=0, stdout="OK", stderr=""),  # Success
            Mock(returncode=1, stdout="", stderr="Error"),  # Error
            Mock(returncode=0, stdout="OK", stderr=""),  # Success
        ]

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        results = runner.run_campaign(test_files)

        assert len(results[ExecutionStatus.SUCCESS]) == 3
        assert len(results[ExecutionStatus.CRASH]) == 1
        assert len(results[ExecutionStatus.ERROR]) == 1

        summary = runner.get_summary(results)
        assert "Total test cases: 5" in summary
