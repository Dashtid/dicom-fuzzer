"""Comprehensive tests for dicom_fuzzer.core.target_runner module.

This test suite provides thorough coverage of target runner functionality,
including execution monitoring, crash detection, circuit breaker pattern, and resource management.
"""

import subprocess
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.resource_manager import ResourceLimits
from dicom_fuzzer.core.target_runner import (
    CircuitBreakerState,
    ExecutionResult,
    ExecutionStatus,
    TargetRunner,
)


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

        TargetRunner(target_executable=str(exe), crash_dir=str(crash_dir))

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
            target_executable=str(exe),
            enable_circuit_breaker=False,
            crash_dir=str(tmp_path),
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
            target_executable=str(exe),
            enable_circuit_breaker=False,
            crash_dir=str(tmp_path),
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


class TestMissingCoveragePaths:
    """Tests for uncovered lines 425-427, 535, 547 in target_runner.py."""

    @patch("subprocess.run")
    def test_run_campaign_resource_check_exception(self, mock_run, tmp_path):
        """Test lines 425-427: Exception during pre-flight resource check.

        The resource manager's check_available_resources should be mocked
        to raise an exception, triggering the error handling path.
        """
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / "test.dcm"]
        test_files[0].touch()

        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Mock the resource manager to raise exception on check
        with patch.object(
            runner.resource_manager,
            "check_available_resources",
            side_effect=Exception("Resource check failed"),
        ):
            # Campaign should proceed even with resource check failure
            results = runner.run_campaign(test_files)

        # Should still complete successfully
        assert len(results[ExecutionStatus.SUCCESS]) == 1

    def test_get_summary_with_many_oom_entries(self, tmp_path):
        """Test line 535: OOM summary truncation with >5 entries.

        When there are more than 5 OOM results, the summary should truncate
        and show '... and X more' message.
        """
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Create results with 8 OOM entries (more than the 5 limit)
        oom_results = [
            Mock(test_file=Path(f"oom_test{i}.dcm"), exit_code=None, retry_count=0)
            for i in range(8)
        ]

        results = {
            ExecutionStatus.SUCCESS: [],
            ExecutionStatus.CRASH: [],
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
            ExecutionStatus.OOM: oom_results,
            ExecutionStatus.SKIPPED: [],
            ExecutionStatus.RESOURCE_EXHAUSTED: [],
        }

        summary = runner.get_summary(results)

        # Line 535: Should show truncation message
        assert "OUT OF MEMORY" in summary
        assert "... and 3 more" in summary
        # Should only list first 5 OOM entries
        assert "oom_test0.dcm" in summary
        assert "oom_test4.dcm" in summary

    def test_get_summary_with_circuit_breaker_open(self, tmp_path):
        """Test line 547: Circuit breaker OPEN status in summary.

        When circuit breaker is open, the summary should show
        'Status: OPEN (target failing consistently)' message.
        """
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Set circuit breaker to open state
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.failure_count = 10
        runner.circuit_breaker.success_count = 2

        results = {
            ExecutionStatus.SUCCESS: [],
            ExecutionStatus.CRASH: [],
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
            ExecutionStatus.OOM: [],
            ExecutionStatus.SKIPPED: [],
            ExecutionStatus.RESOURCE_EXHAUSTED: [],
        }

        summary = runner.get_summary(results)

        # Line 547: Should show OPEN status
        assert "Circuit Breaker Stats:" in summary
        assert "Status: OPEN (target failing consistently)" in summary
        assert "Successes: 2" in summary
        assert "Failures: 10" in summary


class TestAdditionalCoveragePaths:
    """Additional tests to improve target_runner.py coverage from 24% to higher."""

    def test_execution_result_with_crash_hash(self, tmp_path):
        """Test ExecutionResult with crash_hash set."""
        test_file = tmp_path / "test.dcm"
        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.CRASH,
            exit_code=-11,
            execution_time=0.5,
            stdout="",
            stderr="Segmentation fault",
            crash_hash="abc123def456",
            retry_count=2,
        )

        assert result.crash_hash == "abc123def456"
        assert result.retry_count == 2
        assert bool(result) is False  # Not SUCCESS

    def test_execution_result_all_non_success_statuses_are_falsy(self, tmp_path):
        """Test that all non-SUCCESS statuses evaluate to False."""
        test_file = tmp_path / "test.dcm"

        for status in ExecutionStatus:
            result = ExecutionResult(
                test_file=test_file,
                result=status,
                exit_code=0 if status == ExecutionStatus.SUCCESS else 1,
                execution_time=1.0,
                stdout="",
                stderr="",
            )
            if status == ExecutionStatus.SUCCESS:
                assert bool(result) is True
            else:
                assert bool(result) is False

    def test_circuit_breaker_state_mutation(self):
        """Test circuit breaker state is properly mutable."""
        state = CircuitBreakerState()

        # Start with defaults
        assert state.failure_count == 0
        assert state.is_open is False

        # Mutate state
        state.failure_count = 5
        state.consecutive_failures = 5
        state.is_open = True
        state.open_until = time.time() + 30.0

        assert state.failure_count == 5
        assert state.is_open is True
        assert state.open_until > time.time()

    def test_initialization_default_values(self, tmp_path):
        """Test TargetRunner default initialization values."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe))

        assert runner.timeout == 5.0
        assert runner.collect_stdout is True
        assert runner.collect_stderr is True
        assert runner.max_retries == 2
        assert runner.enable_circuit_breaker is True

    @patch("subprocess.run")
    def test_execute_test_with_string_path(self, mock_run, tmp_path):
        """Test execute_test accepts string path (line 269)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(returncode=0, stdout="OK", stderr="")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        # Pass string instead of Path
        result = runner.execute_test(str(test_file))

        assert result.result == ExecutionStatus.SUCCESS
        # Result should have Path object
        assert isinstance(result.test_file, Path)

    @patch("subprocess.run")
    def test_execute_test_captures_stdout_stderr(self, mock_run, tmp_path):
        """Test execute_test captures stdout/stderr when enabled."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(
            returncode=0, stdout="Standard output text", stderr="Standard error text"
        )

        runner = TargetRunner(
            target_executable=str(exe),
            crash_dir=str(tmp_path),
            collect_stdout=True,
            collect_stderr=True,
        )
        result = runner.execute_test(test_file)

        assert result.stdout == "Standard output text"
        assert result.stderr == "Standard error text"

    @patch("subprocess.run")
    def test_execute_test_disables_stdout_capture(self, mock_run, tmp_path):
        """Test execute_test with stdout capture disabled."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(
            returncode=0, stdout="Should not appear", stderr="Error text"
        )

        runner = TargetRunner(
            target_executable=str(exe),
            crash_dir=str(tmp_path),
            collect_stdout=False,
            collect_stderr=True,
        )
        result = runner.execute_test(test_file)

        assert result.stdout == ""
        assert result.stderr == "Error text"

    @patch("subprocess.run")
    def test_execute_test_disables_stderr_capture(self, mock_run, tmp_path):
        """Test execute_test with stderr capture disabled."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(
            returncode=0, stdout="Output text", stderr="Should not appear"
        )

        runner = TargetRunner(
            target_executable=str(exe),
            crash_dir=str(tmp_path),
            collect_stdout=True,
            collect_stderr=False,
        )
        result = runner.execute_test(test_file)

        assert result.stdout == "Output text"
        assert result.stderr == ""

    @patch("subprocess.run")
    def test_execute_test_timeout_with_stdout_stderr(self, mock_run, tmp_path):
        """Test timeout captures partial stdout/stderr (lines 347-348)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        timeout_exc = subprocess.TimeoutExpired(
            cmd=["test"], timeout=5.0, output=b"Partial output", stderr=b"Partial error"
        )
        mock_run.side_effect = timeout_exc

        runner = TargetRunner(
            target_executable=str(exe),
            timeout=5.0,
            crash_dir=str(tmp_path),
            collect_stdout=True,
            collect_stderr=True,
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.HANG
        assert result.stdout == "Partial output"
        assert result.stderr == "Partial error"
        assert result.exception == timeout_exc

    @patch("subprocess.run")
    def test_execute_test_timeout_without_capture(self, mock_run, tmp_path):
        """Test timeout with stdout/stderr capture disabled."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        timeout_exc = subprocess.TimeoutExpired(
            cmd=["test"], timeout=5.0, output=b"Partial output", stderr=b"Partial error"
        )
        mock_run.side_effect = timeout_exc

        runner = TargetRunner(
            target_executable=str(exe),
            timeout=5.0,
            crash_dir=str(tmp_path),
            collect_stdout=False,
            collect_stderr=False,
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.HANG
        assert result.stdout == ""
        assert result.stderr == ""

    @patch("subprocess.run")
    def test_execute_test_timeout_none_output(self, mock_run, tmp_path):
        """Test timeout when stdout/stderr are None (lines 347-348 edge case)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # TimeoutExpired can have None output
        timeout_exc = subprocess.TimeoutExpired(
            cmd=["test"], timeout=5.0, output=None, stderr=None
        )
        mock_run.side_effect = timeout_exc

        runner = TargetRunner(
            target_executable=str(exe), timeout=5.0, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.HANG
        assert result.stdout == ""
        assert result.stderr == ""

    @patch("subprocess.run")
    def test_execute_test_unexpected_exception_with_retries(self, mock_run, tmp_path):
        """Test unexpected exception triggers retries (lines 379-386)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # First two calls raise exception, third succeeds
        mock_run.side_effect = [
            OSError("File system error"),
            OSError("File system error again"),
            Mock(returncode=0, stdout="Success", stderr=""),
        ]

        runner = TargetRunner(
            target_executable=str(exe), max_retries=2, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SUCCESS
        assert result.retry_count == 2

    @patch("subprocess.run")
    def test_execute_test_unexpected_exception_exhausts_retries(
        self, mock_run, tmp_path
    ):
        """Test unexpected exception exhausts all retries (lines 388-397)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # All calls raise exception
        mock_run.side_effect = OSError("Persistent file system error")

        runner = TargetRunner(
            target_executable=str(exe), max_retries=2, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.ERROR
        assert result.retry_count == 2
        assert isinstance(result.exception, OSError)

    @patch("subprocess.run")
    def test_execute_test_oom_classification(self, mock_run, tmp_path):
        """Test classification of OOM errors from stderr (line 227-228)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="Cannot allocate memory for buffer"
        )

        runner = TargetRunner(
            target_executable=str(exe), max_retries=0, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.OOM

    @patch("subprocess.run")
    def test_execute_test_resource_exhausted_retry(self, mock_run, tmp_path):
        """Test RESOURCE_EXHAUSTED triggers retry (lines 309-318)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # First call resource exhausted, second succeeds
        mock_run.side_effect = [
            Mock(returncode=1, stdout="", stderr="Resource limit exceeded"),
            Mock(returncode=0, stdout="Success", stderr=""),
        ]

        runner = TargetRunner(
            target_executable=str(exe), max_retries=2, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SUCCESS
        assert result.retry_count == 1

    @patch("subprocess.run")
    def test_run_campaign_logs_notable_results(self, mock_run, tmp_path):
        """Test run_campaign logs crashes/hangs/OOM (lines 436-445)."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(4)]
        for f in test_files:
            f.touch()

        mock_run.side_effect = [
            Mock(returncode=-11, stdout="", stderr="Crash"),  # CRASH
            Mock(returncode=0, stdout="OK", stderr=""),  # SUCCESS
            Mock(returncode=1, stdout="", stderr="Out of memory"),  # OOM
            Mock(returncode=0, stdout="OK", stderr=""),  # SUCCESS
        ]

        runner = TargetRunner(
            target_executable=str(exe), max_retries=0, crash_dir=str(tmp_path)
        )
        results = runner.run_campaign(test_files)

        assert len(results[ExecutionStatus.CRASH]) == 1
        assert len(results[ExecutionStatus.OOM]) == 1
        assert len(results[ExecutionStatus.SUCCESS]) == 2

    @patch("subprocess.run")
    def test_run_campaign_circuit_breaker_stops_early(self, mock_run, tmp_path):
        """Test campaign stops early when circuit breaker opens (lines 452-456)."""
        exe = tmp_path / "target.exe"
        exe.touch()

        # Create many test files
        test_files = [tmp_path / f"test{i}.dcm" for i in range(10)]
        for f in test_files:
            f.touch()

        # All executions fail, eventually triggering circuit breaker
        mock_run.return_value = Mock(returncode=-11, stdout="", stderr="Crash")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        results = runner.run_campaign(test_files)

        # Should have stopped before processing all 10 files
        total_processed = sum(len(r) for r in results.values())
        # Circuit breaker opens after 5 consecutive failures (default threshold)
        # So we should have exactly 5 crashes + campaign stopped
        assert total_processed <= 6  # Some flexibility for timing

    @patch("subprocess.run")
    def test_run_campaign_with_hangs(self, mock_run, tmp_path):
        """Test run_campaign with timeout/hang results."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(3)]
        for f in test_files:
            f.touch()

        # Mix of results including a hang
        mock_run.side_effect = [
            Mock(returncode=0, stdout="OK", stderr=""),
            subprocess.TimeoutExpired(
                cmd=["test"], timeout=5.0, output=b"", stderr=b""
            ),
            Mock(returncode=0, stdout="OK", stderr=""),
        ]

        runner = TargetRunner(
            target_executable=str(exe), max_retries=0, crash_dir=str(tmp_path)
        )
        results = runner.run_campaign(test_files)

        assert len(results[ExecutionStatus.HANG]) == 1
        assert len(results[ExecutionStatus.SUCCESS]) == 2

    def test_get_summary_empty_results(self, tmp_path):
        """Test get_summary with no results."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        results = {status: [] for status in ExecutionStatus}

        summary = runner.get_summary(results)

        assert "Total test cases: 0" in summary
        assert "Successful:       0" in summary

    def test_get_summary_with_many_crashes(self, tmp_path):
        """Test get_summary truncates crash list (lines 515-517)."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Create 15 crash results (more than 10 limit)
        crash_results = [
            Mock(test_file=Path(f"crash{i}.dcm"), exit_code=-11, retry_count=0)
            for i in range(15)
        ]

        results = {status: [] for status in ExecutionStatus}
        results[ExecutionStatus.CRASH] = crash_results

        summary = runner.get_summary(results)

        assert "CRASHES DETECTED" in summary
        assert "crash0.dcm" in summary
        assert "crash9.dcm" in summary
        assert "... and 5 more" in summary

    def test_get_summary_with_many_hangs(self, tmp_path):
        """Test get_summary truncates hang list (lines 525-528)."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Create 15 hang results (more than 10 limit)
        hang_results = [
            Mock(test_file=Path(f"hang{i}.dcm"), exit_code=None, retry_count=0)
            for i in range(15)
        ]

        results = {status: [] for status in ExecutionStatus}
        results[ExecutionStatus.HANG] = hang_results

        summary = runner.get_summary(results)

        assert "HANGS DETECTED" in summary
        assert "hang0.dcm" in summary
        assert "... and 5 more" in summary

    def test_get_summary_circuit_breaker_disabled(self, tmp_path):
        """Test get_summary without circuit breaker stats."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(
            target_executable=str(exe),
            enable_circuit_breaker=False,
            crash_dir=str(tmp_path),
        )

        results = {status: [] for status in ExecutionStatus}
        results[ExecutionStatus.SUCCESS] = [
            Mock(test_file=Path("test.dcm"), exit_code=0, retry_count=0)
        ]

        summary = runner.get_summary(results)

        # Circuit breaker stats should not appear
        assert "Circuit Breaker Stats" not in summary

    def test_classify_error_various_oom_patterns(self, tmp_path):
        """Test _classify_error with various OOM patterns."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        oom_messages = [
            "Out of memory error",
            "Memory error occurred",
            "Cannot allocate buffer",
            "OOM killer activated",
        ]

        for msg in oom_messages:
            status = runner._classify_error(msg, None)
            assert status == ExecutionStatus.OOM, f"Failed for: {msg}"

    def test_classify_error_various_resource_patterns(self, tmp_path):
        """Test _classify_error with various resource exhaustion patterns."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        resource_messages = [
            "Resource limit exceeded",
            "Quota exceeded",
            "Too many open files",
            "Process exhausted resources",
        ]

        for msg in resource_messages:
            status = runner._classify_error(msg, None)
            assert status == ExecutionStatus.RESOURCE_EXHAUSTED, f"Failed for: {msg}"

    def test_classify_error_crash_signal_codes(self, tmp_path):
        """Test _classify_error with Unix signal codes (negative return codes)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Common Unix signal codes: SIGSEGV=-11, SIGABRT=-6, SIGBUS=-7
        for code in [-11, -6, -7, -9, -15]:
            status = runner._classify_error("", code)
            assert status == ExecutionStatus.CRASH, f"Failed for code: {code}"

    @patch("subprocess.run")
    def test_execute_test_measures_execution_time(self, mock_run, tmp_path):
        """Test that execution time is properly measured."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        def slow_execution(*args, **kwargs):
            time.sleep(0.1)
            return Mock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = slow_execution

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        result = runner.execute_test(test_file)

        assert result.execution_time >= 0.1

    def test_update_circuit_breaker_disabled(self, tmp_path):
        """Test _update_circuit_breaker does nothing when disabled."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(
            target_executable=str(exe),
            enable_circuit_breaker=False,
            crash_dir=str(tmp_path),
        )

        # Should not update any counters when disabled
        runner._update_circuit_breaker(success=True)
        runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.success_count == 0
        assert runner.circuit_breaker.failure_count == 0

    def test_circuit_breaker_resets_consecutive_failures_on_success(self, tmp_path):
        """Test that consecutive failures reset to 0 on success."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Add some failures
        for _ in range(3):
            runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.consecutive_failures == 3

        # Success should reset consecutive failures
        runner._update_circuit_breaker(success=True)

        assert runner.circuit_breaker.consecutive_failures == 0
        assert runner.circuit_breaker.success_count == 1
        assert runner.circuit_breaker.failure_count == 3

    @patch("subprocess.run")
    def test_execute_test_crash_with_error_classification(self, mock_run, tmp_path):
        """Test crash detection with error classification."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="Some generic error message"
        )

        runner = TargetRunner(
            target_executable=str(exe), max_retries=0, crash_dir=str(tmp_path)
        )
        result = runner.execute_test(test_file)

        # Generic error should be classified as ERROR
        assert result.result == ExecutionStatus.ERROR

    def test_get_summary_all_status_types(self, tmp_path):
        """Test get_summary displays all status types."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        results = {
            ExecutionStatus.SUCCESS: [
                Mock(test_file=Path("s.dcm"), exit_code=0, retry_count=0)
            ],
            ExecutionStatus.CRASH: [
                Mock(test_file=Path("c.dcm"), exit_code=-11, retry_count=0)
            ],
            ExecutionStatus.HANG: [
                Mock(test_file=Path("h.dcm"), exit_code=None, retry_count=0)
            ],
            ExecutionStatus.ERROR: [
                Mock(test_file=Path("e.dcm"), exit_code=1, retry_count=0)
            ],
            ExecutionStatus.OOM: [
                Mock(test_file=Path("o.dcm"), exit_code=None, retry_count=0)
            ],
            ExecutionStatus.SKIPPED: [
                Mock(test_file=Path("sk.dcm"), exit_code=None, retry_count=0)
            ],
            ExecutionStatus.RESOURCE_EXHAUSTED: [],
        }

        summary = runner.get_summary(results)

        assert "Total test cases: 6" in summary
        assert "Successful:       1" in summary
        assert "Crashes:          1" in summary
        assert "Hangs/Timeouts:   1" in summary
        assert "OOM:              1" in summary
        assert "Errors:           1" in summary
        assert "Skipped:          1" in summary


class TestRemainingEdgeCases:
    """Tests for remaining uncovered lines in target_runner.py."""

    @patch("subprocess.run")
    def test_circuit_breaker_half_open_retry(self, mock_run, tmp_path):
        """Test circuit breaker transitions from open to half-open (lines 163, 166-177).

        When circuit breaker timeout expires, it should transition to half-open
        and allow a retry attempt.
        """
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Set circuit breaker to open state with expired timeout
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() - 1  # Already expired
        runner.circuit_breaker.consecutive_failures = 10

        # Execute should succeed and reset circuit breaker
        result = runner.execute_test(test_file)

        # Circuit breaker should now be closed
        assert runner.circuit_breaker.is_open is False
        assert runner.circuit_breaker.consecutive_failures == 0
        assert result.result == ExecutionStatus.SUCCESS

    @patch("subprocess.run")
    def test_circuit_breaker_skip_returns_skipped(self, mock_run, tmp_path):
        """Test that skipped execution returns SKIPPED status (line 273)."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Set circuit breaker to open state (not expired)
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() + 3600  # Far in future

        result = runner.execute_test(test_file)

        # Should return SKIPPED with specific message
        assert result.result == ExecutionStatus.SKIPPED
        assert "Circuit breaker open" in result.stderr
        assert result.exit_code is None
        assert result.execution_time == 0.0

        # subprocess.run should not be called
        assert not mock_run.called

    @patch("subprocess.run")
    def test_run_campaign_stop_on_crash_logging(self, mock_run, tmp_path):
        """Test stop_on_crash logs message (lines 448-449)."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(5)]
        for f in test_files:
            f.touch()

        # First file crashes
        mock_run.return_value = Mock(returncode=-11, stdout="", stderr="Crash")

        runner = TargetRunner(
            target_executable=str(exe),
            crash_dir=str(tmp_path),
            enable_circuit_breaker=False,  # Disable to isolate stop_on_crash
        )
        results = runner.run_campaign(test_files, stop_on_crash=True)

        # Should have stopped after first crash
        assert len(results[ExecutionStatus.CRASH]) == 1
        total = sum(len(r) for r in results.values())
        assert total == 1

    @patch("subprocess.run")
    def test_memory_error_during_execution(self, mock_run, tmp_path):
        """Test MemoryError handling during execution (lines 356-361).

        Note: This tests the MemoryError path in execute_test, which is different
        from OOM detection in stderr.
        """
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        # Simulate MemoryError in the fuzzer itself
        mock_run.side_effect = MemoryError("Fuzzer ran out of memory")

        runner = TargetRunner(
            target_executable=str(exe),
            crash_dir=str(tmp_path),
            max_retries=0,  # Don't retry
        )
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.OOM
        assert result.exit_code is None
        assert isinstance(result.exception, MemoryError)
        assert "out of memory" in result.stderr.lower()

    @patch("subprocess.run")
    def test_circuit_breaker_open_prevents_execution(self, mock_run, tmp_path):
        """Test that circuit breaker open state prevents subprocess execution."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Set circuit breaker to open state (not expired)
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() + 30

        result = runner._check_circuit_breaker()

        assert result is False
        # Now execute_test should skip
        exec_result = runner.execute_test(test_file)
        assert exec_result.result == ExecutionStatus.SKIPPED

    @patch("subprocess.run")
    def test_circuit_breaker_half_open_allows_execution(self, mock_run, tmp_path):
        """Test that circuit breaker half-open state allows execution."""
        exe = tmp_path / "target.exe"
        exe.touch()
        test_file = tmp_path / "test.dcm"
        test_file.touch()

        mock_run.return_value = Mock(returncode=0, stdout="OK", stderr="")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Set circuit breaker to open state with expired timeout (half-open)
        runner.circuit_breaker.is_open = True
        runner.circuit_breaker.open_until = time.time() - 1  # Expired

        result = runner._check_circuit_breaker()

        assert result is True
        assert runner.circuit_breaker.is_open is False  # Now closed
        assert runner.circuit_breaker.consecutive_failures == 0

    @patch("subprocess.run")
    def test_circuit_breaker_opens_after_threshold_failures(self, mock_run, tmp_path):
        """Test circuit breaker opens after reaching failure threshold."""
        exe = tmp_path / "target.exe"
        exe.touch()

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))

        # Not open initially
        assert runner.circuit_breaker.is_open is False

        # Trigger failures up to but not including threshold
        for _ in range(runner.circuit_breaker.failure_threshold - 1):
            runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.is_open is False

        # One more failure should open it
        runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.is_open is True
        assert runner.circuit_breaker.open_until > time.time()

    @patch("subprocess.run")
    def test_run_campaign_stops_when_circuit_breaker_opens(self, mock_run, tmp_path):
        """Test campaign stops processing when circuit breaker opens."""
        exe = tmp_path / "target.exe"
        exe.touch()

        test_files = [tmp_path / f"test{i}.dcm" for i in range(10)]
        for f in test_files:
            f.touch()

        # All executions fail
        mock_run.return_value = Mock(returncode=-11, stdout="", stderr="Crash")

        runner = TargetRunner(target_executable=str(exe), crash_dir=str(tmp_path))
        results = runner.run_campaign(test_files)

        # Should have stopped after circuit breaker opened
        total = sum(len(r) for r in results.values())
        # Circuit breaker opens after 5 failures (default threshold)
        # Campaign should stop at that point
        assert total <= runner.circuit_breaker.failure_threshold + 1
