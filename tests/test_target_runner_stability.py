"""
Comprehensive stability tests for TargetRunner.

Tests all new stability features:
- Resource limit enforcement
- Retry logic for transient failures
- Circuit breaker pattern
- Error classification (OOM, resource exhaustion)
- Crash detection reliability
- Hang detection accuracy
"""

import subprocess
import sys
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


@pytest.fixture
def mock_executable(tmp_path):
    """Create a mock executable script."""
    if sys.platform == "win32":
        script = tmp_path / "test_app.bat"
        script.write_text("@echo off\nexit 0")
    else:
        script = tmp_path / "test_app.sh"
        script.write_text("#!/bin/bash\nexit 0")
        script.chmod(0o755)
    return script


@pytest.fixture
def test_file(tmp_path):
    """Create a test DICOM file."""
    test_dcm = tmp_path / "test.dcm"
    test_dcm.write_bytes(b"DICOM_TEST_DATA")
    return test_dcm


@pytest.fixture
def runner(mock_executable, tmp_path):
    """Create TargetRunner instance."""
    return TargetRunner(
        target_executable=str(mock_executable),
        timeout=2.0,
        crash_dir=str(tmp_path / "crashes"),
        max_retries=2,
        enable_circuit_breaker=True,
    )


class TestTargetRunnerBasics:
    """Test basic TargetRunner functionality."""

    def test_init_creates_crash_dir(self, mock_executable, tmp_path):
        """Test that initialization creates crash directory."""
        crash_dir = tmp_path / "my_crashes"
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(crash_dir),
        )

        assert crash_dir.exists()
        assert runner.crash_dir == crash_dir

    def test_init_validates_executable(self, tmp_path):
        """Test that initialization fails for non-existent executable."""
        fake_exe = tmp_path / "nonexistent.exe"

        with pytest.raises(FileNotFoundError, match="Target executable not found"):
            TargetRunner(target_executable=str(fake_exe))

    def test_retry_parameters(self, mock_executable, tmp_path):
        """Test that retry parameters are set correctly."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            max_retries=5,
        )

        assert runner.max_retries == 5


class TestExecutionSuccess:
    """Test successful execution scenarios."""

    def test_successful_execution(self, runner, test_file):
        """Test successful test case execution."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.SUCCESS
            assert result.exit_code == 0
            assert result.test_file == test_file
            assert result.retry_count == 0
            assert result.execution_time >= 0

    def test_collect_stdout_stderr(self, runner, test_file):
        """Test that stdout/stderr are collected when enabled."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Application output",
                stderr="Debug messages",
                args=[],
            )

            result = runner.execute_test(test_file)

            assert result.stdout == "Application output"
            assert result.stderr == "Debug messages"

    def test_disable_stdout_stderr_collection(self, mock_executable, tmp_path, test_file):
        """Test disabling stdout/stderr collection."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            collect_stdout=False,
            collect_stderr=False,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Should not be collected",
                stderr="Should not be collected",
                args=[],
            )

            result = runner.execute_test(test_file)

            assert result.stdout == ""
            assert result.stderr == ""


class TestErrorClassification:
    """Test error classification logic."""

    def test_classify_crash_negative_returncode(self, runner, test_file):
        """Test that negative return code is classified as crash."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11,  # SIGSEGV
                stdout="",
                stderr="Segmentation fault",
                args=[],
            )

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.CRASH
            assert result.exit_code == -11

    def test_classify_oom_from_stderr(self, runner, test_file):
        """Test OOM detection from stderr."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="Out of memory error occurred",
                args=[],
            )

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.OOM

    def test_classify_resource_exhausted(self, runner, test_file):
        """Test resource exhaustion detection."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="Resource limit exceeded",
                args=[],
            )

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.RESOURCE_EXHAUSTED

    def test_classify_generic_error(self, runner, test_file):
        """Test generic error classification."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="Unknown error",
                args=[],
            )

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.ERROR
            assert result.exit_code == 1


class TestHangDetection:
    """Test timeout/hang detection."""

    def test_hang_detection_timeout(self, runner, test_file):
        """Test that timeout is detected as hang."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=["test"], timeout=2.0, output=b"", stderr=b""
            )

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.HANG
            assert result.exit_code is None
            assert result.exception is not None

    def test_hang_updates_circuit_breaker(self, runner, test_file):
        """Test that hang updates circuit breaker."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=["test"], timeout=2.0, output=b"", stderr=b""
            )

            runner.execute_test(test_file)

            assert runner.circuit_breaker.failure_count == 1
            assert runner.circuit_breaker.consecutive_failures == 1


class TestRetryLogic:
    """Test retry logic for transient failures."""

    def test_retry_on_transient_error(self, runner, test_file):
        """Test that transient errors trigger retry."""
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                # First call fails with transient error
                return Mock(
                    returncode=1,
                    stdout="",
                    stderr="Resource temporarily unavailable",
                    args=[],
                )
            else:
                # Second call succeeds
                return Mock(returncode=0, stdout="Success", stderr="", args=[])

        with patch("subprocess.run", side_effect=side_effect):
            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.SUCCESS
            assert result.retry_count == 1  # One retry
            assert call_count == 2  # Called twice

    def test_retry_exhaustion(self, runner, test_file):
        """Test that retries are exhausted after max_retries."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="Resource temporarily unavailable",
                args=[],
            )

            result = runner.execute_test(test_file)

            # Should try 3 times total (initial + 2 retries)
            assert mock_run.call_count == 3
            assert result.retry_count == 2
            assert result.result == ExecutionStatus.RESOURCE_EXHAUSTED

    def test_no_retry_on_success(self, runner, test_file):
        """Test that successful execution doesn't retry."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            result = runner.execute_test(test_file)

            assert mock_run.call_count == 1
            assert result.retry_count == 0

    def test_no_retry_on_crash(self, runner, test_file):
        """Test that crashes don't trigger retry."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Segmentation fault", args=[]
            )

            result = runner.execute_test(test_file)

            assert mock_run.call_count == 1  # No retry on crash
            assert result.retry_count == 0
            assert result.result == ExecutionStatus.CRASH


class TestCircuitBreaker:
    """Test circuit breaker pattern."""

    def test_circuit_breaker_opens_after_failures(self, runner, test_file):
        """Test that circuit breaker opens after consecutive failures."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )

            # Trigger enough failures to open circuit (threshold = 5)
            for i in range(5):
                result = runner.execute_test(test_file)
                assert result.result == ExecutionStatus.CRASH

            # Circuit should now be open
            assert runner.circuit_breaker.is_open
            assert runner.circuit_breaker.consecutive_failures == 5

            # Next execution should be skipped
            result = runner.execute_test(test_file)
            assert result.result == ExecutionStatus.SKIPPED

    def test_circuit_breaker_resets_on_success(self, runner, test_file):
        """Test that circuit breaker resets on success."""
        with patch("subprocess.run") as mock_run:
            # Fail a few times
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )
            for _ in range(3):
                runner.execute_test(test_file)

            assert runner.circuit_breaker.consecutive_failures == 3

            # Then succeed
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )
            runner.execute_test(test_file)

            # Consecutive failures should reset
            assert runner.circuit_breaker.consecutive_failures == 0
            assert runner.circuit_breaker.success_count == 1

    def test_circuit_breaker_can_be_disabled(
        self, mock_executable, tmp_path, test_file
    ):
        """Test that circuit breaker can be disabled."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=False,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )

            # Even after many failures, circuit should not open
            for _ in range(10):
                result = runner.execute_test(test_file)
                assert result.result == ExecutionStatus.CRASH
                assert not runner.circuit_breaker.is_open

    def test_circuit_breaker_half_open_state(self, runner, test_file):
        """Test circuit breaker half-open state after timeout."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )

            # Open the circuit
            for _ in range(5):
                runner.execute_test(test_file)

            assert runner.circuit_breaker.is_open

            # Set timeout to expire immediately
            runner.circuit_breaker.open_until = time.time() - 1

            # Should allow retry (half-open state)
            result = runner.execute_test(test_file)
            assert result.result == ExecutionStatus.CRASH
            assert not runner.circuit_breaker.is_open  # Should be closed again


class TestCampaignExecution:
    """Test campaign-level execution."""

    def test_run_campaign_basic(self, runner, tmp_path):
        """Test basic campaign execution."""
        # Create test files
        test_files = [tmp_path / f"test_{i}.dcm" for i in range(5)]
        for f in test_files:
            f.write_bytes(b"DICOM_DATA")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            results = runner.run_campaign(test_files)

            assert len(results[ExecutionStatus.SUCCESS]) == 5
            assert mock_run.call_count == 5

    def test_run_campaign_stop_on_crash(self, runner, tmp_path):
        """Test that campaign stops on first crash when requested."""
        test_files = [tmp_path / f"test_{i}.dcm" for i in range(10)]
        for f in test_files:
            f.write_bytes(b"DICOM_DATA")

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 3:
                # Third file crashes
                return Mock(returncode=-11, stdout="", stderr="Crash", args=[])
            return Mock(returncode=0, stdout="Success", stderr="", args=[])

        with patch("subprocess.run", side_effect=side_effect):
            results = runner.run_campaign(test_files, stop_on_crash=True)

            # Should stop after 3 files
            assert call_count == 3
            assert len(results[ExecutionStatus.SUCCESS]) == 2
            assert len(results[ExecutionStatus.CRASH]) == 1

    def test_run_campaign_circuit_breaker_stops(self, runner, tmp_path):
        """Test that open circuit breaker stops campaign."""
        test_files = [tmp_path / f"test_{i}.dcm" for i in range(20)]
        for f in test_files:
            f.write_bytes(b"DICOM_DATA")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )

            results = runner.run_campaign(test_files)

            # Should stop after circuit opens (5 consecutive failures)
            total_executed = sum(len(r) for r in results.values())
            assert total_executed <= 6  # 5 crashes + possibly 1 skipped


class TestResourceIntegration:
    """Test resource manager integration."""

    def test_resource_manager_initialized(self, runner):
        """Test that resource manager is initialized."""
        assert runner.resource_manager is not None

    def test_campaign_checks_resources(self, runner, tmp_path):
        """Test that campaign performs pre-flight resource check."""
        test_files = [tmp_path / "test.dcm"]
        test_files[0].write_bytes(b"DICOM_DATA")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            with patch.object(
                runner.resource_manager, "check_available_resources"
            ) as mock_check:
                runner.run_campaign(test_files)

                # Should call resource check
                mock_check.assert_called_once()


class TestExecutionResultBool:
    """Test ExecutionResult __bool__ method."""

    def test_result_bool_success(self, test_file):
        """Test that successful result is truthy."""
        result = ExecutionResult(
            test_file=test_file,
            result=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=0.1,
            stdout="",
            stderr="",
        )

        assert bool(result) is True

    def test_result_bool_failure(self, test_file):
        """Test that failed result is falsy."""
        for status in [
            ExecutionStatus.CRASH,
            ExecutionStatus.HANG,
            ExecutionStatus.ERROR,
            ExecutionStatus.OOM,
        ]:
            result = ExecutionResult(
                test_file=test_file,
                result=status,
                exit_code=1,
                execution_time=0.1,
                stdout="",
                stderr="",
            )

            assert bool(result) is False


class TestGetSummary:
    """Test campaign summary generation."""

    def test_summary_formatting(self, runner, tmp_path):
        """Test that summary is properly formatted."""
        test_files = [tmp_path / f"test_{i}.dcm" for i in range(10)]
        for f in test_files:
            f.write_bytes(b"DICOM_DATA")

        # Create mixed results
        results = {
            ExecutionStatus.SUCCESS: [
                Mock(
                    test_file=test_files[0],
                    result=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    retry_count=0,
                )
            ]
            * 5,
            ExecutionStatus.CRASH: [
                Mock(
                    test_file=test_files[5],
                    result=ExecutionStatus.CRASH,
                    exit_code=-11,
                    retry_count=0,
                )
            ]
            * 2,
            ExecutionStatus.HANG: [
                Mock(
                    test_file=test_files[7],
                    result=ExecutionStatus.HANG,
                    exit_code=None,
                    retry_count=0,
                )
            ],
            ExecutionStatus.OOM: [
                Mock(
                    test_file=test_files[8],
                    result=ExecutionStatus.OOM,
                    exit_code=None,
                    retry_count=0,
                )
            ],
            ExecutionStatus.ERROR: [],
            ExecutionStatus.SKIPPED: [],
            ExecutionStatus.RESOURCE_EXHAUSTED: [],
        }

        summary = runner.get_summary(results)

        # Verify summary contains expected sections
        assert "Total test cases: 9" in summary
        assert "Successful:       5" in summary
        assert "Crashes:          2" in summary
        assert "Hangs/Timeouts:   1" in summary
        assert "OOM:              1" in summary
        assert "CRASHES DETECTED:" in summary
        assert "Circuit Breaker Stats:" in summary


class TestMemoryErrorHandling:
    """Test OOM handling in fuzzer itself."""

    def test_memory_error_caught(self, runner, test_file):
        """Test that MemoryError in subprocess.run is caught."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = MemoryError("Out of memory")

            result = runner.execute_test(test_file)

            assert result.result == ExecutionStatus.OOM
            assert "Out of memory" in result.stderr


class TestExceptionHandling:
    """Test unexpected exception handling."""

    def test_unexpected_exception_with_retry(self, runner, test_file):
        """Test that unexpected exceptions trigger retry."""
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Unexpected error")
            return Mock(returncode=0, stdout="Success", stderr="", args=[])

        with patch("subprocess.run", side_effect=side_effect):
            result = runner.execute_test(test_file)

            # Should retry and eventually succeed
            assert result.result == ExecutionStatus.SUCCESS
            assert result.retry_count == 1

    def test_unexpected_exception_exhausts_retries(self, runner, test_file):
        """Test that unexpected exceptions exhaust retries."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = RuntimeError("Unexpected error")

            result = runner.execute_test(test_file)

            # Should try 3 times (initial + 2 retries)
            assert mock_run.call_count == 3
            assert result.result == ExecutionStatus.ERROR
            assert "Unexpected error" in result.stderr


class TestPropertyBasedTargetRunner:
    """Property-based tests for target runner using Hypothesis."""

    from hypothesis import given, settings, strategies as st, HealthCheck

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(
        exit_code=st.integers(min_value=-255, max_value=255),
        max_retries=st.integers(min_value=0, max_value=10),
    )
    def test_retry_count_bounded(
        self, mock_executable, tmp_path, test_file, exit_code, max_retries
    ):
        """Property: retry_count never exceeds max_retries."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            max_retries=max_retries,
        )

        with patch("subprocess.run") as mock_run:
            # Always fail to trigger retries
            mock_run.return_value = Mock(
                returncode=exit_code,
                stdout="",
                stderr="Resource temporarily unavailable",
                args=[],
            )

            result = runner.execute_test(test_file)

            # Property: retry count should never exceed max_retries
            assert result.retry_count <= max_retries

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(
        failure_threshold=st.integers(min_value=1, max_value=20),
        num_failures=st.integers(min_value=0, max_value=30),
    )
    def test_circuit_breaker_threshold_property(
        self, mock_executable, tmp_path, test_file, failure_threshold, num_failures
    ):
        """Property: circuit breaker opens after threshold consecutive failures."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=True,
        )

        # Set custom threshold
        runner.circuit_breaker.failure_threshold = failure_threshold

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )

            # Trigger failures
            for _ in range(min(num_failures, failure_threshold + 5)):
                runner.execute_test(test_file)

            # Property: circuit opens at or before threshold
            if num_failures >= failure_threshold:
                assert runner.circuit_breaker.is_open
            else:
                # May or may not be open depending on failures
                pass

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(
        timeout=st.floats(min_value=0.1, max_value=60.0), num_files=st.integers(1, 20)
    )
    def test_timeout_property(
        self, mock_executable, tmp_path, test_file, timeout, num_files
    ):
        """Property: timeout is respected for all executions."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            timeout=timeout,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            # Execute multiple times
            for _ in range(num_files):
                result = runner.execute_test(test_file)

            # Property: subprocess.run should be called with correct timeout
            for call in mock_run.call_args_list:
                assert call.kwargs.get("timeout") == timeout

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(
        stdout_len=st.integers(min_value=0, max_value=1000),
        stderr_len=st.integers(min_value=0, max_value=1000),
    )
    def test_output_collection_property(
        self, mock_executable, tmp_path, test_file, stdout_len, stderr_len
    ):
        """Property: stdout/stderr are collected correctly."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            collect_stdout=True,
            collect_stderr=True,
        )

        stdout_data = "A" * stdout_len
        stderr_data = "B" * stderr_len

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout=stdout_data, stderr=stderr_data, args=[]
            )

            result = runner.execute_test(test_file)

            # Property: output should match exactly
            assert result.stdout == stdout_data
            assert result.stderr == stderr_data

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(num_successes=st.integers(0, 100), num_failures=st.integers(0, 100))
    def test_campaign_statistics_property(
        self, mock_executable, tmp_path, num_successes, num_failures
    ):
        """Property: campaign statistics sum correctly."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=False,  # Disable to test full counts
        )

        # Create test files
        test_files = []
        for i in range(num_successes + num_failures):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"DICOM_DATA")
            test_files.append(f)

        with patch("subprocess.run") as mock_run:

            def side_effect(*args, **kwargs):
                # First num_successes succeed, rest fail
                if mock_run.call_count <= num_successes:
                    return Mock(returncode=0, stdout="Success", stderr="", args=[])
                else:
                    return Mock(returncode=1, stdout="", stderr="Error", args=[])

            mock_run.side_effect = side_effect

            results = runner.run_campaign(test_files)

            # Property: total results should equal input count
            total_results = sum(len(r) for r in results.values())
            assert total_results == len(test_files)

            # Property: success count should match
            assert len(results[ExecutionStatus.SUCCESS]) == num_successes

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(execution_time=st.floats(min_value=0.001, max_value=10.0))
    def test_execution_time_property(
        self, mock_executable, tmp_path, test_file, execution_time
    ):
        """Property: execution time is non-negative and reasonable."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            # Mock time to return consistent execution time
            with patch("time.perf_counter") as mock_time:
                mock_time.side_effect = [0.0, execution_time]
                result = runner.execute_test(test_file)

            # Property: execution time should be non-negative and match duration
            assert result.execution_time >= 0
            assert abs(result.execution_time - execution_time) < 0.01

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(exit_code=st.integers(min_value=-255, max_value=255))
    def test_exit_code_classification_property(
        self, mock_executable, tmp_path, test_file, exit_code
    ):
        """Property: exit codes are correctly classified."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=exit_code, stdout="", stderr="", args=[]
            )

            result = runner.execute_test(test_file)

            # Property: negative exit codes are crashes
            if exit_code < 0:
                assert result.result == ExecutionStatus.CRASH
            elif exit_code == 0:
                assert result.result == ExecutionStatus.SUCCESS
            else:
                # Positive non-zero is error (unless stderr indicates otherwise)
                assert result.result in (
                    ExecutionStatus.ERROR,
                    ExecutionStatus.OOM,
                    ExecutionStatus.RESOURCE_EXHAUSTED,
                )

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=1000
    )
    @given(
        circuit_enabled=st.booleans(),
        num_failures=st.integers(min_value=0, max_value=15),
    )
    def test_circuit_breaker_enable_disable_property(
        self, mock_executable, tmp_path, test_file, circuit_enabled, num_failures
    ):
        """Property: circuit breaker behavior matches enable flag."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            crash_dir=str(tmp_path / "crashes"),
            enable_circuit_breaker=circuit_enabled,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=-11, stdout="", stderr="Crash", args=[]
            )

            for _ in range(num_failures):
                runner.execute_test(test_file)

            # Property: circuit should only open if enabled and threshold reached
            if circuit_enabled and num_failures >= 5:
                assert runner.circuit_breaker.is_open
            elif not circuit_enabled:
                assert not runner.circuit_breaker.is_open
