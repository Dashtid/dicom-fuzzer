"""Target Application Runner

CONCEPT: This module interfaces with target applications to feed them
fuzzed DICOM files and detect crashes, hangs, and other anomalies.

SECURITY TESTING WORKFLOW:
1. Generate fuzzed DICOM files
2. Feed files to target application (viewer, PACS, etc.)
3. Monitor application behavior (crashes, hangs, errors)
4. Collect crash reports and analyze vulnerabilities

This implements file-based fuzzing testing (Option 1).

STABILITY ENHANCEMENTS:
- Resource limit enforcement (memory/CPU)
- Retry logic for transient failures
- Better error classification (OOM, resource exhaustion)
- Circuit breaker pattern for failing targets
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager
from dicom_fuzzer.utils.logger import get_logger

if TYPE_CHECKING:
    from dicom_fuzzer.core.windows_crash_handler import WindowsCrashInfo

logger = get_logger(__name__)


class ExecutionStatus(Enum):
    """Result of a single test case execution."""

    SUCCESS = "success"  # Application handled file successfully
    CRASH = "crash"  # Application crashed/terminated abnormally
    HANG = "hang"  # Application hung/timed out
    ERROR = "error"  # Application returned error code
    SKIPPED = "skipped"  # Test was skipped
    OOM = "oom"  # Out of memory
    RESOURCE_EXHAUSTED = "resource_exhausted"  # Resource limit exceeded


@dataclass
class ExecutionResult:
    """Results from executing target application with a test file.

    CONCEPT: Captures all relevant information about how the target
    application behaved when processing a fuzzed DICOM file.
    """

    test_file: Path
    result: ExecutionStatus
    exit_code: int | None
    execution_time: float
    stdout: str
    stderr: str
    exception: Exception | None = None
    crash_hash: str | None = None
    retry_count: int = 0  # Number of retries attempted
    windows_crash_info: WindowsCrashInfo | None = None  # Windows-specific crash details
    hang_reason: str | None = None  # Reason for hang (timeout, cpu_idle, memory_spike)
    peak_memory_mb: float | None = None  # Peak memory usage during execution

    def __bool__(self) -> bool:
        """Test succeeded if result is SUCCESS."""
        return self.result == ExecutionStatus.SUCCESS

    @property
    def is_exploitable(self) -> bool:
        """Check if crash is potentially exploitable."""
        if self.windows_crash_info:
            return self.windows_crash_info.is_exploitable
        return self.result == ExecutionStatus.CRASH


@dataclass
class CircuitBreakerState:
    """Circuit breaker state for failing target applications.

    CONCEPT: If target consistently fails, temporarily stop testing it
    to avoid wasting resources on a broken target.
    """

    failure_count: int = 0
    success_count: int = 0
    consecutive_failures: int = 0
    is_open: bool = False
    open_until: float = 0.0  # Timestamp when circuit closes
    failure_threshold: int = 5  # Failures before opening circuit
    reset_timeout: float = 60.0  # Seconds to wait before retry


class TargetRunner:
    """Runs target application with fuzzed files and detects anomalies.

    CONCEPT: This class acts as the bridge between the fuzzer and the
    target application being tested. It handles:
    - Launching the target application
    - Feeding it test files
    - Monitoring for crashes/hangs
    - Collecting diagnostic information
    - Enforcing resource limits
    - Retry logic for transient failures
    - Circuit breaker for consistently failing targets

    SECURITY: Runs target in isolated process to contain potential exploits.
    """

    def __init__(
        self,
        target_executable: str,
        timeout: float = 5.0,
        crash_dir: str = "./artifacts/crashes",
        collect_stdout: bool = True,
        collect_stderr: bool = True,
        max_retries: int = 2,
        enable_circuit_breaker: bool = True,
        resource_limits: ResourceLimits | None = None,
        enable_monitoring: bool = False,
        idle_threshold: float = 5.0,
        memory_limit_mb: float | None = None,
    ):
        """Initialize target runner.

        Args:
            target_executable: Path to application to test
            timeout: Max seconds to wait for execution
            crash_dir: Directory to save crash reports
            collect_stdout: Whether to capture stdout
            collect_stderr: Whether to capture stderr
            max_retries: Maximum retries for transient failures
            enable_circuit_breaker: Enable circuit breaker pattern
            resource_limits: Resource limits to enforce
            enable_monitoring: Enable enhanced CPU/memory monitoring (requires psutil)
            idle_threshold: Seconds of 0% CPU before considering hung (if monitoring enabled)
            memory_limit_mb: Memory limit in MB (if monitoring enabled)

        Raises:
            FileNotFoundError: If target executable doesn't exist

        """
        self.target_executable = Path(target_executable)
        if not self.target_executable.exists():
            raise FileNotFoundError(f"Target executable not found: {target_executable}")

        self.timeout = timeout
        self.crash_dir = Path(crash_dir)
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        self.collect_stdout = collect_stdout
        self.collect_stderr = collect_stderr
        self.max_retries = max_retries
        self.enable_circuit_breaker = enable_circuit_breaker
        self.enable_monitoring = enable_monitoring
        self.idle_threshold = idle_threshold
        self.memory_limit_mb = memory_limit_mb

        # Initialize crash analyzer for crash reporting
        self.crash_analyzer = CrashAnalyzer(crash_dir=str(self.crash_dir))

        # Initialize resource manager
        self.resource_manager = ResourceManager(resource_limits)

        # Circuit breaker state
        self.circuit_breaker = CircuitBreakerState()

        # Initialize Windows crash handler if on Windows
        self.windows_crash_handler: WindowsCrashHandler | None = None
        if sys.platform == "win32":
            from dicom_fuzzer.core.windows_crash_handler import WindowsCrashHandler

            self.windows_crash_handler = WindowsCrashHandler(crash_dir=self.crash_dir)
            logger.debug("Windows crash handler initialized")

        # Initialize process monitor if monitoring enabled
        self.process_monitor = None
        if enable_monitoring:
            from dicom_fuzzer.core.process_monitor import (
                ProcessMonitor,
                is_psutil_available,
            )

            if is_psutil_available():
                self.process_monitor = ProcessMonitor(
                    timeout=timeout,
                    idle_threshold=idle_threshold,
                    memory_limit_mb=memory_limit_mb,
                )
                logger.debug(
                    f"Enhanced monitoring enabled: idle_threshold={idle_threshold}s, "
                    f"memory_limit={memory_limit_mb}MB"
                )
            else:
                logger.warning(
                    "Enhanced monitoring requested but psutil not available. "
                    "Install with: pip install psutil"
                )

        logger.info(
            f"Initialized TargetRunner: target={target_executable}, "
            f"timeout={timeout}s, max_retries={max_retries}"
        )

    def _check_circuit_breaker(self) -> bool:
        """Check if circuit breaker allows execution.

        Returns:
            True if execution should proceed, False if circuit is open

        """
        if not self.enable_circuit_breaker:
            return True

        if self.circuit_breaker.is_open:
            current_time = time.time()
            if current_time < self.circuit_breaker.open_until:
                logger.warning(
                    f"Circuit breaker OPEN - target failing consistently. "
                    f"Retry in {self.circuit_breaker.open_until - current_time:.0f}s"
                )
                return False
            else:
                # Reset timeout elapsed, try again
                logger.info("Circuit breaker half-open - attempting retry")
                self.circuit_breaker.is_open = False
                self.circuit_breaker.consecutive_failures = 0

        return True

    def _update_circuit_breaker(self, success: bool) -> None:
        """Update circuit breaker state after execution.

        Args:
            success: Whether execution was successful

        """
        if not self.enable_circuit_breaker:
            return

        if success:
            self.circuit_breaker.success_count += 1
            self.circuit_breaker.consecutive_failures = 0
        else:
            self.circuit_breaker.failure_count += 1
            self.circuit_breaker.consecutive_failures += 1

            # Check if we should open the circuit
            if (
                self.circuit_breaker.consecutive_failures
                >= self.circuit_breaker.failure_threshold
            ):
                self.circuit_breaker.is_open = True
                self.circuit_breaker.open_until = (
                    time.time() + self.circuit_breaker.reset_timeout
                )
                logger.warning(
                    f"Circuit breaker OPENED - {self.circuit_breaker.consecutive_failures} "
                    f"consecutive failures detected"
                )

    def _classify_error(self, stderr: str, returncode: int | None) -> ExecutionStatus:
        """Classify error type based on stderr and return code.

        Args:
            stderr: Standard error output
            returncode: Process return code

        Returns:
            ExecutionStatus indicating error type

        """
        stderr_lower = stderr.lower()

        # Check for out of memory
        oom_indicators = ["out of memory", "memory error", "cannot allocate", "oom"]
        if any(indicator in stderr_lower for indicator in oom_indicators):
            return ExecutionStatus.OOM

        # Check for resource exhaustion
        resource_indicators = [
            "resource",
            "limit",
            "quota",
            "too many",
            "exhausted",
        ]
        if any(indicator in stderr_lower for indicator in resource_indicators):
            return ExecutionStatus.RESOURCE_EXHAUSTED

        # Check for Windows-specific crash codes
        if returncode is not None and self.windows_crash_handler:
            if self.windows_crash_handler.is_windows_crash(returncode):
                return ExecutionStatus.CRASH

        # Check for crash signals (negative return codes on Unix, or high codes on Windows)
        if returncode is not None:
            if returncode < 0:
                return ExecutionStatus.CRASH
            # Windows exception codes appear as large positive numbers (0xC0000005 = 3221225477)
            if sys.platform == "win32" and returncode > 0x80000000:
                return ExecutionStatus.CRASH

        return ExecutionStatus.ERROR

    def execute_test(
        self, test_file: Path | str, retry_count: int = 0
    ) -> ExecutionResult:
        """Execute target application with a test file.

        Args:
            test_file: Path to DICOM file to test (str or Path)
            retry_count: Current retry attempt number

        Returns:
            ExecutionResult with test outcome

        CONCEPT: This is the core method that:
        1. Launches the target app with the test file
        2. Monitors execution with timeout
        3. Captures output and exit code
        4. Classifies the result (success/crash/hang/error)
        5. Retries on transient failures
        6. Enforces resource limits

        """
        # Normalize to Path for consistent handling
        test_file_path = Path(test_file) if isinstance(test_file, str) else test_file

        # Check circuit breaker
        if not self._check_circuit_breaker():
            return ExecutionResult(
                test_file=test_file_path,
                result=ExecutionStatus.SKIPPED,
                exit_code=None,
                execution_time=0.0,
                stdout="",
                stderr="Circuit breaker open - target failing consistently",
                retry_count=retry_count,
            )

        start_time = time.time()
        logger.debug(f"Testing file: {test_file_path.name} (attempt {retry_count + 1})")

        try:
            # Launch target application with test file
            # SECURITY: Use subprocess for isolation
            result = subprocess.run(
                [str(self.target_executable), str(test_file_path)],
                timeout=self.timeout,
                capture_output=True,
                text=True,
                check=False,  # Don't raise on non-zero exit
            )

            execution_time = time.time() - start_time

            # Classify result based on exit code and stderr
            windows_crash_info = None
            if result.returncode == 0:
                test_result = ExecutionStatus.SUCCESS
                self._update_circuit_breaker(success=True)
            else:
                # Use advanced classification
                test_result = self._classify_error(result.stderr, result.returncode)
                self._update_circuit_breaker(success=False)

                # Capture Windows-specific crash info if applicable
                if (
                    test_result == ExecutionStatus.CRASH
                    and self.windows_crash_handler
                    and result.returncode is not None
                ):
                    windows_crash_info = self.windows_crash_handler.analyze_crash(
                        exit_code=result.returncode,
                        test_file=test_file_path,
                        stdout=result.stdout,
                        stderr=result.stderr,
                    )
                    # Save crash report
                    self.windows_crash_handler.save_crash_report(
                        windows_crash_info, test_file_path
                    )
                    logger.warning(
                        f"Windows crash: {windows_crash_info.exception_name} "
                        f"(0x{windows_crash_info.exception_code:08X}) - "
                        f"{windows_crash_info.severity}"
                    )

                # Retry on transient errors
                if retry_count < self.max_retries and test_result in [
                    ExecutionStatus.ERROR,
                    ExecutionStatus.RESOURCE_EXHAUSTED,
                ]:
                    logger.debug(
                        f"Transient error detected, retrying "
                        f"({retry_count + 1}/{self.max_retries})"
                    )
                    time.sleep(0.1)  # Brief delay before retry
                    return self.execute_test(test_file_path, retry_count + 1)

            # Get crash hash from Windows crash info if available
            crash_hash = windows_crash_info.crash_hash if windows_crash_info else None

            return ExecutionResult(
                test_file=test_file_path,
                result=test_result,
                exit_code=result.returncode,
                execution_time=execution_time,
                stdout=result.stdout if self.collect_stdout else "",
                stderr=result.stderr if self.collect_stderr else "",
                retry_count=retry_count,
                windows_crash_info=windows_crash_info,
                crash_hash=crash_hash,
            )

        except subprocess.TimeoutExpired as e:
            # Application hung - didn't complete within timeout
            execution_time = time.time() - start_time

            # Record hang as potential DoS vulnerability
            crash_report = self.crash_analyzer.analyze_exception(
                Exception(f"Timeout after {self.timeout}s"),
                test_case_path=str(test_file_path),
            )

            self._update_circuit_breaker(success=False)

            # Handle stdout/stderr which may be str (text=True) or bytes
            stdout_val = ""
            stderr_val = ""
            if e.stdout and self.collect_stdout:
                # stdout can be str (text=True) or bytes (text=False)
                stdout_val = (
                    e.stdout if isinstance(e.stdout, str) else e.stdout.decode()  # type: ignore[unreachable]
                )
            if e.stderr and self.collect_stderr:
                # stderr can be str (text=True) or bytes (text=False)
                stderr_val = (
                    e.stderr if isinstance(e.stderr, str) else e.stderr.decode()  # type: ignore[unreachable]
                )

            return ExecutionResult(
                test_file=test_file_path,
                result=ExecutionStatus.HANG,
                exit_code=None,
                execution_time=execution_time,
                stdout=stdout_val,
                stderr=stderr_val,
                exception=e,
                crash_hash=crash_report.crash_hash if crash_report else None,
                retry_count=retry_count,
                hang_reason="timeout",
            )

        except MemoryError as e:
            # Out of memory in fuzzer itself
            execution_time = time.time() - start_time
            logger.error(f"Fuzzer OOM while testing {test_file_path.name}: {e}")

            self._update_circuit_breaker(success=False)

            return ExecutionResult(
                test_file=test_file_path,
                result=ExecutionStatus.OOM,
                exit_code=None,
                execution_time=execution_time,
                stdout="",
                stderr=f"Fuzzer out of memory: {e}",
                exception=e,
                retry_count=retry_count,
            )

        except (KeyboardInterrupt, SystemExit):
            # User/system requested stop - propagate immediately without retry
            raise

        except Exception as e:
            # Unexpected error during test execution
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error testing {test_file_path.name}: {e}")

            self._update_circuit_breaker(success=False)

            # Retry on unexpected errors
            if retry_count < self.max_retries:
                logger.debug(
                    f"Retrying after unexpected error "
                    f"({retry_count + 1}/{self.max_retries})"
                )
                time.sleep(0.1)
                return self.execute_test(test_file_path, retry_count + 1)

            return ExecutionResult(
                test_file=test_file_path,
                result=ExecutionStatus.ERROR,
                exit_code=None,
                execution_time=execution_time,
                stdout="",
                stderr=str(e),
                exception=e,
                retry_count=retry_count,
            )

    def execute_with_monitoring(
        self, test_file: Path | str, retry_count: int = 0
    ) -> ExecutionResult:
        """Execute target with enhanced CPU/memory monitoring.

        This method uses subprocess.Popen with ProcessMonitor for:
        - CPU idle detection (process alive but 0% CPU)
        - Memory spike detection (exceeds limit)
        - Graceful process tree termination

        Args:
            test_file: Path to DICOM file to test
            retry_count: Current retry attempt

        Returns:
            ExecutionResult with monitoring metrics

        """
        from dicom_fuzzer.core.process_monitor import HangReason

        test_file_path = Path(test_file) if isinstance(test_file, str) else test_file

        # Check circuit breaker
        if not self._check_circuit_breaker():
            return ExecutionResult(
                test_file=test_file_path,
                result=ExecutionStatus.SKIPPED,
                exit_code=None,
                execution_time=0.0,
                stdout="",
                stderr="Circuit breaker open",
                retry_count=retry_count,
            )

        if not self.process_monitor:
            # Fall back to basic execution if no monitor
            return self.execute_test(test_file_path, retry_count)

        start_time = time.time()
        logger.debug(f"Testing with monitoring: {test_file_path.name}")

        try:
            # Launch process with Popen for monitoring
            process = subprocess.Popen(
                [str(self.target_executable), str(test_file_path)],
                stdout=subprocess.PIPE if self.collect_stdout else subprocess.DEVNULL,
                stderr=subprocess.PIPE if self.collect_stderr else subprocess.DEVNULL,
                text=True,
            )

            # Monitor the process
            monitor_result = self.process_monitor.monitor_process(process)

            # Collect output
            stdout_val = ""
            stderr_val = ""
            if process.stdout and self.collect_stdout:
                try:
                    stdout_val = process.stdout.read()
                except Exception as e:
                    logger.debug(f"Error reading stdout: {e}")
            if process.stderr and self.collect_stderr:
                try:
                    stderr_val = process.stderr.read()
                except Exception as e:
                    logger.debug(f"Error reading stderr: {e}")

            execution_time = monitor_result.duration_seconds
            windows_crash_info = None

            # Process completed normally
            if monitor_result.completed:
                exit_code = monitor_result.exit_code

                if exit_code == 0:
                    test_result = ExecutionStatus.SUCCESS
                    self._update_circuit_breaker(success=True)
                else:
                    test_result = self._classify_error(stderr_val, exit_code)
                    self._update_circuit_breaker(success=False)

                    # Capture Windows crash info
                    if (
                        test_result == ExecutionStatus.CRASH
                        and self.windows_crash_handler
                        and exit_code is not None
                    ):
                        windows_crash_info = self.windows_crash_handler.analyze_crash(
                            exit_code=exit_code,
                            test_file=test_file_path,
                            stdout=stdout_val,
                            stderr=stderr_val,
                        )
                        self.windows_crash_handler.save_crash_report(
                            windows_crash_info, test_file_path
                        )

                crash_hash = (
                    windows_crash_info.crash_hash if windows_crash_info else None
                )

                return ExecutionResult(
                    test_file=test_file_path,
                    result=test_result,
                    exit_code=exit_code,
                    execution_time=execution_time,
                    stdout=stdout_val,
                    stderr=stderr_val,
                    retry_count=retry_count,
                    windows_crash_info=windows_crash_info,
                    crash_hash=crash_hash,
                    peak_memory_mb=monitor_result.metrics.peak_memory_mb,
                )

            # Hang detected
            else:
                self._update_circuit_breaker(success=False)

                # Map HangReason to hang_reason string
                hang_reason_str = "timeout"
                if monitor_result.hang_reason == HangReason.CPU_IDLE:
                    hang_reason_str = "cpu_idle"
                    logger.warning(
                        f"CPU idle hang: {test_file_path.name} "
                        f"(idle for {monitor_result.metrics.idle_duration_seconds:.1f}s)"
                    )
                elif monitor_result.hang_reason == HangReason.MEMORY_SPIKE:
                    hang_reason_str = "memory_spike"
                    logger.warning(
                        f"Memory spike: {test_file_path.name} "
                        f"(peak {monitor_result.metrics.peak_memory_mb:.1f}MB)"
                    )
                else:
                    logger.warning(f"Timeout: {test_file_path.name}")

                # Check for OOM based on hang reason
                if monitor_result.hang_reason == HangReason.MEMORY_SPIKE:
                    test_result = ExecutionStatus.OOM
                else:
                    test_result = ExecutionStatus.HANG

                return ExecutionResult(
                    test_file=test_file_path,
                    result=test_result,
                    exit_code=None,
                    execution_time=execution_time,
                    stdout=stdout_val,
                    stderr=stderr_val,
                    retry_count=retry_count,
                    hang_reason=hang_reason_str,
                    peak_memory_mb=monitor_result.metrics.peak_memory_mb,
                )

        except (KeyboardInterrupt, SystemExit):
            raise

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Monitoring error for {test_file_path.name}: {e}")

            self._update_circuit_breaker(success=False)

            if retry_count < self.max_retries:
                time.sleep(0.1)
                return self.execute_with_monitoring(test_file_path, retry_count + 1)

            return ExecutionResult(
                test_file=test_file_path,
                result=ExecutionStatus.ERROR,
                exit_code=None,
                execution_time=execution_time,
                stdout="",
                stderr=str(e),
                exception=e,
                retry_count=retry_count,
            )

    def run_campaign(
        self, test_files: list[Path], stop_on_crash: bool = False
    ) -> dict[ExecutionStatus, list[ExecutionResult]]:
        """Run fuzzing campaign against target with multiple test files.

        Args:
            test_files: List of fuzzed DICOM files to test
            stop_on_crash: If True, stop testing on first crash

        Returns:
            Dictionary mapping ExecutionStatus to list of ExecutionResults

        CONCEPT: Batch testing mode - feed all fuzzed files to target
        and collect comprehensive results for analysis.

        """
        results: dict[ExecutionStatus, list[ExecutionResult]] = {
            result_type: [] for result_type in ExecutionStatus
        }

        total = len(test_files)
        logger.info(f"Starting fuzzing campaign with {total} test files")

        # Pre-flight resource check
        try:
            self.resource_manager.check_available_resources(output_dir=self.crash_dir)
        except Exception as e:
            logger.error(f"Pre-flight resource check failed: {e}")
            logger.warning("Proceeding anyway - resource limits may not be enforced")

        for i, test_file in enumerate(test_files, 1):
            logger.debug(f"[{i}/{total}] Testing {test_file.name}")

            # Use monitoring if enabled, otherwise basic execution
            if self.process_monitor:
                exec_result = self.execute_with_monitoring(test_file)
            else:
                exec_result = self.execute_test(test_file)
            results[exec_result.result].append(exec_result)

            # Log notable results
            if exec_result.result in (
                ExecutionStatus.CRASH,
                ExecutionStatus.HANG,
                ExecutionStatus.OOM,
            ):
                logger.warning(
                    f"[{i}/{total}] {exec_result.result.value.upper()}: "
                    f"{test_file.name} (exit_code={exec_result.exit_code}, "
                    f"retries={exec_result.retry_count})"
                )

                if stop_on_crash and exec_result.result == ExecutionStatus.CRASH:
                    logger.info("Stopping campaign on first crash (stop_on_crash=True)")
                    break

            # Check circuit breaker - if open, skip remaining tests
            if self.circuit_breaker.is_open:
                logger.warning(
                    f"Circuit breaker open - skipping remaining {total - i} tests"
                )
                break

        # Print summary
        logger.info("Campaign complete. Results:")
        for result_type, exec_results in results.items():
            if exec_results:
                logger.info(f"  {result_type.value}: {len(exec_results)}")

        # Print circuit breaker stats
        if self.enable_circuit_breaker:
            logger.info(
                f"Circuit breaker: {self.circuit_breaker.success_count} successes, "
                f"{self.circuit_breaker.failure_count} failures"
            )

        return results

    def get_summary(self, results: dict[ExecutionStatus, list[ExecutionResult]]) -> str:
        """Generate human-readable summary of campaign results.

        Args:
            results: Campaign results from run_campaign()

        Returns:
            Formatted summary string

        """
        total = sum(len(r) for r in results.values())
        crashes = len(results[ExecutionStatus.CRASH])
        hangs = len(results[ExecutionStatus.HANG])
        errors = len(results[ExecutionStatus.ERROR])
        success = len(results[ExecutionStatus.SUCCESS])
        oom = len(results[ExecutionStatus.OOM])
        skipped = len(results[ExecutionStatus.SKIPPED])

        summary = [
            "=" * 70,
            "  Fuzzing Campaign Summary",
            "=" * 70,
            f"  Total test cases: {total}",
            f"  Successful:       {success}",
            f"  Crashes:          {crashes}",
            f"  Hangs/Timeouts:   {hangs}",
            f"  OOM:              {oom}",
            f"  Errors:           {errors}",
            f"  Skipped:          {skipped}",
            "=" * 70,
        ]

        if crashes > 0:
            summary.append("\n  CRASHES DETECTED:")
            # Show first 10 crashes with Windows-specific info if available
            for exec_result in results[ExecutionStatus.CRASH][:10]:
                if exec_result.windows_crash_info:
                    wci = exec_result.windows_crash_info
                    crash_line = (
                        f"    - {exec_result.test_file.name}: "
                        f"{wci.exception_name} (0x{wci.exception_code:08X}) "
                        f"[{wci.severity.upper()}]"
                    )
                    if wci.is_exploitable:
                        crash_line += " [EXPLOITABLE]"
                else:
                    crash_line = (
                        f"    - {exec_result.test_file.name} "
                        f"(exit_code={exec_result.exit_code}, "
                        f"retries={exec_result.retry_count})"
                    )
                summary.append(crash_line)
            if len(results[ExecutionStatus.CRASH]) > 10:
                remaining = len(results[ExecutionStatus.CRASH]) - 10
                summary.append(f"    ... and {remaining} more")

            # Count exploitable crashes
            exploitable = sum(
                1
                for r in results[ExecutionStatus.CRASH]
                if r.windows_crash_info and r.windows_crash_info.is_exploitable
            )
            if exploitable > 0:
                summary.append(f"\n  [!] EXPLOITABLE CRASHES: {exploitable}")

        if hangs > 0:
            summary.append("\n  HANGS DETECTED:")
            for exec_result in results[ExecutionStatus.HANG][:10]:
                summary.append(
                    f"    - {exec_result.test_file.name} (timeout={self.timeout}s)"
                )
            if len(results[ExecutionStatus.HANG]) > 10:
                summary.append(
                    f"    ... and {len(results[ExecutionStatus.HANG]) - 10} more"
                )

        if oom > 0:
            summary.append("\n  OUT OF MEMORY:")
            for exec_result in results[ExecutionStatus.OOM][:5]:
                summary.append(f"    - {exec_result.test_file.name}")
            if len(results[ExecutionStatus.OOM]) > 5:
                summary.append(
                    f"    ... and {len(results[ExecutionStatus.OOM]) - 5} more"
                )

        # Circuit breaker stats
        if self.enable_circuit_breaker:
            summary.append("\n  Circuit Breaker Stats:")
            summary.append(
                f"    Successes: {self.circuit_breaker.success_count}, "
                f"Failures: {self.circuit_breaker.failure_count}"
            )
            if self.circuit_breaker.is_open:
                summary.append("    Status: OPEN (target failing consistently)")
            else:
                summary.append("    Status: CLOSED")

        summary.append("")
        return "\n".join(summary)
