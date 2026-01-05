"""Process Monitoring for Target Harness.

Functions for monitoring target processes, including memory usage,
crash detection, and process lifecycle management.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import structlog

from dicom_fuzzer.core.harness.types import (
    ObservationPhase,
    PhaseResult,
    TestResult,
    TestStatus,
    ValidationResult,
)

logger = structlog.get_logger(__name__)


def is_psutil_available() -> bool:
    """Check if psutil is available."""
    try:
        import psutil  # noqa: F401

        return True
    except ImportError:
        return False


def monitor_process(
    process: subprocess.Popen,
    input_path: Path,
    start_time: float,
    timeout_seconds: float,
    memory_limit_mb: int,
) -> TestResult:
    """Monitor a running process for crashes and resource usage.

    Args:
        process: The subprocess to monitor.
        input_path: Path to the input being tested.
        start_time: When the test started.
        timeout_seconds: Maximum time to wait.
        memory_limit_mb: Memory limit in MB.

    Returns:
        TestResult with monitoring results.

    """
    memory_peak = 0.0
    psutil_proc = None

    # Try to get psutil process handle
    if is_psutil_available():
        import psutil

        try:
            psutil_proc = psutil.Process(process.pid)
        except psutil.NoSuchProcess:
            return TestResult(
                input_path=input_path,
                status="crash",
                error_message="Process exited immediately",
                duration_seconds=time.time() - start_time,
                process_pid=process.pid,
            )

    elapsed = time.time() - start_time
    while elapsed < timeout_seconds:
        try:
            # Check if process exited
            exit_code = process.poll()
            if exit_code is not None:
                status: TestStatus
                error_msg = None

                if exit_code == 0:
                    status = "success"
                elif exit_code < 0 or exit_code > 1:
                    # Negative exit codes on Unix indicate signals
                    # Exit codes > 1 typically indicate errors
                    status = "crash"
                    error_msg = f"Exit code: {exit_code}"
                else:
                    # Exit code 1 is typically a normal error exit
                    status = "success"

                return TestResult(
                    input_path=input_path,
                    status=status,
                    exit_code=exit_code,
                    memory_peak_mb=memory_peak,
                    duration_seconds=time.time() - start_time,
                    error_message=error_msg,
                    process_pid=process.pid,
                )

            # Check memory if psutil available
            if psutil_proc is not None:
                import psutil

                try:
                    mem_info = psutil_proc.memory_info()
                    mem_mb = mem_info.rss / (1024 * 1024)
                    memory_peak = max(memory_peak, mem_mb)

                    if mem_mb > memory_limit_mb:
                        process.kill()
                        return TestResult(
                            input_path=input_path,
                            status="memory_exceeded",
                            memory_peak_mb=memory_peak,
                            duration_seconds=time.time() - start_time,
                            error_message=f"Memory limit exceeded: {mem_mb:.1f} MB",
                            process_pid=process.pid,
                        )
                except psutil.NoSuchProcess:
                    return TestResult(
                        input_path=input_path,
                        status="crash",
                        memory_peak_mb=memory_peak,
                        duration_seconds=time.time() - start_time,
                        error_message="Process disappeared unexpectedly",
                        process_pid=process.pid,
                    )

            time.sleep(0.5)
            elapsed = time.time() - start_time

        except Exception as e:
            logger.warning("Error during monitoring", error=str(e))
            break

    # Timeout reached - kill process and mark as success
    # (GUI apps typically don't exit on their own)
    pid = process.pid  # Store before killing
    try:
        process.kill()
        process.wait(timeout=3)
    except Exception as e:
        logger.debug(f"Error during process cleanup: {e}")

    return TestResult(
        input_path=input_path,
        status="success",
        memory_peak_mb=memory_peak,
        duration_seconds=time.time() - start_time,
        process_pid=pid,
    )


def run_observation_phase(
    process: subprocess.Popen,
    phase: ObservationPhase,
    default_memory_limit: int,
) -> PhaseResult:
    """Run a single observation phase.

    Args:
        process: The running subprocess.
        phase: Phase configuration.
        default_memory_limit: Default memory limit if phase doesn't specify one.

    Returns:
        PhaseResult with phase status and metrics.

    """
    phase_start = time.time()
    memory_peak = 0.0
    memory_limit = phase.memory_limit_mb or default_memory_limit

    # Get psutil handle if available
    psutil_proc = None
    if is_psutil_available():
        import psutil

        try:
            psutil_proc = psutil.Process(process.pid)
        except psutil.NoSuchProcess:
            return PhaseResult(
                phase_name=phase.name,
                status="crash",
                duration_seconds=time.time() - phase_start,
                error_message="Process exited before phase started",
            )

    # Monitor for phase duration
    elapsed = 0.0
    while elapsed < phase.duration_seconds:
        try:
            # Check if process exited
            exit_code = process.poll()
            if exit_code is not None:
                if exit_code == 0:
                    status = "success"
                    error_msg = None
                elif exit_code < 0 or exit_code > 1:
                    status = "crash"
                    error_msg = f"Exit code: {exit_code}"
                else:
                    status = "success"
                    error_msg = None

                return PhaseResult(
                    phase_name=phase.name,
                    status=status,
                    duration_seconds=time.time() - phase_start,
                    memory_peak_mb=memory_peak,
                    error_message=error_msg,
                )

            # Check memory
            if psutil_proc is not None:
                import psutil

                try:
                    mem_info = psutil_proc.memory_info()
                    mem_mb = mem_info.rss / (1024 * 1024)
                    memory_peak = max(memory_peak, mem_mb)

                    if mem_mb > memory_limit:
                        process.kill()
                        return PhaseResult(
                            phase_name=phase.name,
                            status="memory_exceeded",
                            duration_seconds=time.time() - phase_start,
                            memory_peak_mb=memory_peak,
                            error_message=f"Memory limit exceeded: {mem_mb:.1f} MB > {memory_limit} MB",
                        )
                except psutil.NoSuchProcess:
                    return PhaseResult(
                        phase_name=phase.name,
                        status="crash",
                        duration_seconds=time.time() - phase_start,
                        memory_peak_mb=memory_peak,
                        error_message="Process disappeared during phase",
                    )

            time.sleep(0.5)
            elapsed = time.time() - phase_start

        except Exception as e:
            logger.warning(
                "Error during phase monitoring",
                phase=phase.name,
                error=str(e),
            )
            break

    # Phase completed successfully - run validation callback if present
    validation_result = None
    if phase.validation_callback is not None:
        try:
            validation_result = phase.validation_callback(process.pid)
            if not validation_result.passed:
                return PhaseResult(
                    phase_name=phase.name,
                    status="validation_failed",
                    duration_seconds=time.time() - phase_start,
                    memory_peak_mb=memory_peak,
                    validation_result=validation_result,
                    error_message=validation_result.message,
                )
        except Exception as e:
            logger.warning(
                "Validation callback failed",
                phase=phase.name,
                error=str(e),
            )
            validation_result = ValidationResult(
                passed=False,
                message=f"Validation error: {e}",
            )
            return PhaseResult(
                phase_name=phase.name,
                status="validation_failed",
                duration_seconds=time.time() - phase_start,
                memory_peak_mb=memory_peak,
                validation_result=validation_result,
                error_message=f"Validation error: {e}",
            )

    return PhaseResult(
        phase_name=phase.name,
        status="success",
        duration_seconds=time.time() - phase_start,
        memory_peak_mb=memory_peak,
        validation_result=validation_result,
    )


def kill_target_processes(process_pattern: str) -> int:
    """Kill any running target processes matching the pattern.

    Args:
        process_pattern: Pattern to match in process names (lowercase).

    Returns:
        Number of processes killed.

    """
    if not is_psutil_available():
        return 0

    import psutil

    killed = 0

    for proc in psutil.process_iter(["name", "pid"]):
        try:
            proc_name = proc.info.get("name", "")
            if proc_name and process_pattern in proc_name.lower():
                proc.kill()
                proc.wait(timeout=3)
                killed += 1
                logger.debug(
                    "Killed process",
                    name=proc_name,
                    pid=proc.info.get("pid"),
                )
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.TimeoutExpired,
        ) as e:
            logger.debug(f"Process already gone or inaccessible: {e}")
        except Exception as e:
            logger.warning("Error killing process", error=str(e))

    return killed


__all__ = [
    "is_psutil_available",
    "monitor_process",
    "run_observation_phase",
    "kill_target_processes",
]
