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


def _check_process_memory(
    psutil_proc: object,
    process: subprocess.Popen,
    input_path: Path,
    memory_peak: float,
    memory_limit_mb: int,
    start_time: float,
) -> tuple[float, TestResult | None]:
    """Check memory usage and return updated peak and optional result if exceeded."""
    import psutil

    try:
        mem_info = psutil_proc.memory_info()  # type: ignore[attr-defined]
        mem_mb = mem_info.rss / (1024 * 1024)
        memory_peak = max(memory_peak, mem_mb)

        if mem_mb > memory_limit_mb:
            process.kill()
            return memory_peak, TestResult(
                input_path=input_path,
                status="memory_exceeded",
                memory_peak_mb=memory_peak,
                duration_seconds=time.time() - start_time,
                error_message=f"Memory limit exceeded: {mem_mb:.1f} MB",
                process_pid=process.pid,
            )
    except psutil.NoSuchProcess:
        return memory_peak, TestResult(
            input_path=input_path,
            status="crash",
            memory_peak_mb=memory_peak,
            duration_seconds=time.time() - start_time,
            error_message="Process disappeared unexpectedly",
            process_pid=process.pid,
        )
    return memory_peak, None


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
            exit_code = process.poll()
            if exit_code is not None:
                if exit_code in (0, 1):
                    return TestResult(
                        input_path=input_path,
                        status="success",
                        exit_code=exit_code,
                        memory_peak_mb=memory_peak,
                        duration_seconds=time.time() - start_time,
                        error_message=None,
                        process_pid=process.pid,
                    )
                return TestResult(
                    input_path=input_path,
                    status="crash",
                    exit_code=exit_code,
                    memory_peak_mb=memory_peak,
                    duration_seconds=time.time() - start_time,
                    error_message=f"Exit code: {exit_code}",
                    process_pid=process.pid,
                )

            if psutil_proc is not None:
                memory_peak, result = _check_process_memory(
                    psutil_proc,
                    process,
                    input_path,
                    memory_peak,
                    memory_limit_mb,
                    start_time,
                )
                if result:
                    return result

            time.sleep(0.5)
            elapsed = time.time() - start_time

        except Exception as e:
            logger.warning("Error during monitoring", error=str(e))
            break

    # Timeout: kill and mark success (GUI apps don't exit on their own)
    pid = process.pid
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


def _classify_exit_code(exit_code: int) -> tuple[str, str | None]:
    """Classify process exit code into status and error message."""
    if exit_code == 0 or exit_code == 1:
        return "success", None
    return "crash", f"Exit code: {exit_code}"


def _check_phase_memory(
    psutil_proc: object,
    process: subprocess.Popen,
    phase_name: str,
    phase_start: float,
    memory_peak: float,
    memory_limit: int,
) -> tuple[float, PhaseResult | None]:
    """Check memory usage and return updated peak and optional result if exceeded."""
    import psutil

    try:
        mem_info = psutil_proc.memory_info()  # type: ignore[attr-defined]
        mem_mb = mem_info.rss / (1024 * 1024)
        memory_peak = max(memory_peak, mem_mb)

        if mem_mb > memory_limit:
            process.kill()
            return memory_peak, PhaseResult(
                phase_name=phase_name,
                status="memory_exceeded",
                duration_seconds=time.time() - phase_start,
                memory_peak_mb=memory_peak,
                error_message=f"Memory limit exceeded: {mem_mb:.1f} MB > {memory_limit} MB",
            )
    except psutil.NoSuchProcess:
        return memory_peak, PhaseResult(
            phase_name=phase_name,
            status="crash",
            duration_seconds=time.time() - phase_start,
            memory_peak_mb=memory_peak,
            error_message="Process disappeared during phase",
        )
    return memory_peak, None


def _run_phase_validation(
    phase: ObservationPhase,
    process_pid: int,
    phase_start: float,
    memory_peak: float,
) -> tuple[ValidationResult | None, PhaseResult | None]:
    """Run validation callback and return result and optional failure PhaseResult."""
    if phase.validation_callback is None:
        return None, None

    try:
        validation_result = phase.validation_callback(process_pid)
        if not validation_result.passed:
            return validation_result, PhaseResult(
                phase_name=phase.name,
                status="validation_failed",
                duration_seconds=time.time() - phase_start,
                memory_peak_mb=memory_peak,
                validation_result=validation_result,
                error_message=validation_result.message,
            )
        return validation_result, None
    except Exception as e:
        logger.warning("Validation callback failed", phase=phase.name, error=str(e))
        validation_result = ValidationResult(
            passed=False, message=f"Validation error: {e}"
        )
        return validation_result, PhaseResult(
            phase_name=phase.name,
            status="validation_failed",
            duration_seconds=time.time() - phase_start,
            memory_peak_mb=memory_peak,
            validation_result=validation_result,
            error_message=f"Validation error: {e}",
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

    elapsed = 0.0
    while elapsed < phase.duration_seconds:
        try:
            exit_code = process.poll()
            if exit_code is not None:
                status, error_msg = _classify_exit_code(exit_code)
                return PhaseResult(
                    phase_name=phase.name,
                    status=status,
                    duration_seconds=time.time() - phase_start,
                    memory_peak_mb=memory_peak,
                    error_message=error_msg,
                )

            if psutil_proc is not None:
                memory_peak, result = _check_phase_memory(
                    psutil_proc,
                    process,
                    phase.name,
                    phase_start,
                    memory_peak,
                    memory_limit,
                )
                if result:
                    return result

            time.sleep(0.5)
            elapsed = time.time() - phase_start
        except Exception as e:
            logger.warning(
                "Error during phase monitoring", phase=phase.name, error=str(e)
            )
            break

    validation_result, failure_result = _run_phase_validation(
        phase, process.pid, phase_start, memory_peak
    )
    if failure_result:
        return failure_result

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
