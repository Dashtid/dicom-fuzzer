"""Process Monitor - CPU and Memory monitoring for hang detection.

This module provides enhanced process monitoring:
- CPU usage tracking (detect idle hangs)
- Memory usage monitoring (detect memory spikes/leaks)
- Graceful process termination
- Process tree handling (kill child processes)

SECURITY CONTEXT: Traditional hang detection relies on timeout expiry.
This module adds smarter detection:
- "Idle hang": Process alive but 0% CPU for extended period (infinite loop waiting)
- "Memory spike": Process consuming excessive memory (potential DoS)
- "CPU spin": Process at 100% CPU (busy loop, regex DoS)
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import psutil, but make it optional
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment,unused-ignore]
    PSUTIL_AVAILABLE = False
    logger.debug("psutil not available - enhanced monitoring disabled")


class HangReason(Enum):
    """Reason why a process was considered hung."""

    TIMEOUT = "timeout"  # Traditional timeout expiry
    CPU_IDLE = "cpu_idle"  # Process alive but 0% CPU for too long
    MEMORY_SPIKE = "memory_spike"  # Memory exceeded threshold
    CPU_SPIN = "cpu_spin"  # 100% CPU for too long (optional detection)
    NOT_RESPONDING = "not_responding"  # Windows "not responding" state


@dataclass
class ProcessMetrics:
    """Metrics collected during process execution."""

    peak_memory_mb: float = 0.0
    average_cpu_percent: float = 0.0
    cpu_samples: list[float] = field(default_factory=list)
    memory_samples: list[float] = field(default_factory=list)
    idle_duration_seconds: float = 0.0
    total_duration_seconds: float = 0.0

    def add_sample(self, cpu_percent: float, memory_mb: float) -> None:
        """Add a monitoring sample."""
        self.cpu_samples.append(cpu_percent)
        self.memory_samples.append(memory_mb)
        if memory_mb > self.peak_memory_mb:
            self.peak_memory_mb = memory_mb

    def calculate_averages(self) -> None:
        """Calculate average values from samples."""
        if self.cpu_samples:
            self.average_cpu_percent = sum(self.cpu_samples) / len(self.cpu_samples)


@dataclass
class MonitorResult:
    """Result of process monitoring."""

    completed: bool  # Process completed normally
    hang_detected: bool  # Hang was detected
    hang_reason: HangReason | None
    exit_code: int | None
    metrics: ProcessMetrics
    duration_seconds: float


class ProcessMonitor:
    """Monitors a running process for hangs and resource issues.

    This monitor provides smarter hang detection than simple timeouts:
    - Detects idle processes (0% CPU but still alive)
    - Detects memory spikes before OOM
    - Gracefully terminates with cleanup

    Usage:
        monitor = ProcessMonitor(
            timeout=30.0,
            idle_threshold=5.0,  # Kill if 0% CPU for 5 seconds
            memory_limit_mb=2048,  # Kill if >2GB memory
        )
        result = monitor.monitor_process(process)
    """

    def __init__(
        self,
        timeout: float = 30.0,
        idle_threshold: float = 5.0,
        memory_limit_mb: float | None = None,
        poll_interval: float = 0.1,
        cpu_idle_percent: float = 1.0,
    ):
        """Initialize process monitor.

        Args:
            timeout: Maximum time to wait for process (seconds)
            idle_threshold: Kill if CPU below cpu_idle_percent for this long (seconds)
            memory_limit_mb: Kill if memory exceeds this (MB), None = no limit
            poll_interval: How often to sample metrics (seconds)
            cpu_idle_percent: CPU percent threshold for "idle" detection

        """
        self.timeout = timeout
        self.idle_threshold = idle_threshold
        self.memory_limit_mb = memory_limit_mb
        self.poll_interval = poll_interval
        self.cpu_idle_percent = cpu_idle_percent

        if not PSUTIL_AVAILABLE:
            logger.warning(
                "psutil not installed - using basic timeout only. "
                "Install with: pip install psutil"
            )

    def monitor_process(self, process: subprocess.Popen[bytes]) -> MonitorResult:
        """Monitor a running process until completion or hang detection.

        Args:
            process: subprocess.Popen object to monitor

        Returns:
            MonitorResult with metrics and hang detection info

        """
        if not PSUTIL_AVAILABLE:
            return self._basic_monitor(process)

        return self._enhanced_monitor(process)

    def _basic_monitor(self, process: subprocess.Popen[bytes]) -> MonitorResult:
        """Basic monitoring using only subprocess wait (no psutil).

        Args:
            process: Process to monitor

        Returns:
            MonitorResult with basic timeout detection only

        """
        start_time = time.time()
        metrics = ProcessMetrics()

        try:
            exit_code = process.wait(timeout=self.timeout)
            duration = time.time() - start_time
            metrics.total_duration_seconds = duration

            return MonitorResult(
                completed=True,
                hang_detected=False,
                hang_reason=None,
                exit_code=exit_code,
                metrics=metrics,
                duration_seconds=duration,
            )

        except Exception:  # subprocess.TimeoutExpired or similar
            duration = time.time() - start_time
            metrics.total_duration_seconds = duration

            # Kill the process
            self._terminate_process(process)

            return MonitorResult(
                completed=False,
                hang_detected=True,
                hang_reason=HangReason.TIMEOUT,
                exit_code=None,
                metrics=metrics,
                duration_seconds=duration,
            )

    def _enhanced_monitor(self, process: subprocess.Popen[bytes]) -> MonitorResult:
        """Enhanced monitoring with CPU/memory tracking.

        Args:
            process: Process to monitor

        Returns:
            MonitorResult with detailed metrics and smart hang detection

        """
        start_time = time.time()
        metrics = ProcessMetrics()
        idle_start: float | None = None
        ps_process: psutil.Process | None = None

        try:
            ps_process = psutil.Process(process.pid)
            # Prime CPU percent (first call returns 0)
            ps_process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning("cannot attach to process", pid=process.pid, error=str(e))
            return self._basic_monitor(process)

        while True:
            elapsed = time.time() - start_time

            # Check if process completed
            exit_code = process.poll()
            if exit_code is not None:
                metrics.total_duration_seconds = elapsed
                metrics.calculate_averages()

                return MonitorResult(
                    completed=True,
                    hang_detected=False,
                    hang_reason=None,
                    exit_code=exit_code,
                    metrics=metrics,
                    duration_seconds=elapsed,
                )

            # Check timeout
            if elapsed >= self.timeout:
                logger.debug("process timeout", elapsed_seconds=elapsed)
                self._terminate_process_tree(ps_process)
                metrics.total_duration_seconds = elapsed
                metrics.calculate_averages()

                return MonitorResult(
                    completed=False,
                    hang_detected=True,
                    hang_reason=HangReason.TIMEOUT,
                    exit_code=None,
                    metrics=metrics,
                    duration_seconds=elapsed,
                )

            # Sample metrics
            try:
                cpu_percent = ps_process.cpu_percent(interval=None)
                memory_info = ps_process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)

                metrics.add_sample(cpu_percent, memory_mb)

                # Check for idle hang
                if cpu_percent < self.cpu_idle_percent:
                    if idle_start is None:
                        idle_start = time.time()
                    elif time.time() - idle_start >= self.idle_threshold:
                        logger.debug(
                            "CPU idle hang detected",
                            cpu_percent=cpu_percent,
                            idle_seconds=time.time() - idle_start,
                        )
                        self._terminate_process_tree(ps_process)
                        metrics.idle_duration_seconds = time.time() - idle_start
                        metrics.total_duration_seconds = elapsed
                        metrics.calculate_averages()

                        return MonitorResult(
                            completed=False,
                            hang_detected=True,
                            hang_reason=HangReason.CPU_IDLE,
                            exit_code=None,
                            metrics=metrics,
                            duration_seconds=elapsed,
                        )
                else:
                    idle_start = None  # Reset idle timer

                # Check memory limit
                if self.memory_limit_mb and memory_mb > self.memory_limit_mb:
                    logger.debug(
                        "memory spike detected",
                        memory_mb=memory_mb,
                        limit_mb=self.memory_limit_mb,
                    )
                    self._terminate_process_tree(ps_process)
                    metrics.total_duration_seconds = elapsed
                    metrics.calculate_averages()

                    return MonitorResult(
                        completed=False,
                        hang_detected=True,
                        hang_reason=HangReason.MEMORY_SPIKE,
                        exit_code=None,
                        metrics=metrics,
                        duration_seconds=elapsed,
                    )

                # Note: Windows "not responding" detection requires win32api
                # which is not currently a dependency. The basic timeout and
                # CPU idle detection above will catch most hang scenarios.

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process may have terminated between poll() and metric collection
                exit_code = process.poll()
                metrics.total_duration_seconds = elapsed
                metrics.calculate_averages()

                return MonitorResult(
                    completed=exit_code is not None,
                    hang_detected=False,
                    hang_reason=None,
                    exit_code=exit_code,
                    metrics=metrics,
                    duration_seconds=elapsed,
                )

            # Sleep before next sample
            time.sleep(self.poll_interval)

    def _terminate_process(self, process: subprocess.Popen[bytes]) -> None:
        """Terminate a process gracefully, then forcefully.

        Args:
            process: Process to terminate

        """
        try:
            if sys.platform == "win32":
                # Windows: terminate() sends TerminateProcess
                process.terminate()
            else:
                # Unix: try SIGTERM first, then SIGKILL
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except Exception:
                    process.kill()
        except Exception as e:
            logger.warning("error terminating process", error=str(e))

    def _terminate_process_tree(self, ps_process: psutil.Process) -> None:
        """Terminate process and all child processes.

        Args:
            ps_process: psutil.Process to terminate with children

        """
        if not PSUTIL_AVAILABLE:
            return

        try:
            # Get all children first
            children = ps_process.children(recursive=True)

            # Terminate children
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug(
                        "child process already gone or inaccessible", error=str(e)
                    )

            # Terminate main process
            try:
                ps_process.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.debug("main process already gone or inaccessible", error=str(e))

            # Wait briefly for graceful termination
            _, alive = psutil.wait_procs([ps_process] + children, timeout=2.0)

            # Force kill any survivors
            for proc in alive:
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug(
                        "survivor process already gone or inaccessible", error=str(e)
                    )

            logger.debug(
                "terminated process tree",
                children_count=len(children),
            )

        except Exception as e:
            logger.warning("error terminating process tree", error=str(e))


def is_psutil_available() -> bool:
    """Check if psutil is available for enhanced monitoring."""
    return PSUTIL_AVAILABLE
