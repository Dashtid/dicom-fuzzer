"""Response-Aware GUI Monitor for DICOM Viewer Fuzzing.

This module provides advanced monitoring capabilities for GUI-based DICOM viewers,
going beyond simple crash detection to identify:
- Error dialogs and warning popups
- Rendering anomalies
- Memory corruption indicators
- Application hang detection
- Resource exhaustion patterns

Based on research from:
- NetworkFuzzer (ARES 2025) - Response-aware fuzzing operators
- pywinauto documentation - Windows GUI automation

References:
- https://github.com/pywinauto/pywinauto
- https://link.springer.com/chapter/10.1007/978-3-032-00644-8_13

"""

from __future__ import annotations

import logging
import re
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Import types from gui_monitor_types
from dicom_fuzzer.core.gui_monitor_types import (
    GUIResponse,
    MonitorConfig,
    ResponseType,
    SeverityLevel,
)

# Import state coverage types
from dicom_fuzzer.core.state_coverage import (
    StateCoverageTracker,
    StateTransition,
)

if TYPE_CHECKING:
    import subprocess

# Optional imports for GUI monitoring
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from pywinauto import Application
    from pywinauto.findwindows import ElementNotFoundError

    HAS_PYWINAUTO = True
except ImportError:
    HAS_PYWINAUTO = False
    Application = None
    ElementNotFoundError = Exception

logger = logging.getLogger(__name__)


class GUIMonitor:
    """Advanced GUI monitoring for DICOM viewer fuzzing.

    Monitors GUI applications for various responses beyond crashes:
    - Error and warning dialogs
    - Memory corruption indicators
    - Application hangs
    - Rendering anomalies

    Usage:
        monitor = GUIMonitor(config)
        with monitor.monitor_process(process, test_file):
            # Application runs here
            pass
        responses = monitor.get_responses()

    """

    def __init__(self, config: MonitorConfig | None = None):
        """Initialize GUI monitor.

        Args:
            config: Monitoring configuration (uses defaults if None)

        Raises:
            ImportError: If required dependencies are not available

        """
        self.config = config or MonitorConfig()
        self._responses: list[GUIResponse] = []
        self._lock = threading.Lock()
        self._monitoring = False
        self._monitor_thread: threading.Thread | None = None
        self._baseline_memory: float = 0.0
        self._last_response_time: float = 0.0

        # Compile regex patterns
        self._error_patterns = [re.compile(p) for p in self.config.error_patterns]
        self._warning_patterns = [re.compile(p) for p in self.config.warning_patterns]

        # Create screenshot directory if needed
        if self.config.capture_screenshots:
            self.config.screenshot_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"GUIMonitor initialized: poll_interval={self.config.poll_interval}s, "
            f"memory_threshold={self.config.memory_threshold_mb}MB"
        )

    def start_monitoring(
        self, process: subprocess.Popen[bytes], test_file: Path | None = None
    ) -> None:
        """Start monitoring a process.

        Args:
            process: The subprocess to monitor
            test_file: The test file being processed

        """
        if self._monitoring:
            logger.warning("Already monitoring a process")
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(process, test_file),
            daemon=True,
        )
        self._monitor_thread.start()
        logger.debug(f"Started monitoring process {process.pid}")

    def stop_monitoring(self) -> None:
        """Stop monitoring the current process."""
        self._monitoring = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
        logger.debug("Stopped monitoring")

    def _monitor_loop(
        self, process: subprocess.Popen[bytes], test_file: Path | None
    ) -> None:
        """Main monitoring loop.

        Args:
            process: Process to monitor
            test_file: Test file being processed

        """
        if not HAS_PSUTIL:
            logger.warning("psutil not available, limited monitoring")
            return

        try:
            ps_process = psutil.Process(process.pid)
            self._baseline_memory = ps_process.memory_info().rss / (1024 * 1024)
        except psutil.NoSuchProcess:
            return

        last_cpu_check = time.time()

        while self._monitoring and process.poll() is None:
            try:
                # Check memory usage
                self._check_memory(ps_process, test_file)

                # Check for dialogs (Windows only)
                if HAS_PYWINAUTO:
                    self._check_dialogs(process.pid, test_file)

                # Check for hang (CPU usage near zero for extended period)
                if time.time() - last_cpu_check > self.config.hang_timeout:
                    self._check_hang(ps_process, test_file)
                    last_cpu_check = time.time()

            except psutil.NoSuchProcess:
                # Process died
                self._add_response(
                    GUIResponse(
                        response_type=ResponseType.CRASH,
                        severity=SeverityLevel.CRITICAL,
                        test_file=test_file,
                        details="Process terminated unexpectedly",
                    )
                )
                break
            except Exception as e:
                logger.debug(f"Monitoring error: {e}")

            time.sleep(self.config.poll_interval)

        # Final check after process exits
        exit_code = process.poll()
        if exit_code is not None and exit_code != 0:
            self._add_response(
                GUIResponse(
                    response_type=ResponseType.CRASH,
                    severity=SeverityLevel.CRITICAL,
                    test_file=test_file,
                    details=f"Process exited with code {exit_code}",
                )
            )

    def _check_memory(self, ps_process: psutil.Process, test_file: Path | None) -> None:
        """Check for memory anomalies.

        Args:
            ps_process: psutil Process object
            test_file: Test file being processed

        """
        try:
            mem_info = ps_process.memory_info()
            mem_mb = mem_info.rss / (1024 * 1024)

            # Check absolute threshold
            if mem_mb > self.config.memory_threshold_mb:
                self._add_response(
                    GUIResponse(
                        response_type=ResponseType.RESOURCE_EXHAUSTION,
                        severity=SeverityLevel.HIGH,
                        test_file=test_file,
                        details=f"Memory usage {mem_mb:.1f}MB exceeds threshold "
                        f"{self.config.memory_threshold_mb}MB",
                        memory_usage_mb=mem_mb,
                    )
                )

            # Check for spike
            if self._baseline_memory > 0:
                increase_percent = (
                    (mem_mb - self._baseline_memory) / self._baseline_memory
                ) * 100
                if increase_percent > self.config.memory_spike_percent:
                    self._add_response(
                        GUIResponse(
                            response_type=ResponseType.MEMORY_SPIKE,
                            severity=SeverityLevel.MEDIUM,
                            test_file=test_file,
                            details=f"Memory increased {increase_percent:.1f}% "
                            f"({self._baseline_memory:.1f}MB -> {mem_mb:.1f}MB)",
                            memory_usage_mb=mem_mb,
                        )
                    )

        except psutil.NoSuchProcess:
            # Process exited during monitoring - expected race condition
            logger.debug("Process exited during memory monitoring")

    def _check_dialogs(self, pid: int, test_file: Path | None) -> None:
        """Check for error/warning dialogs using pywinauto.

        Args:
            pid: Process ID to check
            test_file: Test file being processed

        """
        if not HAS_PYWINAUTO:
            return

        try:
            app = Application(backend="uia").connect(process=pid)

            # Find all windows
            for window in app.windows():
                try:
                    title = window.window_text()
                    # Get all text from the window
                    texts = self._get_window_texts(window)
                    combined_text = " ".join(texts)

                    # Check for error patterns
                    for pattern in self._error_patterns:
                        if pattern.search(combined_text) or pattern.search(title):
                            self._add_response(
                                GUIResponse(
                                    response_type=ResponseType.ERROR_DIALOG,
                                    severity=SeverityLevel.HIGH,
                                    test_file=test_file,
                                    details=f"Error dialog detected: {title}",
                                    window_title=title,
                                    dialog_text=combined_text[:500],
                                )
                            )
                            break

                    # Check for warning patterns
                    for pattern in self._warning_patterns:
                        if pattern.search(combined_text) or pattern.search(title):
                            self._add_response(
                                GUIResponse(
                                    response_type=ResponseType.WARNING_DIALOG,
                                    severity=SeverityLevel.MEDIUM,
                                    test_file=test_file,
                                    details=f"Warning dialog detected: {title}",
                                    window_title=title,
                                    dialog_text=combined_text[:500],
                                )
                            )
                            break

                except Exception as window_err:
                    # Window access error (closed, minimized, etc.)
                    logger.debug(f"Window access error: {window_err}")

        except ElementNotFoundError:
            # Application not found or no longer running
            logger.debug("Application window not found for dialog check")
        except Exception as e:
            logger.debug(f"Dialog check error: {e}")

    def _get_window_texts(self, window: Any) -> list[str]:
        """Extract all text content from a window.

        Args:
            window: pywinauto window object

        Returns:
            List of text strings found in the window

        """
        texts = []
        try:
            # Get window text
            if hasattr(window, "window_text"):
                text = window.window_text()
                if text:
                    texts.append(text)

            # Get text from child controls
            if hasattr(window, "descendants"):
                for control in window.descendants():
                    try:
                        text = control.window_text()
                        if text:
                            texts.append(text)
                    except Exception:
                        # Control access failed - skip to next control
                        continue
        except Exception as text_err:
            # Window text extraction failed - return what we have
            logger.debug(f"Window text extraction error: {text_err}")

        return texts

    def _check_hang(self, ps_process: psutil.Process, test_file: Path | None) -> None:
        """Check if application is hanging (not responding).

        Args:
            ps_process: psutil Process object
            test_file: Test file being processed

        """
        try:
            # Check CPU usage over time
            cpu_percent = ps_process.cpu_percent(interval=0.5)
            status = ps_process.status()

            # If CPU is near zero and status is running, might be hung
            if cpu_percent < 0.1 and status == psutil.STATUS_RUNNING:
                # Additional check: try to get threads
                try:
                    threads = ps_process.threads()
                    if all(t.user_time == 0 for t in threads):
                        self._add_response(
                            GUIResponse(
                                response_type=ResponseType.HANG,
                                severity=SeverityLevel.HIGH,
                                test_file=test_file,
                                details="Application appears to be hanging "
                                f"(CPU: {cpu_percent}%, Status: {status})",
                            )
                        )
                except Exception as thread_err:
                    # Thread info unavailable - skip hang detection for this check
                    logger.debug(f"Could not get thread info: {thread_err}")

        except psutil.NoSuchProcess:
            # Process exited during hang check - not actually hung
            logger.debug("Process exited during hang check")

    def _add_response(self, response: GUIResponse) -> None:
        """Add a response to the list (thread-safe).

        Args:
            response: Response to add

        """
        # Debounce similar responses
        current_time = time.time()
        if current_time - self._last_response_time < 1.0:
            return

        with self._lock:
            # Check for duplicates
            for existing in self._responses[-10:]:
                if (
                    existing.response_type == response.response_type
                    and existing.details == response.details
                ):
                    return

            self._responses.append(response)
            self._last_response_time = current_time

            logger.info(
                f"GUI Response: {response.response_type.value} "
                f"[{response.severity.value}] - {response.details}"
            )

    def get_responses(self) -> list[GUIResponse]:
        """Get all detected responses.

        Returns:
            List of GUIResponse objects

        """
        with self._lock:
            return list(self._responses)

    def clear_responses(self) -> None:
        """Clear all recorded responses."""
        with self._lock:
            self._responses.clear()

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all responses.

        Returns:
            Dictionary with response statistics

        """
        with self._lock:
            summary: dict[str, Any] = {
                "total_responses": len(self._responses),
                "by_type": {},
                "by_severity": {},
                "critical_issues": [],
            }

            for response in self._responses:
                # Count by type
                type_name = response.response_type.value
                summary["by_type"][type_name] = summary["by_type"].get(type_name, 0) + 1

                # Count by severity
                sev_name = response.severity.value
                summary["by_severity"][sev_name] = (
                    summary["by_severity"].get(sev_name, 0) + 1
                )

                # Track critical issues
                if response.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
                    summary["critical_issues"].append(response.to_dict())

            return summary


# Import GUIFuzzer for backward compatibility
# Cyclic import is intentional: gui_fuzzer imports GUIMonitor at runtime in __init__
from dicom_fuzzer.core.gui_fuzzer import (  # noqa: E402
    GUIFuzzer,  # lgtm[py/cyclic-import]
)

# Backward compatibility alias
ResponseAwareFuzzer = GUIFuzzer


# Re-export all public symbols for backward compatibility
__all__ = [
    # Types and Enums (from gui_monitor_types)
    "ResponseType",
    "SeverityLevel",
    "GUIResponse",
    "MonitorConfig",
    # State coverage (from state_coverage)
    "StateTransition",
    "StateCoverageTracker",
    # Main class
    "GUIMonitor",
    # Fuzzer (from gui_fuzzer)
    "GUIFuzzer",
    "ResponseAwareFuzzer",  # Backward compatibility alias
]
