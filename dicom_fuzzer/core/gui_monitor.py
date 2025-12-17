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
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

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


class ResponseType(Enum):
    """Types of responses detected from GUI applications."""

    NORMAL = "normal"  # App running normally
    ERROR_DIALOG = "error_dialog"  # Error dialog detected
    WARNING_DIALOG = "warning_dialog"  # Warning dialog detected
    CRASH = "crash"  # Application crashed
    HANG = "hang"  # Application not responding
    MEMORY_SPIKE = "memory_spike"  # Abnormal memory usage
    RENDER_ANOMALY = "render_anomaly"  # Rendering issue detected
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # Out of resources


class SeverityLevel(Enum):
    """Severity levels for detected issues."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GUIResponse:
    """Represents a response detected from a GUI application.

    Attributes:
        response_type: Type of response detected
        severity: Severity level of the response
        timestamp: When the response was detected
        test_file: File that triggered this response
        details: Additional details about the response
        window_title: Title of the window that generated the response
        dialog_text: Text content of any dialog detected
        memory_usage_mb: Memory usage at time of detection
        screenshot_path: Path to screenshot if captured

    """

    response_type: ResponseType
    severity: SeverityLevel
    timestamp: datetime = field(default_factory=datetime.now)
    test_file: Path | None = None
    details: str = ""
    window_title: str = ""
    dialog_text: str = ""
    memory_usage_mb: float = 0.0
    screenshot_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "response_type": self.response_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "test_file": str(self.test_file) if self.test_file else None,
            "details": self.details,
            "window_title": self.window_title,
            "dialog_text": self.dialog_text,
            "memory_usage_mb": self.memory_usage_mb,
            "screenshot_path": str(self.screenshot_path)
            if self.screenshot_path
            else None,
        }


@dataclass
class MonitorConfig:
    """Configuration for GUI monitoring.

    Attributes:
        poll_interval: Seconds between monitoring checks
        memory_threshold_mb: Memory usage that triggers alert
        memory_spike_percent: Percentage increase that triggers spike alert
        hang_timeout: Seconds of unresponsiveness before hang detection
        capture_screenshots: Whether to capture screenshots of issues
        screenshot_dir: Directory to save screenshots
        error_patterns: Regex patterns to detect in dialog text
        warning_patterns: Regex patterns for warning dialogs

    """

    poll_interval: float = 0.1
    memory_threshold_mb: float = 2048.0
    memory_spike_percent: float = 50.0
    hang_timeout: float = 5.0
    capture_screenshots: bool = True
    screenshot_dir: Path = field(default_factory=lambda: Path("./screenshots"))
    error_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)error",
            r"(?i)exception",
            r"(?i)failed",
            r"(?i)cannot\s+open",
            r"(?i)invalid\s+file",
            r"(?i)corrupt",
            r"(?i)access\s+violation",
            r"(?i)segmentation\s+fault",
            r"(?i)out\s+of\s+memory",
            r"(?i)stack\s+overflow",
            r"(?i)buffer\s+overflow",
        ]
    )
    warning_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)warning",
            r"(?i)caution",
            r"(?i)could\s+not",
            r"(?i)unable\s+to",
            r"(?i)unexpected",
            r"(?i)unsupported",
        ]
    )


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


@dataclass
class StateTransition:
    """Represents a state transition in the application.

    AFLNet-style state tracking for GUI applications.
    """

    from_state: str
    to_state: str
    trigger: str  # What caused the transition (e.g., "file_load", "dialog_open")
    timestamp: float = 0.0
    test_file: Path | None = None

    def __hash__(self) -> int:
        return hash((self.from_state, self.to_state, self.trigger))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StateTransition):
            return False
        return (
            self.from_state == other.from_state
            and self.to_state == other.to_state
            and self.trigger == other.trigger
        )


class StateCoverageTracker:
    """Track state coverage for response-aware fuzzing.

    Inspired by AFLNet's state-aware fuzzing, this tracks:
    - Unique application states visited
    - State transitions observed
    - Coverage-based prioritization of inputs

    This allows for more intelligent fuzzing by:
    1. Identifying inputs that reach new states
    2. Tracking state transition sequences
    3. Prioritizing inputs that explore new paths

    References:
    - AFLNet: A Greybox Fuzzer for Network Protocols (ICST 2020)
    - StateAFL: Greybox Fuzzing Stateful Network Services (ICSE 2022)

    """

    # Pre-defined states for GUI applications
    STATE_INITIAL = "initial"
    STATE_LOADING = "loading"
    STATE_NORMAL = "normal"
    STATE_ERROR_DIALOG = "error_dialog"
    STATE_WARNING_DIALOG = "warning_dialog"
    STATE_CRASH = "crash"
    STATE_HANG = "hang"
    STATE_MEMORY_ISSUE = "memory_issue"

    def __init__(self) -> None:
        self._states_visited: set[str] = set()
        self._transitions: set[StateTransition] = set()
        self._state_sequences: list[list[str]] = []
        self._current_sequence: list[str] = []
        self._interesting_inputs: dict[Path, set[str]] = {}  # file -> states it reached
        self._lock = threading.Lock()

    def start_execution(self) -> None:
        """Start tracking a new execution."""
        with self._lock:
            self._current_sequence = [self.STATE_INITIAL]
            self._states_visited.add(self.STATE_INITIAL)

    def record_state(
        self, state: str, trigger: str = "", test_file: Path | None = None
    ) -> bool:
        """Record a state transition.

        Args:
            state: New state reached
            trigger: What triggered this state
            test_file: File being tested

        Returns:
            True if this is a new state (not seen before)

        """
        with self._lock:
            is_new = state not in self._states_visited
            self._states_visited.add(state)

            if self._current_sequence:
                from_state = self._current_sequence[-1]
                transition = StateTransition(
                    from_state=from_state,
                    to_state=state,
                    trigger=trigger,
                    timestamp=time.time(),
                    test_file=test_file,
                )
                self._transitions.add(transition)

            self._current_sequence.append(state)

            # Track which inputs reached which states
            if test_file:
                if test_file not in self._interesting_inputs:
                    self._interesting_inputs[test_file] = set()
                self._interesting_inputs[test_file].add(state)

            return is_new

    def end_execution(self) -> list[str]:
        """End tracking current execution and return the sequence."""
        with self._lock:
            sequence = self._current_sequence.copy()
            if sequence:
                self._state_sequences.append(sequence)
            self._current_sequence = []
            return sequence

    def get_state_coverage(self) -> dict[str, Any]:
        """Get current state coverage statistics.

        Returns:
            Dictionary with coverage metrics

        """
        with self._lock:
            return {
                "unique_states": len(self._states_visited),
                "states_visited": list(self._states_visited),
                "unique_transitions": len(self._transitions),
                "total_executions": len(self._state_sequences),
                "transition_details": [
                    {
                        "from": t.from_state,
                        "to": t.to_state,
                        "trigger": t.trigger,
                    }
                    for t in self._transitions
                ],
            }

    def get_interesting_inputs(self) -> list[Path]:
        """Get inputs that reached unique states.

        Returns:
            List of file paths that discovered new states

        """
        with self._lock:
            # Rank by number of unique states reached
            ranked = sorted(
                self._interesting_inputs.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            )
            return [path for path, _ in ranked]

    def is_interesting(self, test_file: Path) -> bool:
        """Check if an input discovered new states.

        Args:
            test_file: File to check

        Returns:
            True if this file discovered at least one new state

        """
        with self._lock:
            if test_file not in self._interesting_inputs:
                return False
            # Check if any states were first discovered by this file
            states = self._interesting_inputs[test_file]
            for other_file, other_states in self._interesting_inputs.items():
                if other_file != test_file:
                    states = states - other_states
            return len(states) > 0


class ResponseAwareFuzzer:
    """Fuzzer that uses response-aware monitoring with state coverage.

    Integrates GUIMonitor with fuzzing to detect more than just crashes:
    - Error dialogs indicate potential parsing issues
    - Warning dialogs may reveal edge cases
    - Memory spikes suggest potential DoS vulnerabilities
    - Hangs indicate potential infinite loops

    State Coverage (AFLNet-style):
    - Tracks unique application states visited
    - Records state transitions
    - Identifies inputs that reach new states
    - Prioritizes exploration of new paths

    """

    def __init__(
        self,
        target_executable: str,
        config: MonitorConfig | None = None,
        timeout: float = 10.0,
        enable_state_coverage: bool = True,
    ):
        """Initialize response-aware fuzzer.

        Args:
            target_executable: Path to target application
            config: Monitor configuration
            timeout: Execution timeout in seconds
            enable_state_coverage: Enable AFLNet-style state tracking

        """
        self.target_executable = Path(target_executable)
        self.monitor = GUIMonitor(config)
        self.timeout = timeout
        self.enable_state_coverage = enable_state_coverage
        self.state_tracker: StateCoverageTracker | None = None

        if enable_state_coverage:
            self.state_tracker = StateCoverageTracker()

        if not self.target_executable.exists():
            raise FileNotFoundError(f"Target executable not found: {target_executable}")

    def test_file(self, test_file: Path) -> list[GUIResponse]:
        """Test a single file and return all responses.

        Args:
            test_file: DICOM file to test

        Returns:
            List of responses detected during testing

        """
        import subprocess

        self.monitor.clear_responses()

        # Start state tracking if enabled
        if self.state_tracker:
            self.state_tracker.start_execution()
            self.state_tracker.record_state(
                StateCoverageTracker.STATE_LOADING,
                trigger="file_open",
                test_file=test_file,
            )

        try:
            process = subprocess.Popen(
                [str(self.target_executable), str(test_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.monitor.start_monitoring(process, test_file)

            # Wait for timeout
            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                # Expected for GUI apps - they don't exit on their own
                logger.debug("Process timeout expired - killing process")

            self.monitor.stop_monitoring()

            # Kill if still running
            if process.poll() is None:
                try:
                    if HAS_PSUTIL:
                        parent = psutil.Process(process.pid)
                        for child in parent.children(recursive=True):
                            child.kill()
                        parent.kill()
                    else:
                        process.kill()
                except Exception as kill_err:
                    # Process may have exited during kill attempt
                    logger.debug(f"Process kill error (may be expected): {kill_err}")

        except Exception as e:
            logger.error(f"Error testing {test_file}: {e}")
            self.monitor._add_response(
                GUIResponse(
                    response_type=ResponseType.CRASH,
                    severity=SeverityLevel.CRITICAL,
                    test_file=test_file,
                    details=f"Test execution failed: {e}",
                )
            )

        # Record states based on responses
        responses = self.monitor.get_responses()
        if self.state_tracker:
            self._record_response_states(responses, test_file)
            self.state_tracker.end_execution()

        return responses

    def _record_response_states(
        self, responses: list[GUIResponse], test_file: Path
    ) -> None:
        """Record states based on GUI responses.

        Args:
            responses: List of responses from monitoring
            test_file: File being tested

        """
        if not self.state_tracker:
            return

        if not responses:
            # No issues - normal state
            self.state_tracker.record_state(
                StateCoverageTracker.STATE_NORMAL,
                trigger="no_issues",
                test_file=test_file,
            )
            return

        for response in responses:
            state = self._response_to_state(response.response_type)
            if response.details:
                trigger = response.details[:50]
            else:
                trigger = response.response_type.value
            self.state_tracker.record_state(state, trigger=trigger, test_file=test_file)

    def _response_to_state(self, response_type: ResponseType) -> str:
        """Map response type to state name.

        Args:
            response_type: The response type

        Returns:
            State name string

        """
        mapping = {
            ResponseType.NORMAL: StateCoverageTracker.STATE_NORMAL,
            ResponseType.ERROR_DIALOG: StateCoverageTracker.STATE_ERROR_DIALOG,
            ResponseType.WARNING_DIALOG: StateCoverageTracker.STATE_WARNING_DIALOG,
            ResponseType.CRASH: StateCoverageTracker.STATE_CRASH,
            ResponseType.HANG: StateCoverageTracker.STATE_HANG,
            ResponseType.MEMORY_SPIKE: StateCoverageTracker.STATE_MEMORY_ISSUE,
            ResponseType.RESOURCE_EXHAUSTION: StateCoverageTracker.STATE_MEMORY_ISSUE,
            ResponseType.RENDER_ANOMALY: "render_anomaly",
        }
        return mapping.get(response_type, "unknown")

    def run_campaign(
        self, test_files: list[Path], stop_on_critical: bool = False
    ) -> dict[str, Any]:
        """Run fuzzing campaign with response monitoring and state coverage.

        Args:
            test_files: List of files to test
            stop_on_critical: Stop on first critical issue

        Returns:
            Campaign results dictionary including state coverage metrics

        """
        results: dict[str, Any] = {
            "total_files": len(test_files),
            "files_tested": 0,
            "responses": [],
            "summary": {},
            "state_coverage": {},
            "interesting_inputs": [],
        }

        for test_file in test_files:
            responses = self.test_file(test_file)
            results["files_tested"] += 1

            for response in responses:
                results["responses"].append(response.to_dict())

                if stop_on_critical and response.severity == SeverityLevel.CRITICAL:
                    logger.warning(f"Stopping on critical issue: {response.details}")
                    break

        results["summary"] = self.monitor.get_summary()

        # Add state coverage information
        if self.state_tracker:
            results["state_coverage"] = self.state_tracker.get_state_coverage()
            results["interesting_inputs"] = [
                str(p) for p in self.state_tracker.get_interesting_inputs()
            ]

            logger.info(
                f"State coverage: {results['state_coverage']['unique_states']} states, "
                f"{results['state_coverage']['unique_transitions']} transitions"
            )

        return results

    def get_state_coverage(self) -> dict[str, Any]:
        """Get current state coverage statistics.

        Returns:
            Dictionary with state coverage metrics, or empty dict if disabled

        """
        if self.state_tracker:
            return self.state_tracker.get_state_coverage()
        return {}

    def get_interesting_inputs(self) -> list[Path]:
        """Get inputs that discovered new states.

        Returns:
            List of file paths that reached unique states

        """
        if self.state_tracker:
            return self.state_tracker.get_interesting_inputs()
        return []
