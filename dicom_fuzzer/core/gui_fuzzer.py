"""GUI-aware fuzzer with state coverage.

This module provides GUIFuzzer which integrates GUI monitoring
with fuzzing to detect more than just crashes:
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

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.core.gui_monitor_types import (
    GUIResponse,
    MonitorConfig,
    ResponseType,
    SeverityLevel,
)
from dicom_fuzzer.core.state_coverage import StateCoverageTracker

if TYPE_CHECKING:
    from dicom_fuzzer.core.gui_monitor import GUIMonitor

# Optional imports for process management
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger(__name__)


class GUIFuzzer:
    """Fuzzer that uses GUI response monitoring with state coverage.

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
        """Initialize GUI-aware fuzzer.

        Args:
            target_executable: Path to target application
            config: Monitor configuration
            timeout: Execution timeout in seconds
            enable_state_coverage: Enable AFLNet-style state tracking

        """
        # Import here to avoid circular import
        from dicom_fuzzer.core.gui_monitor import GUIMonitor

        self.target_executable = Path(target_executable)
        self.monitor: GUIMonitor = GUIMonitor(config)
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


# Re-export all public symbols
__all__ = [
    "GUIFuzzer",
]
