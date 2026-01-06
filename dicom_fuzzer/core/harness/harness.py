"""Target Harness for GUI Application Testing.

Main harness class that coordinates target application testing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

import structlog

from dicom_fuzzer.core.harness.monitoring import (
    is_psutil_available,
    kill_target_processes,
    monitor_process,
    run_observation_phase,
)
from dicom_fuzzer.core.harness.types import (
    DEFAULT_OBSERVATION_PHASES,
    CrashArtifact,
    ObservationPhase,
    PhasedTestResult,
    PhaseResult,
    TargetConfig,
    TestResult,
    TestStatus,
)

if TYPE_CHECKING:
    from dicom_fuzzer.adapters.base import ViewerAdapter

logger = structlog.get_logger(__name__)


class TargetHarness:
    """Harness for testing target applications with DICOM inputs.

    This class provides methods to:
    - Launch target applications with study directories
    - Monitor for crashes, memory issues, and timeouts
    - Save crash artifacts for later analysis
    - Kill related target processes
    """

    def __init__(
        self,
        config: TargetConfig,
        crash_dir: Path,
        log_file: Path | None = None,
    ) -> None:
        """Initialize the target harness.

        Args:
            config: Target configuration.
            crash_dir: Directory to save crash artifacts.
            log_file: Optional log file for harness operations.

        """
        self.config = config
        self.crash_dir = crash_dir
        self.log_file = log_file

        # Create crash directory
        self.crash_dir.mkdir(parents=True, exist_ok=True)

        # Statistics
        self._stats = {
            "total_tests": 0,
            "success": 0,
            "crash": 0,
            "memory_exceeded": 0,
            "timeout": 0,
            "error": 0,
        }

        # Check psutil availability
        if not is_psutil_available():
            logger.warning(
                "psutil not available - memory monitoring disabled",
            )

    def _create_error_result(
        self, input_path: Path, error_message: str, start_time: float
    ) -> TestResult:
        """Create error TestResult and increment error stat."""
        self._stats["error"] += 1
        return TestResult(
            input_path=input_path,
            status="error",
            error_message=error_message,
            duration_seconds=time.time() - start_time,
        )

    def _try_adapter_render(
        self,
        viewer_adapter: ViewerAdapter | None,
        pid: int,
        study_dir: Path,
        series_name: str | None,
    ) -> tuple[bool, str | None]:
        """Try to connect adapter and render study.

        Returns:
            Tuple of (render_failed, error_message).

        """
        if viewer_adapter is None:
            return False, None

        if not viewer_adapter.connect(pid=pid):
            logger.warning("Could not connect adapter to viewer")
            return False, None

        logger.debug("Adapter connected", pid=pid)
        render_result = viewer_adapter.load_study_into_viewport(
            study_dir, series_name=series_name, timeout=self.config.timeout_seconds / 2
        )
        if not render_result.success:
            logger.warning("Render failed", error=render_result.error_message)
            return True, render_result.error_message
        return False, None

    def test_study_directory(
        self,
        study_dir: Path,
        viewer_adapter: ViewerAdapter | None = None,
        series_name: str | None = None,
    ) -> TestResult:
        """Test target application with a study directory.

        Args:
            study_dir: Path to study directory containing DICOM series.
            viewer_adapter: Optional viewer adapter for UI automation.
            series_name: Series name to search for when using adapter.

        Returns:
            TestResult with status and metrics.

        """
        start_time = time.time()
        self._stats["total_tests"] += 1

        # Default result
        result = TestResult(
            input_path=study_dir,
            status="error",
            error_message="Test not completed",
        )

        try:
            # Kill any existing target processes
            self.kill_target_processes()

            # Verify executable exists
            if not self.config.executable.exists():
                result.status = "error"
                result.error_message = f"Executable not found: {self.config.executable}"
                result.duration_seconds = time.time() - start_time
                self._stats["error"] += 1
                return result

            # Launch target with study directory
            logger.debug(
                "Launching target",
                executable=str(self.config.executable),
                study_dir=str(study_dir),
            )

            process = subprocess.Popen(
                [str(self.config.executable), str(study_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for startup
            time.sleep(self.config.startup_delay_seconds)

            # Connect adapter and load series into viewport (if adapter provided)
            render_failed, render_error = self._try_adapter_render(
                viewer_adapter, process.pid, study_dir, series_name
            )

            # Monitor process
            result = monitor_process(
                process,
                study_dir,
                start_time,
                self.config.timeout_seconds,
                self.config.memory_limit_mb,
            )

            # If render failed, update result status
            if render_failed and result.status == "success":
                result = TestResult(
                    input_path=result.input_path,
                    status="error",
                    exit_code=result.exit_code,
                    memory_peak_mb=result.memory_peak_mb,
                    duration_seconds=result.duration_seconds,
                    error_message=f"Render failed: {render_error}",
                    process_pid=result.process_pid,
                )

        except FileNotFoundError as e:
            result = self._create_error_result(
                study_dir, f"Executable not found: {e}", start_time
            )

        except PermissionError as e:
            result = self._create_error_result(
                study_dir, f"Permission denied: {e}", start_time
            )

        except Exception as e:
            result = self._create_error_result(study_dir, str(e), start_time)
            logger.exception("Error during test", error=str(e))

        finally:
            # Disconnect adapter before killing process
            if viewer_adapter is not None:
                viewer_adapter.disconnect()
            # Cleanup
            self.kill_target_processes()

        # Update stats
        if result.status in self._stats:
            self._stats[result.status] += 1

        return result

    def test_file(self, file_path: Path) -> TestResult:
        """Test target application with a single DICOM file.

        Args:
            file_path: Path to DICOM file.

        Returns:
            TestResult with status and metrics.

        """
        # For single files, we use the same mechanism
        return self.test_study_directory(file_path)

    def test_study_with_phases(
        self,
        study_dir: Path,
        phases: list[ObservationPhase] | None = None,
    ) -> PhasedTestResult:
        """Test target application with phased observation.

        Runs multiple observation phases with different timeouts and memory
        limits. Each phase can have a validation callback to check UI state.

        Args:
            study_dir: Path to study directory containing DICOM series.
            phases: List of observation phases. If None, uses DEFAULT_OBSERVATION_PHASES.

        Returns:
            PhasedTestResult with per-phase results and overall status.

        """
        if phases is None:
            phases = DEFAULT_OBSERVATION_PHASES

        start_time = time.time()
        self._stats["total_tests"] += 1
        phase_results: list[PhaseResult] = []

        # Default result
        result = PhasedTestResult(
            input_path=study_dir,
            status="error",
            error_message="Test not completed",
            phase_results=[],
        )

        try:
            # Kill any existing target processes
            self.kill_target_processes()

            # Verify executable exists
            if not self.config.executable.exists():
                result.status = "error"
                result.error_message = f"Executable not found: {self.config.executable}"
                result.duration_seconds = time.time() - start_time
                self._stats["error"] += 1
                return result

            # Launch target with study directory
            logger.debug(
                "Launching target for phased observation",
                executable=str(self.config.executable),
                study_dir=str(study_dir),
                phases=[p.name for p in phases],
            )

            process = subprocess.Popen(
                [str(self.config.executable), str(study_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for initial startup
            time.sleep(self.config.startup_delay_seconds)

            # Run each phase
            total_memory_peak = 0.0
            failed_phase = None

            for phase in phases:
                phase_result = run_observation_phase(
                    process=process,
                    phase=phase,
                    default_memory_limit=self.config.memory_limit_mb,
                )
                phase_results.append(phase_result)
                total_memory_peak = max(total_memory_peak, phase_result.memory_peak_mb)

                # Stop on failure
                if phase_result.status != "success":
                    failed_phase = phase.name
                    break

            # Determine overall status
            if failed_phase:
                final_phase = phase_results[-1]
                result = PhasedTestResult(
                    input_path=study_dir,
                    status=cast(TestStatus, final_phase.status),
                    memory_peak_mb=total_memory_peak,
                    duration_seconds=time.time() - start_time,
                    error_message=final_phase.error_message,
                    phase_results=phase_results,
                    failed_phase=failed_phase,
                )
            else:
                result = PhasedTestResult(
                    input_path=study_dir,
                    status="success",
                    memory_peak_mb=total_memory_peak,
                    duration_seconds=time.time() - start_time,
                    phase_results=phase_results,
                )

        except FileNotFoundError as e:
            result = PhasedTestResult(
                input_path=study_dir,
                status="error",
                error_message=f"Executable not found: {e}",
                duration_seconds=time.time() - start_time,
                phase_results=phase_results,
            )
            self._stats["error"] += 1

        except Exception as e:
            result = PhasedTestResult(
                input_path=study_dir,
                status="error",
                error_message=str(e),
                duration_seconds=time.time() - start_time,
                phase_results=phase_results,
            )
            self._stats["error"] += 1
            logger.exception("Error during phased test", error=str(e))

        finally:
            # Cleanup
            self.kill_target_processes()

        # Update stats
        if result.status in self._stats:
            self._stats[result.status] += 1

        return result

    def save_crash_artifact(
        self,
        result: TestResult,
        study_dir: Path,
        test_id: int,
        mutation_records: list | None = None,
        viewer_adapter: ViewerAdapter | None = None,
    ) -> CrashArtifact:
        """Save crash artifact for later analysis.

        Args:
            result: The test result that triggered the crash.
            study_dir: Path to the study that caused the crash.
            test_id: Numeric ID of the test.
            mutation_records: Optional list of mutation records.
            viewer_adapter: Optional viewer adapter for capturing screenshot.

        Returns:
            CrashArtifact with paths to saved files.

        """
        crash_subdir = self.crash_dir / f"crash_{test_id:04d}"
        crash_subdir.mkdir(parents=True, exist_ok=True)

        study_copy_path = None

        # Copy the study directory
        if study_dir.exists():
            study_copy_path = crash_subdir / "study"
            if study_dir.is_dir():
                shutil.copytree(study_dir, study_copy_path, dirs_exist_ok=True)
            else:
                study_copy_path.mkdir(parents=True, exist_ok=True)
                shutil.copy2(study_dir, study_copy_path / study_dir.name)

        # Save result as JSON
        result_file = crash_subdir / "result.json"
        with open(result_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        # Save mutation records if provided
        if mutation_records:
            records_file = crash_subdir / "mutation_records.json"
            with open(records_file, "w") as f:
                # Convert mutation records to serializable format
                records_data = []
                for record in mutation_records:
                    if hasattr(record, "to_dict"):
                        records_data.append(record.to_dict())
                    elif hasattr(record, "__dict__"):
                        records_data.append(record.__dict__)
                    else:
                        records_data.append(str(record))
                json.dump(records_data, f, indent=2, default=str)

        # Capture screenshot if adapter is connected (failure artifact only)
        if viewer_adapter is not None and viewer_adapter.is_connected():
            screenshot_path = crash_subdir / "screenshot.png"
            if viewer_adapter.capture_screenshot(screenshot_path):
                logger.debug(
                    "Screenshot saved to crash artifact", path=str(screenshot_path)
                )

        logger.info(
            "Crash artifact saved",
            crash_dir=str(crash_subdir),
            test_id=test_id,
            status=result.status,
        )

        return CrashArtifact(
            crash_dir=crash_subdir,
            test_result=result,
            test_id=test_id,
            study_copy_path=study_copy_path,
        )

    def kill_target_processes(self) -> int:
        """Kill any running target processes.

        Returns:
            Number of processes killed.

        """
        return kill_target_processes(self.config.process_pattern)

    def get_stats(self) -> dict:
        """Get harness statistics.

        Returns:
            Dictionary with test statistics.

        """
        return self._stats.copy()

    def reset_stats(self) -> None:
        """Reset harness statistics."""
        self._stats = {
            "total_tests": 0,
            "success": 0,
            "crash": 0,
            "memory_exceeded": 0,
            "timeout": 0,
            "error": 0,
        }


__all__ = ["TargetHarness"]
