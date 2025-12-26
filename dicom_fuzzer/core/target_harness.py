"""Target Harness for GUI Application Testing.

Provides a reusable harness for testing target applications (DICOM viewers, etc.)
with mutated DICOM studies. Monitors for crashes, memory issues, and timeouts.

Example usage:
    from dicom_fuzzer.core.target_harness import TargetHarness, TargetConfig

    config = TargetConfig(
        executable=Path("/path/to/viewer.exe"),
        timeout_seconds=15.0,
        memory_limit_mb=2048,
    )
    harness = TargetHarness(config, crash_dir=Path("./crashes"))
    result = harness.test_study_directory(Path("./mutated_study"))
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import structlog

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)

# Status type for test results
TestStatus = Literal["success", "crash", "memory_exceeded", "timeout", "error"]


@dataclass
class TargetConfig:
    """Configuration for target application testing.

    Attributes:
        executable: Path to the target executable.
        timeout_seconds: Maximum time to wait for target (default: 15.0).
        startup_delay_seconds: Delay before monitoring starts (default: 3.0).
        memory_limit_mb: Memory limit in MB before killing (default: 2048).
        process_name_pattern: Pattern to match for killing related processes.
            If None, uses the executable name.

    """

    executable: Path
    timeout_seconds: float = 15.0
    startup_delay_seconds: float = 3.0
    memory_limit_mb: int = 2048
    process_name_pattern: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration."""
        if isinstance(self.executable, str):
            self.executable = Path(self.executable)

        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        if self.startup_delay_seconds < 0:
            raise ValueError("startup_delay_seconds must be non-negative")

        if self.memory_limit_mb <= 0:
            raise ValueError("memory_limit_mb must be positive")

    @property
    def process_pattern(self) -> str:
        """Get the process name pattern for matching."""
        if self.process_name_pattern:
            return self.process_name_pattern.lower()
        return self.executable.stem.lower()


@dataclass
class TestResult:
    """Result from testing a study/file with target application.

    Attributes:
        input_path: Path to the input study/file that was tested.
        status: Result status (success, crash, memory_exceeded, timeout, error).
        exit_code: Process exit code if available.
        memory_peak_mb: Peak memory usage in MB.
        duration_seconds: Total test duration in seconds.
        error_message: Error message if status is crash/error.
        timestamp: When the test was executed.
        process_pid: PID of the process (may be invalid if process exited).

    """

    input_path: Path
    status: TestStatus
    exit_code: int | None = None
    memory_peak_mb: float = 0.0
    duration_seconds: float = 0.0
    error_message: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    process_pid: int | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["input_path"] = str(self.input_path)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> TestResult:
        """Create from dictionary."""
        data = data.copy()
        data["input_path"] = Path(data["input_path"])
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)

    def is_failure(self) -> bool:
        """Check if this result represents a failure worth investigating."""
        return self.status in ("crash", "memory_exceeded", "error")


@dataclass
class CrashArtifact:
    """Information about a saved crash artifact.

    Attributes:
        crash_dir: Directory containing the crash artifact.
        test_result: The test result that triggered the crash.
        test_id: Numeric ID of the test.
        study_copy_path: Path to the copied study directory.

    """

    crash_dir: Path
    test_result: TestResult
    test_id: int
    study_copy_path: Path | None = None


@dataclass
class ValidationResult:
    """Result from a validation callback.

    Attributes:
        passed: Whether validation passed.
        message: Description of validation result.
        details: Additional validation details.

    """

    passed: bool
    message: str | None = None
    details: dict | None = None


@dataclass
class ObservationPhase:
    """Configuration for a single observation phase.

    Observation phases allow testing target applications with multiple
    time-bounded stages, each with different monitoring parameters.

    Example phases:
    - "load": Initial loading phase (5s) - detect immediate crashes
    - "render": Rendering phase (30s) - detect memory issues during display
    - "interact": Interaction phase (60s) - detect issues during user actions

    Attributes:
        name: Human-readable phase name.
        duration_seconds: Maximum duration for this phase.
        memory_limit_mb: Memory limit for this phase (None = use default).
        validation_callback: Optional callback to validate UI state after phase.
            Signature: (pid: int) -> ValidationResult

    """

    name: str
    duration_seconds: float
    memory_limit_mb: int | None = None
    validation_callback: Callable[[int], ValidationResult] | None = None

    def __post_init__(self) -> None:
        """Validate phase configuration."""
        if self.duration_seconds <= 0:
            raise ValueError(f"Phase '{self.name}' duration must be positive")
        if self.memory_limit_mb is not None and self.memory_limit_mb <= 0:
            raise ValueError(f"Phase '{self.name}' memory limit must be positive")


@dataclass
class PhaseResult:
    """Result from a single observation phase.

    Attributes:
        phase_name: Name of the phase.
        status: Phase status (success, crash, memory_exceeded, validation_failed).
        duration_seconds: Time spent in this phase.
        memory_peak_mb: Peak memory during this phase.
        validation_result: Result from validation callback if any.
        error_message: Error message if phase failed.

    """

    phase_name: str
    status: str
    duration_seconds: float = 0.0
    memory_peak_mb: float = 0.0
    validation_result: ValidationResult | None = None
    error_message: str | None = None


@dataclass
class PhasedTestResult(TestResult):
    """Extended test result with per-phase information.

    Attributes:
        phase_results: Results from each observation phase.
        failed_phase: Name of the phase that failed (if any).

    """

    phase_results: list[PhaseResult] = field(default_factory=list)
    failed_phase: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        data = super().to_dict()
        data["phase_results"] = [
            {
                "phase_name": pr.phase_name,
                "status": pr.status,
                "duration_seconds": pr.duration_seconds,
                "memory_peak_mb": pr.memory_peak_mb,
                "error_message": pr.error_message,
                "validation_result": (
                    {
                        "passed": pr.validation_result.passed,
                        "message": pr.validation_result.message,
                    }
                    if pr.validation_result
                    else None
                ),
            }
            for pr in self.phase_results
        ]
        data["failed_phase"] = self.failed_phase
        return data


# Default observation phases for study-level testing
DEFAULT_OBSERVATION_PHASES = [
    ObservationPhase(name="load", duration_seconds=5.0, memory_limit_mb=None),
    ObservationPhase(name="render", duration_seconds=30.0, memory_limit_mb=2048),
    ObservationPhase(name="interact", duration_seconds=60.0, memory_limit_mb=4096),
]


def _is_psutil_available() -> bool:
    """Check if psutil is available."""
    try:
        import psutil  # noqa: F401

        return True
    except ImportError:
        return False


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
        if not _is_psutil_available():
            logger.warning(
                "psutil not available - memory monitoring disabled",
            )

    def test_study_directory(self, study_dir: Path) -> TestResult:
        """Test target application with a study directory.

        Args:
            study_dir: Path to study directory containing DICOM series.

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

            # Monitor process
            result = self._monitor_process(process, study_dir, start_time)

        except FileNotFoundError as e:
            result = TestResult(
                input_path=study_dir,
                status="error",
                error_message=f"Executable not found: {e}",
                duration_seconds=time.time() - start_time,
            )
            self._stats["error"] += 1

        except PermissionError as e:
            result = TestResult(
                input_path=study_dir,
                status="error",
                error_message=f"Permission denied: {e}",
                duration_seconds=time.time() - start_time,
            )
            self._stats["error"] += 1

        except Exception as e:
            result = TestResult(
                input_path=study_dir,
                status="error",
                error_message=str(e),
                duration_seconds=time.time() - start_time,
            )
            self._stats["error"] += 1
            logger.exception("Error during test", error=str(e))

        finally:
            # Cleanup
            self.kill_target_processes()

        # Update stats
        if result.status in self._stats:
            self._stats[result.status] += 1

        return result

    def _monitor_process(
        self,
        process: subprocess.Popen,
        study_dir: Path,
        start_time: float,
    ) -> TestResult:
        """Monitor a running process for crashes and resource usage.

        Args:
            process: The subprocess to monitor.
            study_dir: Path to the study being tested.
            start_time: When the test started.

        Returns:
            TestResult with monitoring results.

        """
        memory_peak = 0.0
        psutil_proc = None

        # Try to get psutil process handle
        if _is_psutil_available():
            import psutil

            try:
                psutil_proc = psutil.Process(process.pid)
            except psutil.NoSuchProcess:
                return TestResult(
                    input_path=study_dir,
                    status="crash",
                    error_message="Process exited immediately",
                    duration_seconds=time.time() - start_time,
                    process_pid=process.pid,
                )

        elapsed = time.time() - start_time
        while elapsed < self.config.timeout_seconds:
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
                        input_path=study_dir,
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

                        if mem_mb > self.config.memory_limit_mb:
                            process.kill()
                            return TestResult(
                                input_path=study_dir,
                                status="memory_exceeded",
                                memory_peak_mb=memory_peak,
                                duration_seconds=time.time() - start_time,
                                error_message=f"Memory limit exceeded: {mem_mb:.1f} MB",
                                process_pid=process.pid,
                            )
                    except psutil.NoSuchProcess:
                        return TestResult(
                            input_path=study_dir,
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
        except Exception:
            pass

        return TestResult(
            input_path=study_dir,
            status="success",
            memory_peak_mb=memory_peak,
            duration_seconds=time.time() - start_time,
            process_pid=pid,
        )

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
                phase_result = self._run_observation_phase(
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
                    status=final_phase.status,  # type: ignore
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

    def _run_observation_phase(
        self,
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
        if _is_psutil_available():
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

    def save_crash_artifact(
        self,
        result: TestResult,
        study_dir: Path,
        test_id: int,
        mutation_records: list | None = None,
    ) -> CrashArtifact:
        """Save crash artifact for later analysis.

        Args:
            result: The test result that triggered the crash.
            study_dir: Path to the study that caused the crash.
            test_id: Numeric ID of the test.
            mutation_records: Optional list of mutation records.

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
        if not _is_psutil_available():
            return 0

        import psutil

        killed = 0
        pattern = self.config.process_pattern

        for proc in psutil.process_iter(["name", "pid"]):
            try:
                proc_name = proc.info.get("name", "")
                if proc_name and pattern in proc_name.lower():
                    proc.kill()
                    proc.wait(timeout=3)
                    killed += 1
                    logger.debug(
                        "Killed process",
                        name=proc_name,
                        pid=proc.info.get("pid"),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                pass
            except Exception as e:
                logger.warning("Error killing process", error=str(e))

        return killed

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
