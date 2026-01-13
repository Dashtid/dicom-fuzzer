"""Target Harness Types.

Dataclasses and type definitions for target application testing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

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
        if isinstance(self.executable, str):  # type: ignore[unreachable]
            self.executable = Path(self.executable)  # type: ignore[unreachable]

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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["input_path"] = str(self.input_path)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestResult:
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
    details: dict[str, Any] | None = None


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

    def to_dict(self) -> dict[str, Any]:
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


__all__ = [
    "TestStatus",
    "TargetConfig",
    "TestResult",
    "CrashArtifact",
    "ValidationResult",
    "ObservationPhase",
    "PhaseResult",
    "PhasedTestResult",
    "DEFAULT_OBSERVATION_PHASES",
]
