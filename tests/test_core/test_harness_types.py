"""Tests for Target Harness Types.

Tests the dataclass definitions and validation logic in
dicom_fuzzer.core.harness.types module.
"""

from datetime import datetime
from pathlib import Path

import pytest

from dicom_fuzzer.core.harness.types import (
    DEFAULT_OBSERVATION_PHASES,
    CrashArtifact,
    ObservationPhase,
    PhasedTestResult,
    PhaseResult,
    TargetConfig,
    TestResult,
    ValidationResult,
)


class TestTargetConfig:
    """Tests for TargetConfig dataclass."""

    def test_init_valid(self) -> None:
        """Test valid initialization."""
        config = TargetConfig(executable=Path("/path/to/app.exe"))
        assert config.executable == Path("/path/to/app.exe")
        assert config.timeout_seconds == 15.0
        assert config.startup_delay_seconds == 3.0
        assert config.memory_limit_mb == 2048
        assert config.process_name_pattern is None

    def test_init_custom_values(self) -> None:
        """Test initialization with custom values."""
        config = TargetConfig(
            executable=Path("/app.exe"),
            timeout_seconds=30.0,
            startup_delay_seconds=5.0,
            memory_limit_mb=4096,
            process_name_pattern="myapp*",
        )
        assert config.timeout_seconds == 30.0
        assert config.startup_delay_seconds == 5.0
        assert config.memory_limit_mb == 4096
        assert config.process_name_pattern == "myapp*"

    def test_invalid_timeout_raises(self) -> None:
        """Test invalid timeout raises ValueError."""
        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            TargetConfig(executable=Path("/app.exe"), timeout_seconds=0)

        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            TargetConfig(executable=Path("/app.exe"), timeout_seconds=-1)

    def test_invalid_startup_delay_raises(self) -> None:
        """Test negative startup delay raises ValueError."""
        with pytest.raises(
            ValueError, match="startup_delay_seconds must be non-negative"
        ):
            TargetConfig(executable=Path("/app.exe"), startup_delay_seconds=-1)

    def test_invalid_memory_limit_raises(self) -> None:
        """Test invalid memory limit raises ValueError."""
        with pytest.raises(ValueError, match="memory_limit_mb must be positive"):
            TargetConfig(executable=Path("/app.exe"), memory_limit_mb=0)

        with pytest.raises(ValueError, match="memory_limit_mb must be positive"):
            TargetConfig(executable=Path("/app.exe"), memory_limit_mb=-100)

    def test_process_pattern_custom(self) -> None:
        """Test custom process pattern is used."""
        config = TargetConfig(
            executable=Path("/path/to/myapp.exe"),
            process_name_pattern="CustomApp*",
        )
        assert config.process_pattern == "customapp*"  # lowercase

    def test_process_pattern_from_executable(self) -> None:
        """Test process pattern derived from executable name."""
        config = TargetConfig(executable=Path("/path/to/DicomViewer.exe"))
        assert config.process_pattern == "dicomviewer"  # lowercase stem


class TestTestResult:
    """Tests for TestResult dataclass."""

    def test_init_defaults(self) -> None:
        """Test initialization with defaults."""
        result = TestResult(
            input_path=Path("/test/file.dcm"),
            status="success",
        )
        assert result.input_path == Path("/test/file.dcm")
        assert result.status == "success"
        assert result.exit_code is None
        assert result.memory_peak_mb == 0.0
        assert result.duration_seconds == 0.0
        assert result.error_message is None
        assert result.process_pid is None

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        ts = datetime(2024, 1, 15, 10, 30, 0)
        input_path = Path("/test/file.dcm")
        result = TestResult(
            input_path=input_path,
            status="crash",
            exit_code=-1,
            memory_peak_mb=512.5,
            duration_seconds=2.5,
            error_message="Segmentation fault",
            timestamp=ts,
            process_pid=12345,
        )
        data = result.to_dict()

        # Use str(Path) for platform-independent comparison
        assert data["input_path"] == str(input_path)
        assert data["status"] == "crash"
        assert data["exit_code"] == -1
        assert data["memory_peak_mb"] == 512.5
        assert data["duration_seconds"] == 2.5
        assert data["error_message"] == "Segmentation fault"
        assert data["timestamp"] == "2024-01-15T10:30:00"
        assert data["process_pid"] == 12345

    def test_from_dict(self) -> None:
        """Test creation from dictionary."""
        data = {
            "input_path": "/test/file.dcm",
            "status": "timeout",
            "exit_code": None,
            "memory_peak_mb": 1024.0,
            "duration_seconds": 30.0,
            "error_message": "Process timed out",
            "timestamp": "2024-01-15T10:30:00",
            "process_pid": 54321,
        }
        result = TestResult.from_dict(data)

        assert result.input_path == Path("/test/file.dcm")
        assert result.status == "timeout"
        assert result.memory_peak_mb == 1024.0
        assert result.error_message == "Process timed out"
        assert result.timestamp == datetime(2024, 1, 15, 10, 30, 0)
        assert result.process_pid == 54321

    def test_is_failure_crash(self) -> None:
        """Test is_failure returns True for crash."""
        result = TestResult(input_path=Path("/f.dcm"), status="crash")
        assert result.is_failure() is True

    def test_is_failure_memory_exceeded(self) -> None:
        """Test is_failure returns True for memory_exceeded."""
        result = TestResult(input_path=Path("/f.dcm"), status="memory_exceeded")
        assert result.is_failure() is True

    def test_is_failure_error(self) -> None:
        """Test is_failure returns True for error."""
        result = TestResult(input_path=Path("/f.dcm"), status="error")
        assert result.is_failure() is True

    def test_is_failure_success(self) -> None:
        """Test is_failure returns False for success."""
        result = TestResult(input_path=Path("/f.dcm"), status="success")
        assert result.is_failure() is False

    def test_is_failure_timeout(self) -> None:
        """Test is_failure returns False for timeout."""
        result = TestResult(input_path=Path("/f.dcm"), status="timeout")
        assert result.is_failure() is False


class TestCrashArtifact:
    """Tests for CrashArtifact dataclass."""

    def test_init(self) -> None:
        """Test CrashArtifact initialization."""
        test_result = TestResult(input_path=Path("/f.dcm"), status="crash")
        artifact = CrashArtifact(
            crash_dir=Path("/crashes/001"),
            test_result=test_result,
            test_id=42,
            study_copy_path=Path("/crashes/001/study"),
        )
        assert artifact.crash_dir == Path("/crashes/001")
        assert artifact.test_result.status == "crash"
        assert artifact.test_id == 42
        assert artifact.study_copy_path == Path("/crashes/001/study")


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_init_passed(self) -> None:
        """Test ValidationResult for passed validation."""
        result = ValidationResult(
            passed=True,
            message="All checks passed",
            details={"checks": 5},
        )
        assert result.passed is True
        assert result.message == "All checks passed"
        assert result.details == {"checks": 5}

    def test_init_failed(self) -> None:
        """Test ValidationResult for failed validation."""
        result = ValidationResult(
            passed=False,
            message="Error dialog detected",
        )
        assert result.passed is False
        assert result.message == "Error dialog detected"
        assert result.details is None


class TestObservationPhase:
    """Tests for ObservationPhase dataclass."""

    def test_init_valid(self) -> None:
        """Test valid ObservationPhase initialization."""
        phase = ObservationPhase(
            name="load",
            duration_seconds=5.0,
            memory_limit_mb=2048,
        )
        assert phase.name == "load"
        assert phase.duration_seconds == 5.0
        assert phase.memory_limit_mb == 2048
        assert phase.validation_callback is None

    def test_init_with_callback(self) -> None:
        """Test ObservationPhase with validation callback."""

        def my_callback(pid: int) -> ValidationResult:
            return ValidationResult(passed=True)

        phase = ObservationPhase(
            name="render",
            duration_seconds=30.0,
            validation_callback=my_callback,
        )
        assert phase.validation_callback is not None
        result = phase.validation_callback(123)
        assert result.passed is True

    def test_invalid_duration_raises(self) -> None:
        """Test invalid duration raises ValueError."""
        with pytest.raises(ValueError, match="duration must be positive"):
            ObservationPhase(name="test", duration_seconds=0)

        with pytest.raises(ValueError, match="duration must be positive"):
            ObservationPhase(name="test", duration_seconds=-1)

    def test_invalid_memory_limit_raises(self) -> None:
        """Test invalid memory limit raises ValueError."""
        with pytest.raises(ValueError, match="memory limit must be positive"):
            ObservationPhase(name="test", duration_seconds=5.0, memory_limit_mb=0)

        with pytest.raises(ValueError, match="memory limit must be positive"):
            ObservationPhase(name="test", duration_seconds=5.0, memory_limit_mb=-100)


class TestPhaseResult:
    """Tests for PhaseResult dataclass."""

    def test_init(self) -> None:
        """Test PhaseResult initialization."""
        result = PhaseResult(
            phase_name="load",
            status="success",
            duration_seconds=4.5,
            memory_peak_mb=512.0,
        )
        assert result.phase_name == "load"
        assert result.status == "success"
        assert result.duration_seconds == 4.5
        assert result.memory_peak_mb == 512.0
        assert result.validation_result is None
        assert result.error_message is None


class TestPhasedTestResult:
    """Tests for PhasedTestResult dataclass."""

    def test_init_with_phases(self) -> None:
        """Test PhasedTestResult with phase results."""
        phase1 = PhaseResult(phase_name="load", status="success", duration_seconds=5.0)
        phase2 = PhaseResult(
            phase_name="render",
            status="crash",
            error_message="Segfault",
        )

        result = PhasedTestResult(
            input_path=Path("/test.dcm"),
            status="crash",
            phase_results=[phase1, phase2],
            failed_phase="render",
        )
        assert len(result.phase_results) == 2
        assert result.failed_phase == "render"

    def test_to_dict(self) -> None:
        """Test PhasedTestResult to_dict includes phases."""
        validation = ValidationResult(passed=True, message="OK")
        phase = PhaseResult(
            phase_name="load",
            status="success",
            duration_seconds=5.0,
            memory_peak_mb=256.0,
            validation_result=validation,
        )

        result = PhasedTestResult(
            input_path=Path("/test.dcm"),
            status="success",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            phase_results=[phase],
        )
        data = result.to_dict()

        assert "phase_results" in data
        assert len(data["phase_results"]) == 1
        assert data["phase_results"][0]["phase_name"] == "load"
        assert data["phase_results"][0]["validation_result"]["passed"] is True
        assert data["failed_phase"] is None


class TestDefaultObservationPhases:
    """Tests for DEFAULT_OBSERVATION_PHASES constant."""

    def test_default_phases_exist(self) -> None:
        """Test default phases are defined."""
        assert len(DEFAULT_OBSERVATION_PHASES) == 3

    def test_default_phase_names(self) -> None:
        """Test default phase names."""
        names = [p.name for p in DEFAULT_OBSERVATION_PHASES]
        assert names == ["load", "render", "interact"]

    def test_default_phase_durations(self) -> None:
        """Test default phase durations."""
        durations = [p.duration_seconds for p in DEFAULT_OBSERVATION_PHASES]
        assert durations == [5.0, 30.0, 60.0]

    def test_default_phase_memory_limits(self) -> None:
        """Test default phase memory limits."""
        limits = [p.memory_limit_mb for p in DEFAULT_OBSERVATION_PHASES]
        assert limits == [None, 2048, 4096]
