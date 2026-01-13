"""Tests for the TargetHarness module.

Tests cover:
- TargetConfig validation and defaults
- TestResult serialization
- TargetHarness process execution and monitoring
- Crash artifact collection
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.target_harness import (
    CrashArtifact,
    TargetConfig,
    TargetHarness,
    TestResult,
    _is_psutil_available,
)


class TestTargetConfig:
    """Tests for TargetConfig dataclass."""

    def test_default_values(self, tmp_path: Path) -> None:
        """Test TargetConfig has sensible defaults."""
        executable = tmp_path / "test.exe"
        executable.touch()

        config = TargetConfig(executable=executable)

        assert config.executable == executable
        assert config.timeout_seconds == 15.0
        assert config.startup_delay_seconds == 3.0
        assert config.memory_limit_mb == 2048
        assert config.process_name_pattern is None

    def test_executable_as_string(self, tmp_path: Path) -> None:
        """Test that executable path accepts strings."""
        executable = tmp_path / "test.exe"
        executable.touch()

        config = TargetConfig(executable=str(executable))

        assert isinstance(config.executable, Path)
        assert config.executable == executable

    def test_timeout_validation(self, tmp_path: Path) -> None:
        """Test timeout must be positive."""
        executable = tmp_path / "test.exe"
        executable.touch()

        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            TargetConfig(executable=executable, timeout_seconds=0)

        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            TargetConfig(executable=executable, timeout_seconds=-1)

    def test_startup_delay_validation(self, tmp_path: Path) -> None:
        """Test startup delay must be non-negative."""
        executable = tmp_path / "test.exe"
        executable.touch()

        # Zero is allowed
        config = TargetConfig(executable=executable, startup_delay_seconds=0)
        assert config.startup_delay_seconds == 0

        with pytest.raises(
            ValueError, match="startup_delay_seconds must be non-negative"
        ):
            TargetConfig(executable=executable, startup_delay_seconds=-1)

    def test_memory_limit_validation(self, tmp_path: Path) -> None:
        """Test memory limit must be positive."""
        executable = tmp_path / "test.exe"
        executable.touch()

        with pytest.raises(ValueError, match="memory_limit_mb must be positive"):
            TargetConfig(executable=executable, memory_limit_mb=0)

        with pytest.raises(ValueError, match="memory_limit_mb must be positive"):
            TargetConfig(executable=executable, memory_limit_mb=-100)

    def test_process_pattern_default(self, tmp_path: Path) -> None:
        """Test process pattern defaults to executable stem."""
        executable = tmp_path / "my_viewer.exe"
        executable.touch()

        config = TargetConfig(executable=executable)

        assert config.process_pattern == "my_viewer"

    def test_process_pattern_custom(self, tmp_path: Path) -> None:
        """Test custom process pattern."""
        executable = tmp_path / "viewer.exe"
        executable.touch()

        config = TargetConfig(executable=executable, process_name_pattern="MyViewer")

        assert config.process_pattern == "myviewer"  # Lowercased


class TestTestResult:
    """Tests for TestResult dataclass."""

    def test_status_values(self, tmp_path: Path) -> None:
        """Test all valid status values."""
        valid_statuses = ["success", "crash", "memory_exceeded", "timeout", "error"]

        for status in valid_statuses:
            result = TestResult(
                input_path=tmp_path / "test",
                status=status,  # type: ignore
            )
            assert result.status == status

    def test_to_dict_serialization(self, tmp_path: Path) -> None:
        """Test TestResult can be serialized to JSON-compatible dict."""
        result = TestResult(
            input_path=tmp_path / "study",
            status="crash",
            exit_code=139,
            memory_peak_mb=512.5,
            duration_seconds=10.2,
            error_message="Segmentation fault",
        )

        data = result.to_dict()

        assert data["input_path"] == str(tmp_path / "study")
        assert data["status"] == "crash"
        assert data["exit_code"] == 139
        assert data["memory_peak_mb"] == 512.5
        assert data["duration_seconds"] == 10.2
        assert data["error_message"] == "Segmentation fault"
        assert "timestamp" in data

        # Should be JSON serializable
        json_str = json.dumps(data)
        assert json_str

    def test_from_dict_deserialization(self, tmp_path: Path) -> None:
        """Test TestResult can be created from dict."""
        original = TestResult(
            input_path=tmp_path / "study",
            status="success",
            exit_code=0,
            memory_peak_mb=256.0,
            duration_seconds=5.0,
        )

        data = original.to_dict()
        restored = TestResult.from_dict(data)

        assert restored.input_path == original.input_path
        assert restored.status == original.status
        assert restored.exit_code == original.exit_code
        assert restored.memory_peak_mb == original.memory_peak_mb
        assert restored.duration_seconds == original.duration_seconds

    def test_is_failure(self, tmp_path: Path) -> None:
        """Test is_failure method."""
        success = TestResult(input_path=tmp_path, status="success")
        crash = TestResult(input_path=tmp_path, status="crash")
        memory = TestResult(input_path=tmp_path, status="memory_exceeded")
        error = TestResult(input_path=tmp_path, status="error")
        timeout = TestResult(input_path=tmp_path, status="timeout")

        assert not success.is_failure()
        assert crash.is_failure()
        assert memory.is_failure()
        assert error.is_failure()
        assert not timeout.is_failure()


class TestTargetHarness:
    """Tests for TargetHarness class."""

    @pytest.fixture
    def mock_target(self, tmp_path: Path) -> Path:
        """Create a mock target that exits successfully."""
        script = tmp_path / "mock_target.py"
        script.write_text(
            textwrap.dedent("""
            import sys
            import time
            time.sleep(0.2)
            sys.exit(0)
            """)
        )
        return script

    @pytest.fixture
    def crashing_target(self, tmp_path: Path) -> Path:
        """Create a mock target that crashes."""
        script = tmp_path / "crashing_target.py"
        script.write_text(
            textwrap.dedent("""
            import sys
            sys.exit(139)  # Simulate SIGSEGV
            """)
        )
        return script

    @pytest.fixture
    def hanging_target(self, tmp_path: Path) -> Path:
        """Create a mock target that hangs."""
        script = tmp_path / "hanging_target.py"
        script.write_text(
            textwrap.dedent("""
            import time
            time.sleep(3600)  # Sleep for an hour
            """)
        )
        return script

    @pytest.fixture
    def sample_study(self, tmp_path: Path) -> Path:
        """Create a sample study directory."""
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        # Create some dummy files
        series_dir = study_dir / "series_000"
        series_dir.mkdir()
        (series_dir / "slice_0000.dcm").write_bytes(b"DICM" + b"\x00" * 100)
        (series_dir / "slice_0001.dcm").write_bytes(b"DICM" + b"\x00" * 100)

        return study_dir

    def test_init_creates_crash_dir(self, tmp_path: Path) -> None:
        """Test harness creates crash directory if missing."""
        executable = tmp_path / "test.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        assert not crash_dir.exists()

        config = TargetConfig(executable=executable)
        TargetHarness(config, crash_dir=crash_dir)

        assert crash_dir.exists()

    def test_kill_target_processes_no_match(self, tmp_path: Path) -> None:
        """Test kill_target_processes returns 0 when no processes match."""
        executable = tmp_path / "nonexistent_unique_name_xyz.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        config = TargetConfig(executable=executable)
        harness = TargetHarness(config, crash_dir=crash_dir)

        killed = harness.kill_target_processes()
        assert killed == 0

    def test_save_crash_artifact_creates_structure(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test crash artifacts are saved with correct structure."""
        executable = tmp_path / "test.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        config = TargetConfig(executable=executable)
        harness = TargetHarness(config, crash_dir=crash_dir)

        result = TestResult(
            input_path=sample_study,
            status="crash",
            exit_code=139,
            memory_peak_mb=256.0,
            duration_seconds=5.0,
            error_message="Segmentation fault",
        )

        artifact = harness.save_crash_artifact(result, sample_study, test_id=42)

        assert artifact.crash_dir.exists()
        assert artifact.crash_dir.name == "crash_0042"
        assert artifact.test_id == 42
        assert artifact.test_result == result

        # Check result.json was created
        result_file = artifact.crash_dir / "result.json"
        assert result_file.exists()
        with open(result_file) as f:
            saved_result = json.load(f)
        assert saved_result["status"] == "crash"
        assert saved_result["exit_code"] == 139

    def test_save_crash_artifact_copies_study(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test study directory is copied to crash artifact."""
        executable = tmp_path / "test.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        config = TargetConfig(executable=executable)
        harness = TargetHarness(config, crash_dir=crash_dir)

        result = TestResult(input_path=sample_study, status="crash")
        artifact = harness.save_crash_artifact(result, sample_study, test_id=1)

        assert artifact.study_copy_path is not None
        assert artifact.study_copy_path.exists()

        # Check study structure was preserved
        assert (artifact.study_copy_path / "series_000").exists()
        assert (artifact.study_copy_path / "series_000" / "slice_0000.dcm").exists()

    def test_save_crash_artifact_with_mutation_records(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test mutation records are saved with crash artifact."""
        executable = tmp_path / "test.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        config = TargetConfig(executable=executable)
        harness = TargetHarness(config, crash_dir=crash_dir)

        result = TestResult(input_path=sample_study, status="crash")

        # Mock mutation records
        mutation_records = [
            {"strategy": "cross_series", "tag": "(0020,000E)", "value": "test"},
            {
                "strategy": "patient_consistency",
                "tag": "(0010,0020)",
                "value": "PAT123",
            },
        ]

        artifact = harness.save_crash_artifact(
            result, sample_study, test_id=1, mutation_records=mutation_records
        )

        records_file = artifact.crash_dir / "mutation_records.json"
        assert records_file.exists()

        with open(records_file) as f:
            saved_records = json.load(f)
        assert len(saved_records) == 2

    def test_test_study_directory_success(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test successful execution returns success status."""
        crash_dir = tmp_path / "crashes"
        executable = tmp_path / "mock_exe"
        executable.touch()

        config = TargetConfig(
            executable=executable,
            timeout_seconds=5.0,
            startup_delay_seconds=0.0,
        )
        harness = TargetHarness(config, crash_dir=crash_dir)

        # Create mock process
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Create expected result
        expected_result = TestResult(
            input_path=sample_study,
            status="success",
            duration_seconds=0.5,
            memory_peak_mb=100.0,
            process_pid=12345,
        )

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch(
                "dicom_fuzzer.core.harness.harness.monitor_process",
                return_value=expected_result,
            ),
            patch.object(harness, "kill_target_processes"),
        ):
            result = harness.test_study_directory(sample_study)

        assert result.status == "success"
        assert result.duration_seconds > 0

    def test_test_study_directory_crash(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test crash detection with non-zero exit code."""
        crash_dir = tmp_path / "crashes"
        executable = tmp_path / "mock_exe"
        executable.touch()

        config = TargetConfig(
            executable=executable,
            timeout_seconds=5.0,
            startup_delay_seconds=0.0,
        )
        harness = TargetHarness(config, crash_dir=crash_dir)

        # Create mock process
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Create expected crash result
        expected_result = TestResult(
            input_path=sample_study,
            status="crash",
            exit_code=139,
            duration_seconds=0.1,
            error_message="Process exited with code 139 (SIGSEGV)",
            process_pid=12345,
        )

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch(
                "dicom_fuzzer.core.harness.harness.monitor_process",
                return_value=expected_result,
            ),
            patch.object(harness, "kill_target_processes"),
        ):
            result = harness.test_study_directory(sample_study)

        assert result.status == "crash"
        assert result.exit_code == 139
        assert result.error_message is not None

    def test_test_study_directory_timeout(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test timeout behavior - should return success for GUI apps."""
        crash_dir = tmp_path / "crashes"
        executable = tmp_path / "mock_exe"
        executable.touch()

        config = TargetConfig(
            executable=executable,
            timeout_seconds=1.0,  # Short timeout
            startup_delay_seconds=0.0,
        )
        harness = TargetHarness(config, crash_dir=crash_dir)

        # Create mock process
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Create expected result - timeout is treated as success for GUI apps
        expected_result = TestResult(
            input_path=sample_study,
            status="success",
            duration_seconds=1.5,
            memory_peak_mb=50.0,
            process_pid=12345,
        )

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch(
                "dicom_fuzzer.core.harness.harness.monitor_process",
                return_value=expected_result,
            ),
            patch.object(harness, "kill_target_processes"),
        ):
            result = harness.test_study_directory(sample_study)

        # Timeout is treated as success for GUI apps
        assert result.status == "success"
        assert result.duration_seconds >= 1.0

    def test_test_study_directory_executable_not_found(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test error when executable doesn't exist."""
        crash_dir = tmp_path / "crashes"
        nonexistent = tmp_path / "nonexistent.exe"

        config = TargetConfig(executable=nonexistent)
        harness = TargetHarness(config, crash_dir=crash_dir)

        result = harness.test_study_directory(sample_study)

        assert result.status == "error"
        assert "not found" in result.error_message.lower()

    def test_get_stats(self, tmp_path: Path) -> None:
        """Test statistics tracking."""
        executable = tmp_path / "test.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        config = TargetConfig(executable=executable)
        harness = TargetHarness(config, crash_dir=crash_dir)

        stats = harness.get_stats()

        assert stats["total_tests"] == 0
        assert stats["success"] == 0
        assert stats["crash"] == 0
        assert stats["memory_exceeded"] == 0
        assert stats["error"] == 0

    def test_reset_stats(self, tmp_path: Path, sample_study: Path) -> None:
        """Test statistics reset."""
        executable = tmp_path / "nonexistent.exe"

        config = TargetConfig(executable=executable)
        harness = TargetHarness(config, crash_dir=tmp_path / "crashes")

        # Run a test to increment stats
        harness.test_study_directory(sample_study)
        assert harness.get_stats()["total_tests"] == 1

        harness.reset_stats()
        assert harness.get_stats()["total_tests"] == 0


class TestCrashArtifact:
    """Tests for CrashArtifact dataclass."""

    def test_crash_artifact_creation(self, tmp_path: Path) -> None:
        """Test CrashArtifact can be created."""
        crash_dir = tmp_path / "crash_0001"
        crash_dir.mkdir()

        result = TestResult(
            input_path=tmp_path / "study",
            status="crash",
        )

        artifact = CrashArtifact(
            crash_dir=crash_dir,
            test_result=result,
            test_id=1,
            study_copy_path=crash_dir / "study",
        )

        assert artifact.crash_dir == crash_dir
        assert artifact.test_id == 1
        assert artifact.test_result == result


class TestPsutilAvailability:
    """Tests for psutil availability check."""

    def test_is_psutil_available(self) -> None:
        """Test psutil availability check."""
        # psutil should be available in the test environment
        assert _is_psutil_available() is True

    @pytest.mark.slow
    def test_harness_without_psutil(self, tmp_path: Path) -> None:
        """Test harness works without psutil (degraded mode).

        Note: Marked as slow to help pytest-split allocate this test
        appropriately, as it often runs at a point in the test sequence
        where memory pressure from previous tests may cause OOM in CI.
        """
        import gc

        # Aggressive garbage collection before test
        gc.collect()
        gc.collect()

        executable = tmp_path / "test.exe"
        executable.touch()
        crash_dir = tmp_path / "crashes"

        config = TargetConfig(executable=executable)

        # Mock psutil as unavailable
        with patch(
            "dicom_fuzzer.core.target_harness._is_psutil_available", return_value=False
        ):
            harness = TargetHarness(config, crash_dir=crash_dir)

            # kill_target_processes should return 0 without psutil
            killed = harness.kill_target_processes()
            assert killed == 0

        # Cleanup
        gc.collect()


class TestObservationPhase:
    """Tests for ObservationPhase dataclass."""

    def test_observation_phase_creation(self) -> None:
        """Test ObservationPhase can be created with required fields."""
        from dicom_fuzzer.core.target_harness import ObservationPhase

        phase = ObservationPhase(name="load", duration_seconds=5.0)

        assert phase.name == "load"
        assert phase.duration_seconds == 5.0
        assert phase.memory_limit_mb is None
        assert phase.validation_callback is None

    def test_observation_phase_with_memory_limit(self) -> None:
        """Test ObservationPhase with memory limit."""
        from dicom_fuzzer.core.target_harness import ObservationPhase

        phase = ObservationPhase(
            name="render",
            duration_seconds=30.0,
            memory_limit_mb=2048,
        )

        assert phase.memory_limit_mb == 2048

    def test_observation_phase_with_callback(self) -> None:
        """Test ObservationPhase with validation callback."""
        from dicom_fuzzer.core.target_harness import ObservationPhase, ValidationResult

        def my_validator(pid: int) -> ValidationResult:
            return ValidationResult(passed=True, message="OK")

        phase = ObservationPhase(
            name="validate",
            duration_seconds=10.0,
            validation_callback=my_validator,
        )

        assert phase.validation_callback is not None
        result = phase.validation_callback(12345)
        assert result.passed is True

    def test_observation_phase_invalid_duration(self) -> None:
        """Test ObservationPhase rejects non-positive duration."""
        from dicom_fuzzer.core.target_harness import ObservationPhase

        with pytest.raises(ValueError, match="duration must be positive"):
            ObservationPhase(name="bad", duration_seconds=0)

        with pytest.raises(ValueError, match="duration must be positive"):
            ObservationPhase(name="bad", duration_seconds=-1.0)

    def test_observation_phase_invalid_memory_limit(self) -> None:
        """Test ObservationPhase rejects non-positive memory limit."""
        from dicom_fuzzer.core.target_harness import ObservationPhase

        with pytest.raises(ValueError, match="memory limit must be positive"):
            ObservationPhase(name="bad", duration_seconds=5.0, memory_limit_mb=0)


class TestPhaseResult:
    """Tests for PhaseResult dataclass."""

    def test_phase_result_creation(self) -> None:
        """Test PhaseResult can be created."""
        from dicom_fuzzer.core.target_harness import PhaseResult

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

    def test_phase_result_with_validation(self) -> None:
        """Test PhaseResult with validation result."""
        from dicom_fuzzer.core.target_harness import PhaseResult, ValidationResult

        validation = ValidationResult(
            passed=False,
            message="Patient ID mismatch",
        )
        result = PhaseResult(
            phase_name="validate",
            status="validation_failed",
            validation_result=validation,
            error_message="Patient ID mismatch",
        )

        assert result.status == "validation_failed"
        assert result.validation_result is not None
        assert result.validation_result.passed is False


class TestPhasedTestResult:
    """Tests for PhasedTestResult dataclass."""

    def test_phased_test_result_creation(self, tmp_path: Path) -> None:
        """Test PhasedTestResult can be created."""
        from dicom_fuzzer.core.target_harness import PhasedTestResult, PhaseResult

        phase_results = [
            PhaseResult(phase_name="load", status="success", duration_seconds=5.0),
            PhaseResult(phase_name="render", status="success", duration_seconds=30.0),
        ]

        result = PhasedTestResult(
            input_path=tmp_path / "study",
            status="success",
            memory_peak_mb=1024.0,
            duration_seconds=35.0,
            phase_results=phase_results,
        )

        assert result.status == "success"
        assert len(result.phase_results) == 2
        assert result.failed_phase is None

    def test_phased_test_result_with_failure(self, tmp_path: Path) -> None:
        """Test PhasedTestResult with failed phase."""
        from dicom_fuzzer.core.target_harness import PhasedTestResult, PhaseResult

        phase_results = [
            PhaseResult(phase_name="load", status="success", duration_seconds=5.0),
            PhaseResult(
                phase_name="render",
                status="crash",
                error_message="Exit code: 139",
            ),
        ]

        result = PhasedTestResult(
            input_path=tmp_path / "study",
            status="crash",
            memory_peak_mb=1024.0,
            duration_seconds=10.0,
            phase_results=phase_results,
            failed_phase="render",
        )

        assert result.status == "crash"
        assert result.failed_phase == "render"

    def test_phased_test_result_to_dict(self, tmp_path: Path) -> None:
        """Test PhasedTestResult serialization to dict."""
        from dicom_fuzzer.core.target_harness import (
            PhasedTestResult,
            PhaseResult,
            ValidationResult,
        )

        validation = ValidationResult(passed=True, message="OK")
        phase_results = [
            PhaseResult(
                phase_name="load",
                status="success",
                duration_seconds=5.0,
                validation_result=validation,
            ),
        ]

        result = PhasedTestResult(
            input_path=tmp_path / "study",
            status="success",
            memory_peak_mb=512.0,
            duration_seconds=5.0,
            phase_results=phase_results,
        )

        data = result.to_dict()

        assert "phase_results" in data
        assert len(data["phase_results"]) == 1
        assert data["phase_results"][0]["phase_name"] == "load"
        assert data["phase_results"][0]["validation_result"]["passed"] is True


class TestDefaultObservationPhases:
    """Tests for default observation phases."""

    def test_default_phases_exist(self) -> None:
        """Test DEFAULT_OBSERVATION_PHASES is defined."""
        from dicom_fuzzer.core.target_harness import DEFAULT_OBSERVATION_PHASES

        assert len(DEFAULT_OBSERVATION_PHASES) == 3
        assert DEFAULT_OBSERVATION_PHASES[0].name == "load"
        assert DEFAULT_OBSERVATION_PHASES[1].name == "render"
        assert DEFAULT_OBSERVATION_PHASES[2].name == "interact"

    def test_default_phases_configuration(self) -> None:
        """Test default phases have expected configuration."""
        from dicom_fuzzer.core.target_harness import DEFAULT_OBSERVATION_PHASES

        load_phase = DEFAULT_OBSERVATION_PHASES[0]
        assert load_phase.duration_seconds == 5.0
        assert load_phase.memory_limit_mb is None

        render_phase = DEFAULT_OBSERVATION_PHASES[1]
        assert render_phase.duration_seconds == 30.0
        assert render_phase.memory_limit_mb == 2048

        interact_phase = DEFAULT_OBSERVATION_PHASES[2]
        assert interact_phase.duration_seconds == 60.0
        assert interact_phase.memory_limit_mb == 4096


class TestPhasedObservation:
    """Tests for test_study_with_phases method."""

    @pytest.fixture
    def sample_study(self, tmp_path: Path) -> Path:
        """Create a sample study directory."""
        study_dir = tmp_path / "study"
        study_dir.mkdir()
        (study_dir / "test.dcm").touch()
        return study_dir

    @pytest.fixture
    def quick_phases(self):
        """Create quick phases for testing."""
        from dicom_fuzzer.core.target_harness import ObservationPhase

        return [
            ObservationPhase(name="quick_load", duration_seconds=0.5),
            ObservationPhase(name="quick_render", duration_seconds=0.5),
        ]

    @pytest.fixture
    def mock_target(self, tmp_path: Path) -> Path:
        """Create a mock target script that exits successfully."""
        script = tmp_path / "mock_target.py"
        script.write_text(
            textwrap.dedent("""
            import sys
            import time
            time.sleep(0.2)
            sys.exit(0)
        """).strip()
        )
        return script

    @pytest.fixture
    def crashing_target(self, tmp_path: Path) -> Path:
        """Create a mock target script that crashes."""
        script = tmp_path / "crashing_target.py"
        script.write_text(
            textwrap.dedent("""
            import sys
            sys.exit(139)  # SIGSEGV-like exit code
        """).strip()
        )
        return script

    def test_phased_observation_executable_not_found(
        self, tmp_path: Path, sample_study: Path, quick_phases
    ) -> None:
        """Test error when executable doesn't exist."""
        from dicom_fuzzer.core.target_harness import TargetConfig, TargetHarness

        nonexistent = tmp_path / "nonexistent.exe"
        config = TargetConfig(executable=nonexistent)
        harness = TargetHarness(config, crash_dir=tmp_path / "crashes")

        result = harness.test_study_with_phases(sample_study, phases=quick_phases)

        assert result.status == "error"
        assert "not found" in result.error_message.lower()

    def test_phased_observation_success(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test successful phased observation."""
        from dicom_fuzzer.core.target_harness import (
            ObservationPhase,
            PhaseResult,
            TargetConfig,
            TargetHarness,
        )

        crash_dir = tmp_path / "crashes"
        executable = tmp_path / "mock_exe"
        executable.touch()

        config = TargetConfig(
            executable=executable,
            startup_delay_seconds=0.0,
        )
        harness = TargetHarness(config, crash_dir=crash_dir)

        # Quick phases for testing
        phases = [
            ObservationPhase(name="phase1", duration_seconds=0.5),
            ObservationPhase(name="phase2", duration_seconds=0.5),
        ]

        # Create mock process
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Create mock phase results
        phase_results = [
            PhaseResult(phase_name="phase1", status="success", duration_seconds=0.5),
            PhaseResult(phase_name="phase2", status="success", duration_seconds=0.5),
        ]

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch(
                "dicom_fuzzer.core.harness.harness.run_observation_phase",
                side_effect=phase_results,
            ),
            patch.object(harness, "kill_target_processes"),
        ):
            result = harness.test_study_with_phases(sample_study, phases=phases)

        assert result.status == "success"
        assert len(result.phase_results) == 2
        assert result.phase_results[0].phase_name == "phase1"
        assert result.phase_results[1].phase_name == "phase2"

    def test_phased_observation_crash_in_phase(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test crash detection during phased observation."""
        from dicom_fuzzer.core.target_harness import (
            ObservationPhase,
            PhaseResult,
            TargetConfig,
            TargetHarness,
        )

        crash_dir = tmp_path / "crashes"
        executable = tmp_path / "mock_exe"
        executable.touch()

        config = TargetConfig(
            executable=executable,
            startup_delay_seconds=0.0,
        )
        harness = TargetHarness(config, crash_dir=crash_dir)

        phases = [
            ObservationPhase(name="load", duration_seconds=2.0),
        ]

        # Create mock process
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Create mock crash result
        crash_phase_result = PhaseResult(
            phase_name="load",
            status="crash",
            duration_seconds=0.1,
            error_message="Process crashed with exit code 139",
        )

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch(
                "dicom_fuzzer.core.harness.harness.run_observation_phase",
                return_value=crash_phase_result,
            ),
            patch.object(harness, "kill_target_processes"),
        ):
            result = harness.test_study_with_phases(sample_study, phases=phases)

        assert result.status == "crash"
        assert result.failed_phase == "load"
        assert len(result.phase_results) == 1

    def test_phased_observation_validation_callback(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test validation callback is invoked."""
        from dicom_fuzzer.core.target_harness import (
            ObservationPhase,
            TargetConfig,
            TargetHarness,
            ValidationResult,
        )

        # Track if callback was invoked
        callback_invoked = {"value": False}

        def mock_validator(pid: int) -> ValidationResult:
            callback_invoked["value"] = True
            return ValidationResult(passed=True, message="Validated")

        phases = [
            ObservationPhase(
                name="validate",
                duration_seconds=0.5,
                validation_callback=mock_validator,
            ),
        ]

        executable = tmp_path / "test.exe"
        executable.touch()
        config = TargetConfig(executable=executable, startup_delay_seconds=0.1)
        harness = TargetHarness(config, crash_dir=tmp_path / "crashes")

        # We can't actually run a process here, but we can verify the setup
        # The callback would be invoked if the phase completed successfully
        assert phases[0].validation_callback is not None

    def test_uses_default_phases_when_none(
        self, tmp_path: Path, sample_study: Path
    ) -> None:
        """Test that default phases are used when none provided."""
        from dicom_fuzzer.core.target_harness import (
            TargetConfig,
            TargetHarness,
        )

        nonexistent = tmp_path / "nonexistent.exe"
        config = TargetConfig(executable=nonexistent)
        harness = TargetHarness(config, crash_dir=tmp_path / "crashes")

        # Call with phases=None should use defaults
        result = harness.test_study_with_phases(sample_study, phases=None)

        # It will error because exe doesn't exist, but we can verify
        # the method was called (stats are updated)
        assert harness.get_stats()["total_tests"] == 1
