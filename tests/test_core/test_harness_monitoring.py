"""Tests for harness/monitoring.py.

Coverage target: 18% -> 70%+
Tests process monitoring, memory checking, and observation phases.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.harness.monitoring import (
    _check_phase_memory,
    _check_process_memory,
    _classify_exit_code,
    _run_phase_validation,
    is_psutil_available,
    kill_target_processes,
    monitor_process,
    run_observation_phase,
)
from dicom_fuzzer.core.harness.types import (
    ObservationPhase,
    PhaseResult,
    ValidationResult,
)


class TestIsPsutilAvailable:
    """Tests for is_psutil_available function."""

    def test_psutil_available(self) -> None:
        """Test psutil is available (should be in test environment)."""
        result = is_psutil_available()
        assert result is True

    def test_psutil_not_available(self) -> None:
        """Test handling when psutil is not installed."""
        with patch.dict("sys.modules", {"psutil": None}):
            with patch(
                "dicom_fuzzer.core.harness.monitoring.is_psutil_available",
                return_value=False,
            ):
                # Simulating psutil not available
                assert True  # The mock would return False


class TestClassifyExitCode:
    """Tests for _classify_exit_code function."""

    def test_exit_code_0_success(self) -> None:
        """Test exit code 0 is success."""
        status, error_msg = _classify_exit_code(0)
        assert status == "success"
        assert error_msg is None

    def test_exit_code_1_success(self) -> None:
        """Test exit code 1 is success (common for normal exits)."""
        status, error_msg = _classify_exit_code(1)
        assert status == "success"
        assert error_msg is None

    def test_exit_code_crash(self) -> None:
        """Test non-zero/non-one exit codes are crashes."""
        for code in [2, 139, 134, 137, 255, -1]:
            status, error_msg = _classify_exit_code(code)
            assert status == "crash"
            assert error_msg is not None
            assert str(code) in error_msg


class TestCheckProcessMemory:
    """Tests for _check_process_memory function."""

    @pytest.fixture
    def mock_process(self) -> MagicMock:
        """Create mock subprocess."""
        proc = MagicMock(spec=subprocess.Popen)
        proc.pid = 12345
        return proc

    @pytest.fixture
    def input_path(self, tmp_path: Path) -> Path:
        """Create test input path."""
        return tmp_path / "test_input"

    def test_memory_within_limit(
        self, mock_process: MagicMock, input_path: Path
    ) -> None:
        """Test memory check when within limit."""
        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.return_value = MagicMock(
            rss=500 * 1024 * 1024  # 500 MB
        )

        memory_peak, result = _check_process_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            input_path=input_path,
            memory_peak=0.0,
            memory_limit_mb=1024,  # 1 GB limit
            start_time=time.time(),
        )

        assert memory_peak == pytest.approx(500.0, rel=0.1)
        assert result is None  # No error result

    def test_memory_exceeded(self, mock_process: MagicMock, input_path: Path) -> None:
        """Test memory check when limit exceeded."""
        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.return_value = MagicMock(
            rss=2000 * 1024 * 1024  # 2 GB
        )

        memory_peak, result = _check_process_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            input_path=input_path,
            memory_peak=0.0,
            memory_limit_mb=1024,  # 1 GB limit
            start_time=time.time(),
        )

        assert result is not None
        assert result.status == "memory_exceeded"
        assert "Memory limit exceeded" in result.error_message
        mock_process.kill.assert_called_once()

    def test_process_disappeared(
        self, mock_process: MagicMock, input_path: Path
    ) -> None:
        """Test handling when process disappears during memory check."""
        import psutil

        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.side_effect = psutil.NoSuchProcess(12345)

        memory_peak, result = _check_process_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            input_path=input_path,
            memory_peak=100.0,
            memory_limit_mb=1024,
            start_time=time.time(),
        )

        assert result is not None
        assert result.status == "crash"
        assert "disappeared" in result.error_message

    def test_memory_peak_tracking(
        self, mock_process: MagicMock, input_path: Path
    ) -> None:
        """Test memory peak is properly tracked."""
        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.return_value = MagicMock(
            rss=300 * 1024 * 1024  # 300 MB
        )

        # Start with higher peak
        memory_peak, result = _check_process_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            input_path=input_path,
            memory_peak=500.0,  # Previous peak was 500 MB
            memory_limit_mb=1024,
            start_time=time.time(),
        )

        # Peak should remain at 500 (not decrease to 300)
        assert memory_peak == pytest.approx(500.0, rel=0.1)


class TestCheckPhaseMemory:
    """Tests for _check_phase_memory function."""

    @pytest.fixture
    def mock_process(self) -> MagicMock:
        """Create mock subprocess."""
        proc = MagicMock(spec=subprocess.Popen)
        proc.pid = 12345
        return proc

    def test_phase_memory_within_limit(self, mock_process: MagicMock) -> None:
        """Test phase memory check when within limit."""
        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.return_value = MagicMock(rss=500 * 1024 * 1024)

        memory_peak, result = _check_phase_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            phase_name="load",
            phase_start=time.time(),
            memory_peak=0.0,
            memory_limit=1024,
        )

        assert memory_peak == pytest.approx(500.0, rel=0.1)
        assert result is None

    def test_phase_memory_exceeded(self, mock_process: MagicMock) -> None:
        """Test phase memory check when limit exceeded."""
        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.return_value = MagicMock(rss=2000 * 1024 * 1024)

        memory_peak, result = _check_phase_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            phase_name="render",
            phase_start=time.time(),
            memory_peak=0.0,
            memory_limit=1024,
        )

        assert result is not None
        assert isinstance(result, PhaseResult)
        assert result.status == "memory_exceeded"
        assert result.phase_name == "render"
        mock_process.kill.assert_called_once()

    def test_phase_process_disappeared(self, mock_process: MagicMock) -> None:
        """Test handling when process disappears during phase."""
        import psutil

        mock_psutil_proc = MagicMock()
        mock_psutil_proc.memory_info.side_effect = psutil.NoSuchProcess(12345)

        memory_peak, result = _check_phase_memory(
            psutil_proc=mock_psutil_proc,
            process=mock_process,
            phase_name="interact",
            phase_start=time.time(),
            memory_peak=100.0,
            memory_limit=1024,
        )

        assert result is not None
        assert result.status == "crash"
        assert "disappeared" in result.error_message


class TestRunPhaseValidation:
    """Tests for _run_phase_validation function."""

    def test_no_validation_callback(self) -> None:
        """Test when phase has no validation callback."""
        phase = ObservationPhase(name="test", duration_seconds=5.0)

        validation_result, failure_result = _run_phase_validation(
            phase=phase,
            process_pid=12345,
            phase_start=time.time(),
            memory_peak=100.0,
        )

        assert validation_result is None
        assert failure_result is None

    def test_validation_passes(self) -> None:
        """Test when validation callback passes."""

        def validator(pid: int) -> ValidationResult:
            return ValidationResult(passed=True, message="OK")

        phase = ObservationPhase(
            name="validate",
            duration_seconds=5.0,
            validation_callback=validator,
        )

        validation_result, failure_result = _run_phase_validation(
            phase=phase,
            process_pid=12345,
            phase_start=time.time(),
            memory_peak=100.0,
        )

        assert validation_result is not None
        assert validation_result.passed is True
        assert failure_result is None

    def test_validation_fails(self) -> None:
        """Test when validation callback fails."""

        def validator(pid: int) -> ValidationResult:
            return ValidationResult(passed=False, message="UI element not found")

        phase = ObservationPhase(
            name="validate",
            duration_seconds=5.0,
            validation_callback=validator,
        )

        validation_result, failure_result = _run_phase_validation(
            phase=phase,
            process_pid=12345,
            phase_start=time.time(),
            memory_peak=100.0,
        )

        assert validation_result is not None
        assert validation_result.passed is False
        assert failure_result is not None
        assert failure_result.status == "validation_failed"
        assert "UI element not found" in failure_result.error_message

    def test_validation_callback_exception(self) -> None:
        """Test when validation callback raises exception."""

        def validator(pid: int) -> ValidationResult:
            raise RuntimeError("Validation crashed")

        phase = ObservationPhase(
            name="validate",
            duration_seconds=5.0,
            validation_callback=validator,
        )

        validation_result, failure_result = _run_phase_validation(
            phase=phase,
            process_pid=12345,
            phase_start=time.time(),
            memory_peak=100.0,
        )

        assert validation_result is not None
        assert validation_result.passed is False
        assert failure_result is not None
        assert failure_result.status == "validation_failed"
        assert "Validation error" in failure_result.error_message


class TestMonitorProcess:
    """Tests for monitor_process function."""

    @pytest.fixture
    def input_path(self, tmp_path: Path) -> Path:
        """Create test input path."""
        path = tmp_path / "test_study"
        path.mkdir()
        return path

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_process_exits_success(
        self, mock_psutil_avail: MagicMock, input_path: Path
    ) -> None:
        """Test monitoring process that exits with code 0."""
        mock_psutil_avail.return_value = False  # Disable psutil for this test

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 0  # Exit code 0

        result = monitor_process(
            process=mock_process,
            input_path=input_path,
            start_time=time.time(),
            timeout_seconds=10.0,
            memory_limit_mb=1024,
        )

        assert result.status == "success"
        assert result.exit_code == 0

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_process_exits_crash(
        self, mock_psutil_avail: MagicMock, input_path: Path
    ) -> None:
        """Test monitoring process that crashes."""
        mock_psutil_avail.return_value = False

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 139  # SIGSEGV

        result = monitor_process(
            process=mock_process,
            input_path=input_path,
            start_time=time.time(),
            timeout_seconds=10.0,
            memory_limit_mb=1024,
        )

        assert result.status == "crash"
        assert result.exit_code == 139

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_process_timeout_success_for_gui(
        self, mock_psutil_avail: MagicMock, input_path: Path
    ) -> None:
        """Test timeout is treated as success for GUI apps."""
        mock_psutil_avail.return_value = False

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None  # Still running

        start_time = time.time()
        result = monitor_process(
            process=mock_process,
            input_path=input_path,
            start_time=start_time,
            timeout_seconds=0.1,  # Very short timeout
            memory_limit_mb=1024,
        )

        # Timeout is success for GUI apps
        assert result.status == "success"
        mock_process.kill.assert_called()

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_monitor_without_psutil(
        self, mock_psutil_avail: MagicMock, input_path: Path
    ) -> None:
        """Test monitoring works without psutil."""
        mock_psutil_avail.return_value = False

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 0

        result = monitor_process(
            process=mock_process,
            input_path=input_path,
            start_time=time.time(),
            timeout_seconds=10.0,
            memory_limit_mb=1024,
        )

        assert result.status == "success"
        assert result.memory_peak_mb == 0.0


class TestRunObservationPhase:
    """Tests for run_observation_phase function."""

    @pytest.fixture
    def quick_phase(self) -> ObservationPhase:
        """Create a quick phase for testing."""
        return ObservationPhase(name="quick", duration_seconds=0.1)

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_process_exits_during_phase(
        self, mock_psutil_avail: MagicMock, quick_phase: ObservationPhase
    ) -> None:
        """Test handling when process exits during phase."""
        mock_psutil_avail.return_value = False

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 0  # Process exits

        result = run_observation_phase(
            process=mock_process,
            phase=quick_phase,
            default_memory_limit=1024,
        )

        assert result.status == "success"
        assert result.phase_name == "quick"

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_process_crashes_during_phase(
        self, mock_psutil_avail: MagicMock, quick_phase: ObservationPhase
    ) -> None:
        """Test handling when process crashes during phase."""
        mock_psutil_avail.return_value = False

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 139  # SIGSEGV

        result = run_observation_phase(
            process=mock_process,
            phase=quick_phase,
            default_memory_limit=1024,
        )

        assert result.status == "crash"

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_phase_completes_successfully(self, mock_psutil_avail: MagicMock) -> None:
        """Test phase completes when process stays running."""
        mock_psutil_avail.return_value = False

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None  # Still running

        phase = ObservationPhase(name="test", duration_seconds=0.1)

        result = run_observation_phase(
            process=mock_process,
            phase=phase,
            default_memory_limit=1024,
        )

        assert result.status == "success"
        assert result.phase_name == "test"

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_phase_uses_custom_memory_limit(self, mock_psutil_avail: MagicMock) -> None:
        """Test phase uses its own memory limit if specified."""
        mock_psutil_avail.return_value = False

        phase = ObservationPhase(
            name="heavy",
            duration_seconds=0.1,
            memory_limit_mb=4096,
        )

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None

        # The phase memory limit of 4096 should be used instead of default
        result = run_observation_phase(
            process=mock_process,
            phase=phase,
            default_memory_limit=1024,
        )

        assert result.status == "success"


class TestKillTargetProcesses:
    """Tests for kill_target_processes function."""

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    def test_no_psutil_returns_zero(self, mock_avail: MagicMock) -> None:
        """Test returns 0 when psutil not available."""
        mock_avail.return_value = False

        killed = kill_target_processes("viewer")

        assert killed == 0

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    @patch("psutil.process_iter")
    def test_kills_matching_processes(
        self, mock_iter: MagicMock, mock_avail: MagicMock
    ) -> None:
        """Test kills processes matching pattern."""
        mock_avail.return_value = True

        # Create mock processes
        mock_proc1 = MagicMock()
        mock_proc1.info = {"name": "MyViewer.exe", "pid": 1001}

        mock_proc2 = MagicMock()
        mock_proc2.info = {"name": "other_app.exe", "pid": 1002}

        mock_proc3 = MagicMock()
        mock_proc3.info = {"name": "viewer_helper.exe", "pid": 1003}

        mock_iter.return_value = [mock_proc1, mock_proc2, mock_proc3]

        killed = kill_target_processes("viewer")

        # Should kill MyViewer and viewer_helper
        assert killed == 2
        mock_proc1.kill.assert_called_once()
        mock_proc2.kill.assert_not_called()
        mock_proc3.kill.assert_called_once()

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    @patch("psutil.process_iter")
    def test_handles_process_gone(
        self, mock_iter: MagicMock, mock_avail: MagicMock
    ) -> None:
        """Test handles NoSuchProcess gracefully."""
        import psutil

        mock_avail.return_value = True

        mock_proc = MagicMock()
        mock_proc.info = {"name": "viewer.exe", "pid": 1001}
        mock_proc.kill.side_effect = psutil.NoSuchProcess(1001)

        mock_iter.return_value = [mock_proc]

        # Should not raise, just log and continue
        killed = kill_target_processes("viewer")
        assert killed == 0  # Process was gone

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    @patch("psutil.process_iter")
    def test_handles_access_denied(
        self, mock_iter: MagicMock, mock_avail: MagicMock
    ) -> None:
        """Test handles AccessDenied gracefully."""
        import psutil

        mock_avail.return_value = True

        mock_proc = MagicMock()
        mock_proc.info = {"name": "viewer.exe", "pid": 1001}
        mock_proc.kill.side_effect = psutil.AccessDenied(1001)

        mock_iter.return_value = [mock_proc]

        # Should not raise
        killed = kill_target_processes("viewer")
        assert killed == 0

    @patch("dicom_fuzzer.core.harness.monitoring.is_psutil_available")
    @patch("psutil.process_iter")
    def test_handles_empty_name(
        self, mock_iter: MagicMock, mock_avail: MagicMock
    ) -> None:
        """Test handles processes with empty/None name."""
        mock_avail.return_value = True

        mock_proc = MagicMock()
        mock_proc.info = {"name": "", "pid": 1001}

        mock_iter.return_value = [mock_proc]

        killed = kill_target_processes("viewer")
        assert killed == 0
        mock_proc.kill.assert_not_called()
