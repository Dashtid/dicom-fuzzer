"""Tests for Process Monitor Module.

Tests cover:
- HangReason enum
- ProcessMetrics dataclass
- MonitorResult dataclass
- ProcessMonitor class (basic and enhanced monitoring)
- Process termination logic
- Factory functions
"""

import subprocess
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

from dicom_fuzzer.core.process_monitor import (
    HangReason,
    MonitorResult,
    ProcessMetrics,
    ProcessMonitor,
    get_process_monitor,
    is_psutil_available,
)


class TestHangReason:
    """Test HangReason enum."""

    def test_all_reasons_exist(self):
        """Test that all hang reasons are defined."""
        assert HangReason.TIMEOUT.value == "timeout"
        assert HangReason.CPU_IDLE.value == "cpu_idle"
        assert HangReason.MEMORY_SPIKE.value == "memory_spike"
        assert HangReason.CPU_SPIN.value == "cpu_spin"
        assert HangReason.NOT_RESPONDING.value == "not_responding"

    def test_reason_count(self):
        """Test that exactly 5 reasons are defined."""
        reasons = list(HangReason)
        assert len(reasons) == 5


class TestProcessMetrics:
    """Test ProcessMetrics dataclass."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = ProcessMetrics()

        assert metrics.peak_memory_mb == 0.0
        assert metrics.average_cpu_percent == 0.0
        assert metrics.cpu_samples == []
        assert metrics.memory_samples == []
        assert metrics.idle_duration_seconds == 0.0
        assert metrics.total_duration_seconds == 0.0

    def test_add_sample_updates_peak(self):
        """Test add_sample updates peak memory."""
        metrics = ProcessMetrics()

        metrics.add_sample(50.0, 100.0)
        assert metrics.peak_memory_mb == 100.0

        metrics.add_sample(60.0, 150.0)
        assert metrics.peak_memory_mb == 150.0

        # Peak should not decrease
        metrics.add_sample(40.0, 80.0)
        assert metrics.peak_memory_mb == 150.0

    def test_add_sample_stores_samples(self):
        """Test add_sample stores CPU and memory samples."""
        metrics = ProcessMetrics()

        metrics.add_sample(50.0, 100.0)
        metrics.add_sample(60.0, 120.0)
        metrics.add_sample(40.0, 80.0)

        assert metrics.cpu_samples == [50.0, 60.0, 40.0]
        assert metrics.memory_samples == [100.0, 120.0, 80.0]

    def test_calculate_averages_empty(self):
        """Test calculate_averages with no samples."""
        metrics = ProcessMetrics()
        metrics.calculate_averages()

        assert metrics.average_cpu_percent == 0.0

    def test_calculate_averages_with_samples(self):
        """Test calculate_averages with samples."""
        metrics = ProcessMetrics()

        metrics.add_sample(50.0, 100.0)
        metrics.add_sample(60.0, 120.0)
        metrics.add_sample(40.0, 80.0)
        metrics.calculate_averages()

        assert metrics.average_cpu_percent == 50.0  # (50+60+40)/3


class TestMonitorResult:
    """Test MonitorResult dataclass."""

    def test_creation_completed(self):
        """Test creating result for completed process."""
        metrics = ProcessMetrics()
        result = MonitorResult(
            completed=True,
            hang_detected=False,
            hang_reason=None,
            exit_code=0,
            metrics=metrics,
            duration_seconds=5.0,
        )

        assert result.completed is True
        assert result.hang_detected is False
        assert result.hang_reason is None
        assert result.exit_code == 0
        assert result.duration_seconds == 5.0

    def test_creation_hung_timeout(self):
        """Test creating result for timeout hang."""
        metrics = ProcessMetrics()
        result = MonitorResult(
            completed=False,
            hang_detected=True,
            hang_reason=HangReason.TIMEOUT,
            exit_code=None,
            metrics=metrics,
            duration_seconds=30.0,
        )

        assert result.completed is False
        assert result.hang_detected is True
        assert result.hang_reason == HangReason.TIMEOUT
        assert result.exit_code is None

    def test_creation_hung_memory_spike(self):
        """Test creating result for memory spike hang."""
        metrics = ProcessMetrics()
        result = MonitorResult(
            completed=False,
            hang_detected=True,
            hang_reason=HangReason.MEMORY_SPIKE,
            exit_code=None,
            metrics=metrics,
            duration_seconds=10.0,
        )

        assert result.hang_reason == HangReason.MEMORY_SPIKE


class TestProcessMonitorInit:
    """Test ProcessMonitor initialization."""

    def test_init_default_values(self):
        """Test monitor initialization with defaults."""
        monitor = ProcessMonitor()

        assert monitor.timeout == 30.0
        assert monitor.idle_threshold == 5.0
        assert monitor.memory_limit_mb is None
        assert monitor.poll_interval == 0.1
        assert monitor.cpu_idle_percent == 1.0

    def test_init_custom_values(self):
        """Test monitor initialization with custom values."""
        monitor = ProcessMonitor(
            timeout=60.0,
            idle_threshold=10.0,
            memory_limit_mb=2048,
            poll_interval=0.5,
            cpu_idle_percent=2.0,
        )

        assert monitor.timeout == 60.0
        assert monitor.idle_threshold == 10.0
        assert monitor.memory_limit_mb == 2048
        assert monitor.poll_interval == 0.5
        assert monitor.cpu_idle_percent == 2.0


class TestProcessMonitorBasic:
    """Test ProcessMonitor with basic (no psutil) monitoring."""

    def test_basic_monitor_completes(self):
        """Test basic monitor when process completes."""
        monitor = ProcessMonitor(timeout=5.0)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.wait.return_value = 0  # Exit code 0

        with patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", False):
            result = monitor.monitor_process(mock_process)

        assert result.completed is True
        assert result.hang_detected is False
        assert result.exit_code == 0
        mock_process.wait.assert_called_once_with(timeout=5.0)

    def test_basic_monitor_timeout(self):
        """Test basic monitor when process times out."""
        monitor = ProcessMonitor(timeout=1.0)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.wait.side_effect = subprocess.TimeoutExpired(
            cmd="test", timeout=1.0
        )
        mock_process.terminate.return_value = None

        with patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", False):
            result = monitor.monitor_process(mock_process)

        assert result.completed is False
        assert result.hang_detected is True
        assert result.hang_reason == HangReason.TIMEOUT
        assert result.exit_code is None
        mock_process.terminate.assert_called()


class TestProcessMonitorEnhanced:
    """Test ProcessMonitor with enhanced (psutil) monitoring."""

    @pytest.fixture
    def mock_psutil_process(self):
        """Create a mock psutil.Process."""
        mock_ps = MagicMock()
        mock_ps.cpu_percent.return_value = 50.0
        mock_memory_info = MagicMock()
        mock_memory_info.rss = 100 * 1024 * 1024  # 100 MB
        mock_ps.memory_info.return_value = mock_memory_info
        mock_ps.children.return_value = []
        return mock_ps

    def test_enhanced_monitor_completes(self, mock_psutil_process):
        """Test enhanced monitor when process completes normally."""
        monitor = ProcessMonitor(timeout=5.0)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        # First poll returns None (running), second returns 0 (completed)
        mock_process.poll.side_effect = [None, 0]

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
            patch("time.sleep"),
        ):
            mock_psutil_module.Process.return_value = mock_psutil_process
            mock_psutil_module.NoSuchProcess = Exception
            mock_psutil_module.AccessDenied = Exception

            result = monitor.monitor_process(mock_process)

        assert result.completed is True
        assert result.hang_detected is False
        assert result.exit_code == 0
        assert result.metrics.cpu_samples == [50.0]

    def test_enhanced_monitor_timeout(self, mock_psutil_process):
        """Test enhanced monitor when process times out."""
        monitor = ProcessMonitor(timeout=0.01, poll_interval=0.001)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        mock_process.poll.return_value = None  # Always running

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
            patch("time.sleep"),
        ):
            mock_psutil_module.Process.return_value = mock_psutil_process
            mock_psutil_module.NoSuchProcess = Exception
            mock_psutil_module.AccessDenied = Exception
            mock_psutil_module.wait_procs.return_value = ([], [])

            result = monitor.monitor_process(mock_process)

        assert result.completed is False
        assert result.hang_detected is True
        assert result.hang_reason == HangReason.TIMEOUT

    def test_enhanced_monitor_cpu_idle_hang(self, mock_psutil_process):
        """Test enhanced monitor detects CPU idle hang."""
        monitor = ProcessMonitor(
            timeout=30.0,
            idle_threshold=0.01,  # Very short for testing
            poll_interval=0.001,
            cpu_idle_percent=1.0,
        )

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        mock_process.poll.return_value = None  # Always running

        # CPU is idle (0%)
        mock_psutil_process.cpu_percent.return_value = 0.0

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
            patch("time.sleep"),
        ):
            mock_psutil_module.Process.return_value = mock_psutil_process
            mock_psutil_module.NoSuchProcess = Exception
            mock_psutil_module.AccessDenied = Exception
            mock_psutil_module.wait_procs.return_value = ([], [])

            result = monitor.monitor_process(mock_process)

        assert result.completed is False
        assert result.hang_detected is True
        assert result.hang_reason == HangReason.CPU_IDLE
        assert result.metrics.idle_duration_seconds > 0

    def test_enhanced_monitor_memory_spike(self, mock_psutil_process):
        """Test enhanced monitor detects memory spike."""
        monitor = ProcessMonitor(
            timeout=30.0,
            memory_limit_mb=50,  # 50 MB limit
            poll_interval=0.001,
        )

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        mock_process.poll.return_value = None  # Always running

        # Memory exceeds limit (100 MB > 50 MB limit)
        mock_memory_info = MagicMock()
        mock_memory_info.rss = 100 * 1024 * 1024  # 100 MB
        mock_psutil_process.memory_info.return_value = mock_memory_info

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
            patch("time.sleep"),
        ):
            mock_psutil_module.Process.return_value = mock_psutil_process
            mock_psutil_module.NoSuchProcess = Exception
            mock_psutil_module.AccessDenied = Exception
            mock_psutil_module.wait_procs.return_value = ([], [])

            result = monitor.monitor_process(mock_process)

        assert result.completed is False
        assert result.hang_detected is True
        assert result.hang_reason == HangReason.MEMORY_SPIKE

    def test_enhanced_monitor_process_attach_fails(self):
        """Test fallback to basic monitor when process attach fails."""
        monitor = ProcessMonitor(timeout=1.0)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        mock_process.wait.return_value = 0

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
        ):
            # Simulate process not found
            mock_psutil_module.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil_module.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil_module.Process.side_effect = mock_psutil_module.NoSuchProcess()

            result = monitor.monitor_process(mock_process)

        # Should fall back to basic monitor
        assert result.completed is True
        assert result.exit_code == 0

    def test_enhanced_monitor_process_disappears(self, mock_psutil_process):
        """Test handling when process disappears during monitoring."""
        monitor = ProcessMonitor(timeout=30.0, poll_interval=0.001)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        # First poll returns None (running), second returns 0 (completed)
        mock_process.poll.side_effect = [None, 0]
        # Also configure wait() for fallback to basic_monitor
        mock_process.wait.return_value = 0

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
            patch("time.sleep"),
        ):
            mock_psutil_module.Process.return_value = mock_psutil_process
            mock_psutil_module.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil_module.AccessDenied = type("AccessDenied", (Exception,), {})

            # Process disappears during priming cpu_percent call - falls back to basic
            mock_psutil_process.cpu_percent.side_effect = (
                mock_psutil_module.NoSuchProcess()
            )

            result = monitor.monitor_process(mock_process)

        assert result.completed is True
        assert result.exit_code == 0


class TestProcessTermination:
    """Test process termination methods."""

    def test_terminate_process_unix(self):
        """Test process termination on Unix."""
        monitor = ProcessMonitor()

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.terminate.return_value = None
        mock_process.wait.return_value = 0

        with patch.object(sys, "platform", "linux"):
            monitor._terminate_process(mock_process)

        mock_process.terminate.assert_called_once()

    def test_terminate_process_windows(self):
        """Test process termination on Windows."""
        monitor = ProcessMonitor()

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.terminate.return_value = None

        with patch.object(sys, "platform", "win32"):
            monitor._terminate_process(mock_process)

        mock_process.terminate.assert_called_once()

    def test_terminate_process_unix_needs_kill(self):
        """Test Unix termination falls back to kill."""
        monitor = ProcessMonitor()

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.terminate.return_value = None
        mock_process.wait.side_effect = subprocess.TimeoutExpired(
            cmd="test", timeout=2.0
        )
        mock_process.kill.return_value = None

        with patch.object(sys, "platform", "linux"):
            monitor._terminate_process(mock_process)

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()

    def test_terminate_process_tree(self):
        """Test process tree termination."""
        monitor = ProcessMonitor()

        mock_ps_process = MagicMock()
        mock_child1 = MagicMock()
        mock_child2 = MagicMock()
        mock_ps_process.children.return_value = [mock_child1, mock_child2]

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
        ):
            mock_psutil_module.NoSuchProcess = Exception
            mock_psutil_module.AccessDenied = Exception
            mock_psutil_module.wait_procs.return_value = ([], [])

            monitor._terminate_process_tree(mock_ps_process)

        mock_child1.terminate.assert_called_once()
        mock_child2.terminate.assert_called_once()
        mock_ps_process.terminate.assert_called_once()

    def test_terminate_process_tree_with_survivors(self):
        """Test process tree termination with processes that need kill."""
        monitor = ProcessMonitor()

        mock_ps_process = MagicMock()
        mock_child = MagicMock()
        mock_ps_process.children.return_value = [mock_child]

        with (
            patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", True),
            patch("dicom_fuzzer.core.process_monitor.psutil") as mock_psutil_module,
        ):
            mock_psutil_module.NoSuchProcess = Exception
            mock_psutil_module.AccessDenied = Exception
            # Return mock_child as a survivor
            mock_psutil_module.wait_procs.return_value = ([], [mock_child])

            monitor._terminate_process_tree(mock_ps_process)

        mock_child.kill.assert_called_once()

    def test_terminate_process_tree_no_psutil(self):
        """Test process tree termination when psutil unavailable."""
        monitor = ProcessMonitor()

        mock_ps_process = MagicMock()

        with patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", False):
            # Should return without error
            monitor._terminate_process_tree(mock_ps_process)

        mock_ps_process.children.assert_not_called()


class TestFactoryFunctions:
    """Test factory functions."""

    def test_get_process_monitor_default(self):
        """Test get_process_monitor with defaults."""
        monitor = get_process_monitor()

        assert isinstance(monitor, ProcessMonitor)
        assert monitor.timeout == 30.0
        assert monitor.idle_threshold == 5.0
        assert monitor.memory_limit_mb is None

    def test_get_process_monitor_custom(self):
        """Test get_process_monitor with custom values."""
        monitor = get_process_monitor(
            timeout=60.0,
            idle_threshold=10.0,
            memory_limit_mb=4096,
        )

        assert monitor.timeout == 60.0
        assert monitor.idle_threshold == 10.0
        assert monitor.memory_limit_mb == 4096

    def test_is_psutil_available(self):
        """Test is_psutil_available function."""
        result = is_psutil_available()

        # Should return boolean
        assert isinstance(result, bool)


class TestIntegration:
    """Integration tests for process monitoring."""

    def test_full_monitoring_workflow_completes(self):
        """Test complete monitoring workflow with successful process."""
        monitor = ProcessMonitor(timeout=5.0)

        mock_process = Mock(spec=subprocess.Popen)
        mock_process.pid = 1234
        mock_process.wait.return_value = 42  # Exit code 42

        with patch("dicom_fuzzer.core.process_monitor.PSUTIL_AVAILABLE", False):
            result = monitor.monitor_process(mock_process)

        assert result.completed is True
        assert result.hang_detected is False
        assert result.exit_code == 42
        assert result.hang_reason is None
        assert result.duration_seconds > 0

    def test_metrics_collection(self):
        """Test that metrics are properly collected."""
        metrics = ProcessMetrics()

        # Simulate monitoring samples
        for i in range(10):
            cpu = 50.0 + (i * 2)  # 50, 52, 54, ... 68
            mem = 100.0 + (i * 10)  # 100, 110, 120, ... 190
            metrics.add_sample(cpu, mem)

        metrics.calculate_averages()

        assert len(metrics.cpu_samples) == 10
        assert len(metrics.memory_samples) == 10
        assert metrics.peak_memory_mb == 190.0
        assert metrics.average_cpu_percent == 59.0  # Average of 50-68


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
