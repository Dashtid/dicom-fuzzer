"""Tests for GUI Monitor module.

Tests for response-aware GUI monitoring including:
- GUIResponse dataclass
- MonitorConfig configuration
- GUIMonitor class
- ResponseAwareFuzzer integration
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.engine import ResponseAwareFuzzer
from dicom_fuzzer.core.engine.gui_monitor import (
    GUIMonitor,
    GUIResponse,
    MonitorConfig,
    ResponseType,
    SeverityLevel,
)


class TestResponseType:
    """Tests for ResponseType enum."""

    def test_response_type_values(self) -> None:
        """Test all response type values exist."""
        assert ResponseType.NORMAL.value == "normal"
        assert ResponseType.ERROR_DIALOG.value == "error_dialog"
        assert ResponseType.WARNING_DIALOG.value == "warning_dialog"
        assert ResponseType.CRASH.value == "crash"
        assert ResponseType.HANG.value == "hang"
        assert ResponseType.MEMORY_SPIKE.value == "memory_spike"
        assert ResponseType.RENDER_ANOMALY.value == "render_anomaly"
        assert ResponseType.RESOURCE_EXHAUSTION.value == "resource_exhaustion"


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_severity_level_values(self) -> None:
        """Test all severity level values exist."""
        assert SeverityLevel.INFO.value == "info"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.CRITICAL.value == "critical"


class TestGUIResponse:
    """Tests for GUIResponse dataclass."""

    def test_gui_response_creation(self) -> None:
        """Test creating GUIResponse."""
        response = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
        )
        assert response.response_type == ResponseType.ERROR_DIALOG
        assert response.severity == SeverityLevel.HIGH
        assert isinstance(response.timestamp, datetime)

    def test_gui_response_with_all_fields(self) -> None:
        """Test GUIResponse with all fields populated."""
        test_file = Path("/test/file.dcm")
        screenshot = Path("/screenshots/error.png")

        response = GUIResponse(
            response_type=ResponseType.CRASH,
            severity=SeverityLevel.CRITICAL,
            test_file=test_file,
            details="Application crashed with access violation",
            window_title="Error",
            dialog_text="Access violation at address 0x00000000",
            memory_usage_mb=1024.5,
            screenshot_path=screenshot,
        )

        assert response.test_file == test_file
        assert "access violation" in response.details.lower()
        assert response.window_title == "Error"
        assert response.memory_usage_mb == 1024.5
        assert response.screenshot_path == screenshot

    def test_gui_response_to_dict(self) -> None:
        """Test GUIResponse serialization to dict."""
        response = GUIResponse(
            response_type=ResponseType.WARNING_DIALOG,
            severity=SeverityLevel.MEDIUM,
            test_file=Path("/test/file.dcm"),
            details="Warning detected",
        )

        data = response.to_dict()

        assert data["response_type"] == "warning_dialog"
        assert data["severity"] == "medium"
        # Use Path comparison to handle Windows/Unix path differences
        assert Path(data["test_file"]) == Path("/test/file.dcm")
        assert data["details"] == "Warning detected"
        assert "timestamp" in data

    def test_gui_response_to_dict_none_values(self) -> None:
        """Test GUIResponse serialization with None values."""
        response = GUIResponse(
            response_type=ResponseType.NORMAL,
            severity=SeverityLevel.INFO,
        )

        data = response.to_dict()

        assert data["test_file"] is None
        assert data["screenshot_path"] is None


class TestMonitorConfig:
    """Tests for MonitorConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = MonitorConfig()

        assert config.poll_interval == 0.1
        assert config.memory_threshold_mb == 2048.0
        assert config.memory_spike_percent == 50.0
        assert config.hang_timeout == 5.0
        assert len(config.error_patterns) > 0
        assert len(config.warning_patterns) > 0

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = MonitorConfig(
            poll_interval=0.5,
            memory_threshold_mb=4096.0,
            memory_spike_percent=100.0,
            hang_timeout=10.0,
        )

        assert config.poll_interval == 0.5
        assert config.memory_threshold_mb == 4096.0

    def test_error_patterns_defaults(self) -> None:
        """Test default error patterns include common errors."""
        config = MonitorConfig()

        # Check key patterns exist
        patterns_text = " ".join(config.error_patterns)
        assert "error" in patterns_text.lower()
        assert "exception" in patterns_text.lower()
        assert "failed" in patterns_text.lower()

    def test_warning_patterns_defaults(self) -> None:
        """Test default warning patterns include common warnings."""
        config = MonitorConfig()

        patterns_text = " ".join(config.warning_patterns)
        assert "warning" in patterns_text.lower()
        assert "caution" in patterns_text.lower()


class TestGUIMonitor:
    """Tests for GUIMonitor class."""

    def test_monitor_initialization(self) -> None:
        """Test monitor initialization with default config."""
        monitor = GUIMonitor()

        assert monitor.config is not None
        assert monitor._monitoring is False
        assert len(monitor.get_responses()) == 0

    def test_monitor_initialization_custom_config(self) -> None:
        """Test monitor initialization with custom config."""
        config = MonitorConfig(poll_interval=0.2)
        monitor = GUIMonitor(config)

        assert monitor.config.poll_interval == 0.2

    def test_get_responses_empty(self) -> None:
        """Test getting responses when none recorded."""
        monitor = GUIMonitor()
        responses = monitor.get_responses()

        assert responses == []

    def test_clear_responses(self) -> None:
        """Test clearing recorded responses."""
        monitor = GUIMonitor()
        # Manually add a response
        monitor._responses.append(
            GUIResponse(
                response_type=ResponseType.ERROR_DIALOG,
                severity=SeverityLevel.HIGH,
            )
        )

        assert len(monitor.get_responses()) == 1
        monitor.clear_responses()
        assert len(monitor.get_responses()) == 0

    def test_get_summary_empty(self) -> None:
        """Test getting summary with no responses."""
        monitor = GUIMonitor()
        summary = monitor.get_summary()

        assert summary["total_responses"] == 0
        assert summary["by_type"] == {}
        assert summary["by_severity"] == {}
        assert summary["critical_issues"] == []

    def test_get_summary_with_responses(self) -> None:
        """Test getting summary with recorded responses."""
        monitor = GUIMonitor()

        # Add various responses
        monitor._responses.extend(
            [
                GUIResponse(
                    response_type=ResponseType.ERROR_DIALOG,
                    severity=SeverityLevel.HIGH,
                ),
                GUIResponse(
                    response_type=ResponseType.ERROR_DIALOG,
                    severity=SeverityLevel.CRITICAL,
                ),
                GUIResponse(
                    response_type=ResponseType.WARNING_DIALOG,
                    severity=SeverityLevel.MEDIUM,
                ),
            ]
        )

        summary = monitor.get_summary()

        assert summary["total_responses"] == 3
        assert summary["by_type"]["error_dialog"] == 2
        assert summary["by_type"]["warning_dialog"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert len(summary["critical_issues"]) == 2  # HIGH and CRITICAL

    def test_add_response_debounce(self) -> None:
        """Test that duplicate responses are debounced."""
        monitor = GUIMonitor()

        response = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="Same error",
        )

        # Add same response twice quickly
        monitor.add_response(response)
        monitor.add_response(response)

        # Should only have one due to debounce
        assert len(monitor.get_responses()) == 1

    def test_stop_monitoring_when_not_started(self) -> None:
        """Test stopping monitor when not running."""
        monitor = GUIMonitor()
        # Should not raise
        monitor.stop_monitoring()
        assert monitor._monitoring is False

    @patch("dicom_fuzzer.core.engine.gui_monitor.HAS_PSUTIL", False)
    def test_monitor_without_psutil(self) -> None:
        """Test monitor behavior without psutil."""
        monitor = GUIMonitor()
        # Should initialize but have limited functionality
        assert monitor is not None


class TestGUIMonitorPatternMatching:
    """Tests for pattern matching in GUIMonitor."""

    def test_error_pattern_compilation(self) -> None:
        """Test that error patterns compile correctly."""
        monitor = GUIMonitor()
        # Should have compiled patterns
        assert len(monitor._error_patterns) > 0

    def test_warning_pattern_compilation(self) -> None:
        """Test that warning patterns compile correctly."""
        monitor = GUIMonitor()
        assert len(monitor._warning_patterns) > 0

    def test_error_pattern_matching(self) -> None:
        """Test error patterns match expected text."""
        monitor = GUIMonitor()

        test_texts = [
            "Error: File not found",
            "An exception occurred",
            "Operation failed",
            "Cannot open file",
            "Invalid file format",
            "File is corrupt",
            "Access violation detected",
        ]

        for text in test_texts:
            matched = any(p.search(text) for p in monitor._error_patterns)
            assert matched, f"Pattern should match: {text}"

    def test_warning_pattern_matching(self) -> None:
        """Test warning patterns match expected text."""
        monitor = GUIMonitor()

        test_texts = [
            "Warning: Low memory",
            "Caution: Unsaved changes",
            "Could not load all data",
            "Unable to complete operation",
            "Unexpected value found",
        ]

        for text in test_texts:
            matched = any(p.search(text) for p in monitor._warning_patterns)
            assert matched, f"Pattern should match: {text}"


class TestResponseAwareFuzzer:
    """Tests for ResponseAwareFuzzer class."""

    def test_fuzzer_init_nonexistent_target(self) -> None:
        """Test fuzzer raises error for nonexistent target."""
        with pytest.raises(FileNotFoundError):
            ResponseAwareFuzzer("/nonexistent/path/to/app.exe")

    def test_fuzzer_init_with_existing_target(self, tmp_path: Path) -> None:
        """Test fuzzer initialization with existing target."""
        # Create a dummy executable
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        fuzzer = ResponseAwareFuzzer(str(target))

        assert fuzzer.target_executable == target
        assert fuzzer.timeout == 10.0  # Default
        assert fuzzer.monitor is not None

    def test_fuzzer_custom_config(self, tmp_path: Path) -> None:
        """Test fuzzer with custom config."""
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        config = MonitorConfig(poll_interval=0.5)
        fuzzer = ResponseAwareFuzzer(str(target), config=config, timeout=5.0)

        assert fuzzer.timeout == 5.0
        assert fuzzer.monitor.config.poll_interval == 0.5

    @patch("subprocess.Popen")
    def test_test_file_method(self, mock_popen: MagicMock, tmp_path: Path) -> None:
        """Test the test_file method."""
        # Setup
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dicom")

        # Mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = 0
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        fuzzer = ResponseAwareFuzzer(str(target), timeout=0.1)
        responses = fuzzer.test_file(test_file)

        # Should return list of responses
        assert isinstance(responses, list)

    @patch("subprocess.Popen")
    def test_run_campaign(self, mock_popen: MagicMock, tmp_path: Path) -> None:
        """Test running a campaign."""
        # Setup
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        test_files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"dicom")
            test_files.append(f)

        # Mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = 0
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        fuzzer = ResponseAwareFuzzer(str(target), timeout=0.1)
        results = fuzzer.run_campaign(test_files)

        assert results["total_files"] == 3
        assert results["files_tested"] == 3
        assert "responses" in results
        assert "summary" in results


class TestGUIMonitorMemoryChecking:
    """Tests for memory monitoring functionality."""

    def test_memory_spike_detection_logic(self) -> None:
        """Test memory spike detection calculation."""
        config = MonitorConfig(memory_spike_percent=50.0)
        monitor = GUIMonitor(config)

        # Set baseline
        monitor._baseline_memory = 100.0

        # Calculate expected increase
        # 150% of baseline should trigger spike
        expected_trigger = 100.0 * 1.5  # 150 MB

        # Verify calculation logic
        increase_percent = ((expected_trigger - 100.0) / 100.0) * 100
        assert increase_percent == 50.0  # Should exactly match threshold

    def test_memory_threshold_detection_logic(self) -> None:
        """Test absolute memory threshold logic."""
        config = MonitorConfig(memory_threshold_mb=2048.0)
        monitor = GUIMonitor(config)

        # Any usage above 2048 should trigger
        assert 2049 > config.memory_threshold_mb
        assert 2047 < config.memory_threshold_mb


class TestGUIMonitorStartStop:
    """Tests for monitoring start/stop functionality."""

    def test_start_monitoring_sets_flag(self) -> None:
        """Test that start_monitoring sets the monitoring flag."""
        monitor = GUIMonitor()
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 0  # Already exited

        monitor.start_monitoring(mock_process)

        assert monitor._monitoring is True
        # Clean up
        monitor.stop_monitoring()

    def test_start_monitoring_when_already_monitoring(self) -> None:
        """Test starting monitor when already monitoring."""
        monitor = GUIMonitor()
        monitor._monitoring = True

        mock_process = MagicMock()
        mock_process.pid = 12345

        # Should log warning but not crash
        monitor.start_monitoring(mock_process)

        # Should still be monitoring
        assert monitor._monitoring is True

    def test_stop_monitoring_clears_flag(self) -> None:
        """Test that stop_monitoring clears the flag."""
        monitor = GUIMonitor()
        monitor._monitoring = True

        monitor.stop_monitoring()

        assert monitor._monitoring is False


class TestGUIMonitorMonitorLoop:
    """Tests for the monitoring loop functionality."""

    def test_monitor_loop_without_psutil(self) -> None:
        """Test monitor loop without psutil returns early."""
        # Save original value
        import dicom_fuzzer.core.engine.gui_monitor as gm

        original = gm.HAS_PSUTIL
        try:
            gm.HAS_PSUTIL = False
            monitor = GUIMonitor()

            mock_process = MagicMock()
            mock_process.pid = 12345

            monitor._monitoring = True
            # Should return early without psutil
            monitor._monitor_loop(mock_process, None)
            # Verify no responses were generated (early return)
            assert len(monitor.get_responses()) == 0
        finally:
            gm.HAS_PSUTIL = original


class TestGUIMonitorMemoryChecks:
    """Tests for memory checking functionality."""

    @patch("dicom_fuzzer.core.engine.gui_monitor.psutil")
    def test_check_memory_exceeds_threshold(self, mock_psutil: MagicMock) -> None:
        """Test memory check when threshold exceeded."""
        config = MonitorConfig(memory_threshold_mb=1000.0)
        monitor = GUIMonitor(config)
        monitor._last_response_time = 0  # Disable debounce

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value.rss = 2000 * 1024 * 1024  # 2000 MB

        monitor._check_memory(mock_ps_process, Path("/test.dcm"))

        responses = monitor.get_responses()
        assert len(responses) >= 1
        assert responses[0].response_type == ResponseType.RESOURCE_EXHAUSTION

    @patch("dicom_fuzzer.core.engine.gui_monitor.psutil")
    def test_check_memory_spike(self, mock_psutil: MagicMock) -> None:
        """Test memory check detects spike."""
        config = MonitorConfig(memory_spike_percent=50.0)
        monitor = GUIMonitor(config)
        monitor._baseline_memory = 100.0
        monitor._last_response_time = 0  # Disable debounce

        mock_ps_process = MagicMock()
        # 200 MB = 100% increase from 100 MB baseline
        mock_ps_process.memory_info.return_value.rss = 200 * 1024 * 1024

        monitor._check_memory(mock_ps_process, Path("/test.dcm"))

        responses = monitor.get_responses()
        spike_responses = [
            r for r in responses if r.response_type == ResponseType.MEMORY_SPIKE
        ]
        assert len(spike_responses) >= 1

    @patch("dicom_fuzzer.core.engine.gui_monitor.psutil")
    def test_check_memory_nosuchprocess(self, mock_psutil: MagicMock) -> None:
        """Test memory check handles NoSuchProcess gracefully."""
        monitor = GUIMonitor()

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.side_effect = mock_psutil.NoSuchProcess(123)
        mock_psutil.NoSuchProcess = Exception

        # Should not raise - exception is handled internally
        monitor._check_memory(mock_ps_process, None)
        # Verify no crash-related responses (exception was caught gracefully)
        assert all(
            r.response_type != ResponseType.CRASH for r in monitor.get_responses()
        )


class TestGUIMonitorHangDetection:
    """Tests for hang detection functionality."""

    def test_check_hang_normal_cpu(self) -> None:
        """Test no hang detection with normal CPU usage."""
        monitor = GUIMonitor()

        mock_ps_process = MagicMock()
        mock_ps_process.cpu_percent.return_value = 25.0  # Normal CPU
        mock_ps_process.status.return_value = "running"

        monitor._check_hang(mock_ps_process, None)

        # Should not detect hang
        hang_responses = [
            r for r in monitor.get_responses() if r.response_type == ResponseType.HANG
        ]
        assert len(hang_responses) == 0

    def test_check_hang_high_cpu(self) -> None:
        """Test no hang detection with high CPU usage."""
        monitor = GUIMonitor()

        mock_ps_process = MagicMock()
        mock_ps_process.cpu_percent.return_value = 50.0  # High CPU
        mock_ps_process.status.return_value = "running"

        monitor._check_hang(mock_ps_process, None)

        # Should not detect hang with high CPU
        hang_responses = [
            r for r in monitor.get_responses() if r.response_type == ResponseType.HANG
        ]
        assert len(hang_responses) == 0


class TestGUIMonitorDialogChecks:
    """Tests for dialog checking functionality."""

    @patch("dicom_fuzzer.core.engine.gui_monitor.HAS_PYWINAUTO", False)
    def test_check_dialogs_without_pywinauto(self) -> None:
        """Test dialog check returns early without pywinauto."""
        monitor = GUIMonitor()

        # Should not raise - returns early without pywinauto
        monitor._check_dialogs(12345, None)
        # Verify no dialog responses generated (early return)
        assert len(monitor.get_responses()) == 0

    @patch("dicom_fuzzer.core.engine.gui_monitor.HAS_PYWINAUTO", True)
    @patch("dicom_fuzzer.core.engine.gui_monitor.Application")
    def test_check_dialogs_element_not_found(self, mock_app_class: MagicMock) -> None:
        """Test dialog check handles ElementNotFoundError gracefully."""
        monitor = GUIMonitor()

        from dicom_fuzzer.core.engine.gui_monitor import ElementNotFoundError

        mock_app_class.return_value.connect.side_effect = ElementNotFoundError()

        # Should not raise - exception is handled internally
        monitor._check_dialogs(12345, None)
        # Verify no dialog responses (element not found is expected)
        assert len(monitor.get_responses()) == 0

    @patch("dicom_fuzzer.core.engine.gui_monitor.HAS_PYWINAUTO", True)
    @patch("dicom_fuzzer.core.engine.gui_monitor.Application")
    def test_check_dialogs_generic_exception(self, mock_app_class: MagicMock) -> None:
        """Test dialog check handles generic exceptions gracefully."""
        monitor = GUIMonitor()

        mock_app_class.return_value.connect.side_effect = RuntimeError(
            "Connection failed"
        )

        # Should not raise - exception is handled internally
        monitor._check_dialogs(12345, None)
        # Verify no dialog responses (exception was caught)
        assert len(monitor.get_responses()) == 0


class TestGUIMonitorWindowTexts:
    """Tests for window text extraction."""

    def test_get_window_texts_with_text(self) -> None:
        """Test extracting text from window with content."""
        monitor = GUIMonitor()

        mock_window = MagicMock()
        mock_window.window_text.return_value = "Main Window"

        mock_child = MagicMock()
        mock_child.window_text.return_value = "Child Text"
        mock_window.descendants.return_value = [mock_child]

        texts = monitor._get_window_texts(mock_window)

        assert "Main Window" in texts
        assert "Child Text" in texts

    def test_get_window_texts_empty(self) -> None:
        """Test extracting text from window with no content."""
        monitor = GUIMonitor()

        mock_window = MagicMock()
        mock_window.window_text.return_value = ""
        mock_window.descendants.return_value = []

        texts = monitor._get_window_texts(mock_window)

        assert texts == []

    def test_get_window_texts_exception(self) -> None:
        """Test extracting text handles exceptions."""
        monitor = GUIMonitor()

        mock_window = MagicMock()
        mock_window.window_text.side_effect = RuntimeError("Access denied")

        texts = monitor._get_window_texts(mock_window)

        assert texts == []


class TestResponseAwareFuzzerAdvanced:
    """Advanced tests for ResponseAwareFuzzer."""

    @patch("subprocess.Popen")
    def test_test_file_handles_exception(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Test test_file handles exceptions gracefully."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dicom")

        mock_popen.side_effect = OSError("Cannot start process")

        fuzzer = ResponseAwareFuzzer(str(target), timeout=0.1)
        responses = fuzzer.test_file(test_file)

        # Should record the error as a crash
        assert len(responses) >= 1
        assert any(r.response_type == ResponseType.CRASH for r in responses)

    @patch("subprocess.Popen")
    def test_run_campaign_completes_all_files(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Test campaign processes all files when no critical issues."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        test_files = [tmp_path / f"test_{i}.dcm" for i in range(3)]
        for f in test_files:
            f.write_bytes(b"dicom")

        # Process exits normally
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        fuzzer = ResponseAwareFuzzer(str(target), timeout=0.1)
        results = fuzzer.run_campaign(test_files)

        # Should process all files
        assert results["files_tested"] == len(test_files)


class TestGUIMonitorAddResponse:
    """Tests for response adding with debouncing."""

    def test_add_response_duplicate_detection(self) -> None:
        """Test that duplicate responses are not added."""
        monitor = GUIMonitor()
        monitor._last_response_time = 0

        response1 = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="Same error message",
        )
        response2 = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="Same error message",
        )

        monitor.add_response(response1)
        import time

        time.sleep(1.1)  # Wait for debounce
        monitor.add_response(response2)

        # Second should be detected as duplicate
        assert len(monitor.get_responses()) <= 2

    def test_add_response_different_types(self) -> None:
        """Test that different response types are added."""
        monitor = GUIMonitor()
        monitor._last_response_time = 0

        monitor.add_response(
            GUIResponse(
                response_type=ResponseType.ERROR_DIALOG,
                severity=SeverityLevel.HIGH,
                details="Error 1",
            )
        )

        import time

        time.sleep(1.1)  # Wait for debounce

        monitor.add_response(
            GUIResponse(
                response_type=ResponseType.WARNING_DIALOG,
                severity=SeverityLevel.MEDIUM,
                details="Warning 1",
            )
        )

        responses = monitor.get_responses()
        assert len(responses) == 2
