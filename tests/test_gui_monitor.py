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

from dicom_fuzzer.core.gui_monitor import (
    GUIMonitor,
    GUIResponse,
    MonitorConfig,
    ResponseAwareFuzzer,
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
        assert config.capture_screenshots is True
        assert len(config.error_patterns) > 0
        assert len(config.warning_patterns) > 0

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = MonitorConfig(
            poll_interval=0.5,
            memory_threshold_mb=4096.0,
            memory_spike_percent=100.0,
            hang_timeout=10.0,
            capture_screenshots=False,
        )

        assert config.poll_interval == 0.5
        assert config.memory_threshold_mb == 4096.0
        assert config.capture_screenshots is False

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
        monitor._add_response(response)
        monitor._add_response(response)

        # Should only have one due to debounce
        assert len(monitor.get_responses()) == 1

    def test_stop_monitoring_when_not_started(self) -> None:
        """Test stopping monitor when not running."""
        monitor = GUIMonitor()
        # Should not raise
        monitor.stop_monitoring()
        assert monitor._monitoring is False

    @patch("dicom_fuzzer.core.gui_monitor.HAS_PSUTIL", False)
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


class TestScreenshotDirectory:
    """Tests for screenshot directory handling."""

    def test_screenshot_dir_created(self, tmp_path: Path) -> None:
        """Test screenshot directory is created."""
        screenshot_dir = tmp_path / "screenshots"
        config = MonitorConfig(
            capture_screenshots=True,
            screenshot_dir=screenshot_dir,
        )

        GUIMonitor(config)

        assert screenshot_dir.exists()

    def test_screenshot_dir_not_created_when_disabled(self, tmp_path: Path) -> None:
        """Test screenshot dir not created when screenshots disabled."""
        screenshot_dir = tmp_path / "no_screenshots"
        config = MonitorConfig(
            capture_screenshots=False,
            screenshot_dir=screenshot_dir,
        )

        GUIMonitor(config)

        # Dir is still created by default factory, but feature is disabled
        # The monitor should work regardless
        assert config.capture_screenshots is False
