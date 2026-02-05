"""Additional tests for gui_monitor.py coverage.

Coverage target: 67% -> 80%+
Tests GUI monitoring for DICOM viewer fuzzing.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.engine.gui_monitor import (
    HAS_PSUTIL,
    HAS_PYWINAUTO,
    GUIMonitor,
)
from dicom_fuzzer.core.engine.gui_monitor_types import (
    GUIResponse,
    MonitorConfig,
    ResponseType,
    SeverityLevel,
)


class TestMonitorConfig:
    """Tests for MonitorConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = MonitorConfig()
        assert config.poll_interval > 0
        assert config.memory_threshold_mb > 0
        assert isinstance(config.error_patterns, list)
        assert isinstance(config.warning_patterns, list)

    def test_custom_config(self, tmp_path: Path) -> None:
        """Test custom configuration."""
        config = MonitorConfig(
            poll_interval=0.5,
            memory_threshold_mb=2048,
        )
        assert config.poll_interval == 0.5
        assert config.memory_threshold_mb == 2048


class TestGUIResponse:
    """Tests for GUIResponse dataclass."""

    def test_response_creation(self) -> None:
        """Test creating a GUI response."""
        response = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="An error occurred",
        )
        assert response.response_type == ResponseType.ERROR_DIALOG
        assert response.severity == SeverityLevel.HIGH
        assert isinstance(response.timestamp, datetime)

    def test_response_optional_fields(self) -> None:
        """Test response with optional fields."""
        response = GUIResponse(
            response_type=ResponseType.WARNING_DIALOG,
            severity=SeverityLevel.MEDIUM,
            details="Warning message",
            window_title="Test App",
            screenshot_path=Path("/screenshots/warning.png"),
        )
        assert response.window_title == "Test App"
        assert response.screenshot_path == Path("/screenshots/warning.png")

    def test_response_to_dict(self) -> None:
        """Test converting response to dict."""
        response = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="Test error",
            test_file=Path("/test/file.dcm"),
        )
        d = response.to_dict()
        assert d["severity"] == "high"
        assert d["details"] == "Test error"


class TestGUIMonitorInit:
    """Tests for GUIMonitor initialization."""

    def test_init_default_config(self) -> None:
        """Test initialization with default config."""
        monitor = GUIMonitor()
        assert monitor.config is not None
        assert monitor._monitoring is False
        assert monitor._responses == []

    def test_init_custom_config(self, tmp_path: Path) -> None:
        """Test initialization with custom config."""
        config = MonitorConfig(
            poll_interval=0.1,
        )
        monitor = GUIMonitor(config)
        assert monitor.config.poll_interval == 0.1

    def test_init_compiles_patterns(self) -> None:
        """Test that regex patterns are compiled."""
        config = MonitorConfig(
            error_patterns=["Error: .*", "Exception: .*"],
            warning_patterns=["Warning: .*"],
        )
        monitor = GUIMonitor(config)
        assert len(monitor._error_patterns) == 2
        assert len(monitor._warning_patterns) == 1


class TestGUIMonitorBasicOperations:
    """Tests for basic GUIMonitor operations."""

    @pytest.fixture
    def monitor(self) -> GUIMonitor:
        """Create a monitor instance."""
        return GUIMonitor(MonitorConfig(poll_interval=0.1))

    def test_start_monitoring(self, monitor: GUIMonitor) -> None:
        """Test starting monitoring."""
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None

        with patch.object(monitor, "_monitor_loop"):
            monitor.start_monitoring(mock_process)

            assert monitor._monitoring is True
            monitor.stop_monitoring()

    def test_start_monitoring_already_running(self, monitor: GUIMonitor) -> None:
        """Test starting monitoring when already running."""
        monitor._monitoring = True

        mock_process = MagicMock()
        # Should log warning and return without starting a new thread
        monitor.start_monitoring(mock_process)

        # Verify monitoring flag unchanged (still True)
        assert monitor._monitoring is True

        # Reset
        monitor._monitoring = False

    def test_stop_monitoring(self, monitor: GUIMonitor) -> None:
        """Test stopping monitoring."""
        monitor._monitoring = True
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = False
        monitor._monitor_thread = mock_thread

        monitor.stop_monitoring()

        assert monitor._monitoring is False

    def test_stop_monitoring_waits_for_thread(self, monitor: GUIMonitor) -> None:
        """Test stop_monitoring waits for thread."""
        monitor._monitoring = True
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._monitor_thread = mock_thread

        monitor.stop_monitoring()

        mock_thread.join.assert_called_once_with(timeout=2.0)


class TestGUIMonitorResponses:
    """Tests for response handling."""

    @pytest.fixture
    def monitor(self) -> GUIMonitor:
        """Create a monitor instance."""
        return GUIMonitor()

    def test_get_responses_empty(self, monitor: GUIMonitor) -> None:
        """Test getting responses when none recorded."""
        responses = monitor.get_responses()
        assert responses == []

    def test_add_response(self, monitor: GUIMonitor) -> None:
        """Test adding a response."""
        response = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="Test error",
        )

        with monitor._lock:
            monitor._responses.append(response)

        responses = monitor.get_responses()
        assert len(responses) == 1
        assert responses[0].details == "Test error"

    def test_clear_responses(self, monitor: GUIMonitor) -> None:
        """Test clearing responses."""
        monitor._responses = [
            GUIResponse(
                response_type=ResponseType.ERROR_DIALOG,
                severity=SeverityLevel.LOW,
                details="Test",
            )
        ]

        monitor.clear_responses()

        assert monitor._responses == []


class TestGUIMonitorSummary:
    """Tests for get_summary method."""

    @pytest.fixture
    def monitor(self) -> GUIMonitor:
        """Create a monitor instance."""
        return GUIMonitor()

    def test_get_summary_empty(self, monitor: GUIMonitor) -> None:
        """Test summary with no responses."""
        summary = monitor.get_summary()
        assert isinstance(summary, dict)
        assert "total_responses" in summary
        assert summary["total_responses"] == 0

    def test_get_summary_with_responses(self, monitor: GUIMonitor) -> None:
        """Test summary with responses."""
        monitor._responses = [
            GUIResponse(
                response_type=ResponseType.ERROR_DIALOG,
                severity=SeverityLevel.HIGH,
            ),
            GUIResponse(
                response_type=ResponseType.WARNING_DIALOG,
                severity=SeverityLevel.MEDIUM,
            ),
        ]
        summary = monitor.get_summary()
        assert summary["total_responses"] == 2


class TestResponseType:
    """Tests for ResponseType enum."""

    def test_all_response_types(self) -> None:
        """Test all response types exist."""
        assert ResponseType.ERROR_DIALOG is not None
        assert ResponseType.WARNING_DIALOG is not None
        assert ResponseType.CRASH is not None
        assert ResponseType.HANG is not None
        assert ResponseType.MEMORY_SPIKE is not None


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_all_severity_levels(self) -> None:
        """Test all severity levels exist."""
        assert SeverityLevel.LOW is not None
        assert SeverityLevel.MEDIUM is not None
        assert SeverityLevel.HIGH is not None
        assert SeverityLevel.CRITICAL is not None


class TestGUIMonitorAvailability:
    """Tests for dependency availability."""

    def test_has_psutil_flag(self) -> None:
        """Test HAS_PSUTIL flag."""
        assert isinstance(HAS_PSUTIL, bool)
        # psutil should be available in test environment
        assert HAS_PSUTIL is True

    def test_has_pywinauto_flag(self) -> None:
        """Test HAS_PYWINAUTO flag."""
        assert isinstance(HAS_PYWINAUTO, bool)
        # May or may not be available
