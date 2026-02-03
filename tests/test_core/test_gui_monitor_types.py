"""Tests for GUI Monitor Types module."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.engine.gui_monitor_types import (
    GUIResponse,
    MonitorConfig,
    ResponseType,
    SeverityLevel,
)


class TestResponseType:
    """Tests for ResponseType enum."""

    def test_all_values_exist(self) -> None:
        """Verify all response types exist."""
        expected = [
            "NORMAL",
            "ERROR_DIALOG",
            "WARNING_DIALOG",
            "CRASH",
            "HANG",
            "MEMORY_SPIKE",
            "RENDER_ANOMALY",
            "RESOURCE_EXHAUSTION",
        ]
        for name in expected:
            assert hasattr(ResponseType, name)

    def test_enum_values(self) -> None:
        """Verify enum values are strings."""
        assert ResponseType.NORMAL.value == "normal"
        assert ResponseType.ERROR_DIALOG.value == "error_dialog"
        assert ResponseType.CRASH.value == "crash"

    def test_member_count(self) -> None:
        """Verify the correct number of response types."""
        assert len(ResponseType) == 8


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_all_values_exist(self) -> None:
        """Verify all severity levels exist."""
        expected = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
        for name in expected:
            assert hasattr(SeverityLevel, name)

    def test_enum_values(self) -> None:
        """Verify enum values are strings."""
        assert SeverityLevel.INFO.value == "info"
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.UNKNOWN.value == "unknown"

    def test_member_count(self) -> None:
        """Verify the correct number of severity levels."""
        # After unification: INFO, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
        assert len(SeverityLevel) == 6


class TestGUIResponse:
    """Tests for GUIResponse dataclass."""

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        response = GUIResponse(
            response_type=ResponseType.NORMAL,
            severity=SeverityLevel.INFO,
        )
        assert response.test_file is None
        assert response.details == ""
        assert response.window_title == ""
        assert response.dialog_text == ""
        assert response.memory_usage_mb == 0.0
        assert response.screenshot_path is None
        assert isinstance(response.timestamp, datetime)

    def test_full_initialization(self) -> None:
        """Test full initialization with all values."""
        test_file = Path("/test/file.dcm")
        screenshot = Path("/screenshots/error.png")

        response = GUIResponse(
            response_type=ResponseType.CRASH,
            severity=SeverityLevel.CRITICAL,
            test_file=test_file,
            details="Application crashed",
            window_title="Error",
            dialog_text="Access violation",
            memory_usage_mb=1024.5,
            screenshot_path=screenshot,
        )

        assert response.response_type == ResponseType.CRASH
        assert response.severity == SeverityLevel.CRITICAL
        assert response.test_file == test_file
        assert response.details == "Application crashed"
        assert response.memory_usage_mb == 1024.5

    def test_to_dict(self) -> None:
        """Test to_dict method."""
        response = GUIResponse(
            response_type=ResponseType.WARNING_DIALOG,
            severity=SeverityLevel.MEDIUM,
            test_file=Path("/test/file.dcm"),
            details="Warning detected",
        )
        d = response.to_dict()

        assert d["response_type"] == "warning_dialog"
        assert d["severity"] == "medium"
        assert d["details"] == "Warning detected"
        assert "timestamp" in d

    def test_to_dict_none_values(self) -> None:
        """Test to_dict with None values."""
        response = GUIResponse(
            response_type=ResponseType.NORMAL,
            severity=SeverityLevel.INFO,
        )
        d = response.to_dict()

        assert d["test_file"] is None
        assert d["screenshot_path"] is None


class TestMonitorConfig:
    """Tests for MonitorConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = MonitorConfig()

        assert config.poll_interval == 0.1
        assert config.memory_threshold_mb == 2048.0
        assert config.memory_spike_percent == 50.0
        assert config.hang_timeout == 5.0
        assert config.capture_screenshots is True
        assert len(config.error_patterns) > 0
        assert len(config.warning_patterns) > 0

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = MonitorConfig(
            poll_interval=0.5,
            memory_threshold_mb=4096.0,
            hang_timeout=10.0,
            capture_screenshots=False,
        )

        assert config.poll_interval == 0.5
        assert config.memory_threshold_mb == 4096.0
        assert config.hang_timeout == 10.0
        assert config.capture_screenshots is False

    def test_error_patterns_content(self) -> None:
        """Verify error patterns contain expected patterns."""
        config = MonitorConfig()
        patterns_text = " ".join(config.error_patterns)

        assert "error" in patterns_text.lower()
        assert "exception" in patterns_text.lower()
        assert "failed" in patterns_text.lower()

    def test_warning_patterns_content(self) -> None:
        """Verify warning patterns contain expected patterns."""
        config = MonitorConfig()
        patterns_text = " ".join(config.warning_patterns)

        assert "warning" in patterns_text.lower()
        assert "caution" in patterns_text.lower()


class TestBackwardCompatibility:
    """Test backward compatibility with gui_monitor module."""

    def test_imports_from_gui_monitor(self) -> None:
        """Verify types can be imported from gui_monitor."""
        from dicom_fuzzer.core.engine.gui_monitor import (
            GUIResponse as Response,
        )
        from dicom_fuzzer.core.engine.gui_monitor import (
            MonitorConfig as Config,
        )
        from dicom_fuzzer.core.engine.gui_monitor import (
            ResponseType as RType,
        )
        from dicom_fuzzer.core.engine.gui_monitor import (
            SeverityLevel as SLevel,
        )

        assert RType is ResponseType
        assert SLevel is SeverityLevel
        assert Response is GUIResponse
        assert Config is MonitorConfig

    def test_imports_from_core(self) -> None:
        """Verify types can be imported from core __init__."""
        from dicom_fuzzer.core import (
            GUIResponse as Response,
        )
        from dicom_fuzzer.core import (
            MonitorConfig as Config,
        )
        from dicom_fuzzer.core import (
            ResponseType as RType,
        )
        from dicom_fuzzer.core import (
            SeverityLevel as SLevel,
        )

        assert RType is ResponseType
        assert SLevel is SeverityLevel
        assert Response is GUIResponse
        assert Config is MonitorConfig
