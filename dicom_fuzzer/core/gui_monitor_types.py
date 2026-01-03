"""Types and constants for GUI monitoring.

This module contains the shared types used by the GUI monitoring components:
- ResponseType: Types of responses detected from GUI applications
- SeverityLevel: Severity levels for detected issues
- GUIResponse: Response record dataclass
- MonitorConfig: Configuration for GUI monitoring

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class ResponseType(Enum):
    """Types of responses detected from GUI applications."""

    NORMAL = "normal"  # App running normally
    ERROR_DIALOG = "error_dialog"  # Error dialog detected
    WARNING_DIALOG = "warning_dialog"  # Warning dialog detected
    CRASH = "crash"  # Application crashed
    HANG = "hang"  # Application not responding
    MEMORY_SPIKE = "memory_spike"  # Abnormal memory usage
    RENDER_ANOMALY = "render_anomaly"  # Rendering issue detected
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # Out of resources


class SeverityLevel(Enum):
    """Severity levels for detected issues."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GUIResponse:
    """Represents a response detected from a GUI application.

    Attributes:
        response_type: Type of response detected
        severity: Severity level of the response
        timestamp: When the response was detected
        test_file: File that triggered this response
        details: Additional details about the response
        window_title: Title of the window that generated the response
        dialog_text: Text content of any dialog detected
        memory_usage_mb: Memory usage at time of detection
        screenshot_path: Path to screenshot if captured

    """

    response_type: ResponseType
    severity: SeverityLevel
    timestamp: datetime = field(default_factory=datetime.now)
    test_file: Path | None = None
    details: str = ""
    window_title: str = ""
    dialog_text: str = ""
    memory_usage_mb: float = 0.0
    screenshot_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "response_type": self.response_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "test_file": str(self.test_file) if self.test_file else None,
            "details": self.details,
            "window_title": self.window_title,
            "dialog_text": self.dialog_text,
            "memory_usage_mb": self.memory_usage_mb,
            "screenshot_path": str(self.screenshot_path)
            if self.screenshot_path
            else None,
        }


@dataclass
class MonitorConfig:
    """Configuration for GUI monitoring.

    Attributes:
        poll_interval: Seconds between monitoring checks
        memory_threshold_mb: Memory usage that triggers alert
        memory_spike_percent: Percentage increase that triggers spike alert
        hang_timeout: Seconds of unresponsiveness before hang detection
        capture_screenshots: Whether to capture screenshots of issues
        screenshot_dir: Directory to save screenshots
        error_patterns: Regex patterns to detect in dialog text
        warning_patterns: Regex patterns for warning dialogs

    """

    poll_interval: float = 0.1
    memory_threshold_mb: float = 2048.0
    memory_spike_percent: float = 50.0
    hang_timeout: float = 5.0
    capture_screenshots: bool = True
    screenshot_dir: Path = field(
        default_factory=lambda: Path("./artifacts/screenshots")
    )
    error_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)error",
            r"(?i)exception",
            r"(?i)failed",
            r"(?i)cannot\s+open",
            r"(?i)invalid\s+file",
            r"(?i)corrupt",
            r"(?i)access\s+violation",
            r"(?i)segmentation\s+fault",
            r"(?i)out\s+of\s+memory",
            r"(?i)stack\s+overflow",
            r"(?i)buffer\s+overflow",
        ]
    )
    warning_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)warning",
            r"(?i)caution",
            r"(?i)could\s+not",
            r"(?i)unable\s+to",
            r"(?i)unexpected",
            r"(?i)unsupported",
        ]
    )


# Re-export all public symbols
__all__ = [
    "ResponseType",
    "SeverityLevel",
    "GUIResponse",
    "MonitorConfig",
]
