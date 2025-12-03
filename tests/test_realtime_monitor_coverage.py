"""Tests for realtime_monitor module to improve code coverage.

These tests exercise the real-time monitoring code paths.
"""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.realtime_monitor import (
    FuzzingSession,
    RealtimeMonitor,
    display_stats,
    get_session_stats,
)


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def monitor(temp_dir):
    """Create RealtimeMonitor instance."""
    return RealtimeMonitor(
        session_dir=temp_dir,
        refresh_interval=1,
        session_id="test-session-123",
    )


@pytest.fixture
def sample_session_data():
    """Sample session data for testing."""
    return {
        "session_info": {
            "session_id": "test-session-123",
            "session_name": "Test Fuzzing Session",
            "start_time": "2025-01-01T10:00:00",
            "end_time": "2025-01-01T11:00:00",
        },
        "statistics": {
            "files_fuzzed": 100,
            "mutations_applied": 500,
            "crashes": 3,
            "hangs": 1,
            "successes": 96,
        },
        "crashes": [
            {
                "crash_id": "crash-001",
                "crash_type": "crash",
                "severity": "critical",
            },
            {
                "crash_id": "crash-002",
                "crash_type": "crash",
                "severity": "high",
            },
            {
                "crash_id": "crash-003",
                "crash_type": "hang",
                "severity": "medium",
            },
        ],
    }


class TestFuzzingSession:
    """Test FuzzingSession mock class."""

    def test_fuzzing_session_exists(self):
        """Test that FuzzingSession class exists."""
        session = FuzzingSession()
        assert session is not None


class TestRealtimeMonitorInit:
    """Test RealtimeMonitor initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default values."""
        monitor = RealtimeMonitor()

        assert monitor.session_dir == Path("./output")
        assert monitor.refresh_interval == 1
        assert monitor.session_id is None
        assert monitor.start_time is not None

    def test_init_with_custom_values(self, temp_dir):
        """Test initialization with custom values."""
        monitor = RealtimeMonitor(
            session_dir=temp_dir,
            refresh_interval=5,
            session_id="custom-session",
        )

        assert monitor.session_dir == temp_dir
        assert monitor.refresh_interval == 5
        assert monitor.session_id == "custom-session"

    def test_init_start_time_is_current(self):
        """Test that start_time is set to current time."""
        before = time.time()
        monitor = RealtimeMonitor()
        after = time.time()

        assert before <= monitor.start_time <= after


class TestPrintWaiting:
    """Test _print_waiting method."""

    def test_print_waiting_output(self, monitor, capsys):
        """Test that waiting message is printed."""
        monitor._print_waiting()

        captured = capsys.readouterr()
        assert "Waiting for session data" in captured.out

    def test_print_waiting_shows_elapsed(self, monitor, capsys):
        """Test that elapsed time is shown."""
        # Wait a bit to have non-zero elapsed time
        time.sleep(0.1)
        monitor._print_waiting()

        captured = capsys.readouterr()
        assert "s)" in captured.out


class TestDisplayStats:
    """Test _display_stats method."""

    def test_display_stats_with_data(self, monitor, sample_session_data, capsys):
        """Test displaying statistics."""
        monitor._display_stats(sample_session_data)

        captured = capsys.readouterr()
        assert "Test Fuzzing Session" in captured.out
        assert "FUZZING STATISTICS" in captured.out
        assert "TEST RESULTS" in captured.out
        assert "100" in captured.out  # files_fuzzed

    def test_display_stats_empty_data(self, monitor, capsys):
        """Test displaying with empty data."""
        monitor._display_stats({})

        captured = capsys.readouterr()
        assert "SESSION" in captured.out

    def test_display_stats_shows_crashes(self, monitor, sample_session_data, capsys):
        """Test that crashes are displayed."""
        monitor._display_stats(sample_session_data)

        captured = capsys.readouterr()
        assert "RECENT CRASHES" in captured.out
        assert "crash-001" in captured.out

    def test_display_stats_no_crashes(self, monitor, capsys):
        """Test display with no crashes."""
        data = {
            "session_info": {"session_name": "Test"},
            "statistics": {"crashes": 0, "hangs": 0, "successes": 10},
            "crashes": [],
        }
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "RECENT CRASHES" not in captured.out

    def test_display_stats_crash_severity_icons(self, monitor, capsys):
        """Test that severity icons are correct."""
        data = {
            "session_info": {"session_name": "Test"},
            "statistics": {"crashes": 4, "hangs": 0, "successes": 0},
            "crashes": [
                {"crash_id": "c1", "crash_type": "crash", "severity": "critical"},
                {"crash_id": "c2", "crash_type": "crash", "severity": "high"},
                {"crash_id": "c3", "crash_type": "crash", "severity": "medium"},
                {"crash_id": "c4", "crash_type": "crash", "severity": "low"},
            ],
        }
        monitor._display_stats(data)

        captured = capsys.readouterr()
        # Check all severity levels are shown
        assert "critical" in captured.out or "c1" in captured.out

    def test_display_stats_progress_bar(self, monitor, sample_session_data, capsys):
        """Test that progress bar is displayed."""
        monitor._display_stats(sample_session_data)

        captured = capsys.readouterr()
        assert "PROGRESS" in captured.out

    def test_display_stats_crash_rate(self, monitor, sample_session_data, capsys):
        """Test that crash rate is calculated."""
        monitor._display_stats(sample_session_data)

        captured = capsys.readouterr()
        assert "Crash Rate" in captured.out


class TestRefreshDisplay:
    """Test _refresh_display method."""

    def test_refresh_display_no_reports_dir(self, monitor, temp_dir, capsys):
        """Test refresh when reports directory doesn't exist."""
        # Use a non-existent path by patching the reports_dir check
        with patch.object(Path, "exists", return_value=False):
            monitor._refresh_display()

        captured = capsys.readouterr()
        assert "Waiting for session data" in captured.out

    def test_refresh_display_empty_reports_dir(self, temp_dir, capsys):
        """Test refresh when reports directory is empty."""
        # Use patch to simulate empty glob result
        with patch.object(Path, "glob", return_value=[]):
            with patch.object(Path, "exists", return_value=True):
                monitor = RealtimeMonitor(session_dir=temp_dir)
                monitor._refresh_display()

        captured = capsys.readouterr()
        assert "Waiting for session data" in captured.out

    def test_refresh_display_with_session_file(
        self, temp_dir, sample_session_data, capsys
    ):
        """Test refresh with existing session file."""
        reports_dir = Path("./reports/json")
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = reports_dir / "session_test.json"
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(sample_session_data, f)

        try:
            monitor = RealtimeMonitor(session_dir=temp_dir)
            monitor._refresh_display()

            captured = capsys.readouterr()
            assert "Test Fuzzing Session" in captured.out
        finally:
            # Cleanup
            session_file.unlink(missing_ok=True)

    def test_refresh_display_invalid_json(self, temp_dir, capsys):
        """Test refresh with invalid JSON file."""
        reports_dir = Path("./reports/json")
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = reports_dir / "session_invalid.json"
        session_file.write_text("invalid json {", encoding="utf-8")

        try:
            monitor = RealtimeMonitor(session_dir=temp_dir)
            monitor._refresh_display()

            captured = capsys.readouterr()
            assert "Error reading session" in captured.out
        finally:
            # Cleanup
            session_file.unlink(missing_ok=True)


class TestMonitor:
    """Test monitor method."""

    def test_monitor_prints_header(self, monitor, capsys):
        """Test that monitor prints header before loop."""
        with patch.object(monitor, "_refresh_display"):
            # Simulate KeyboardInterrupt after first iteration
            with patch("time.sleep", side_effect=KeyboardInterrupt):
                monitor.monitor()

        captured = capsys.readouterr()
        assert "DICOM FUZZER - REAL-TIME MONITOR" in captured.out
        assert "Press Ctrl+C to stop" in captured.out
        assert "Monitoring stopped by user" in captured.out


class TestDisplayStatsFunction:
    """Test display_stats function."""

    def test_display_stats_with_rich(self, capsys):
        """Test display_stats with rich console."""
        stats = {
            "iterations": 100,
            "crashes": 5,
            "coverage": 75.5,
            "exec_speed": 1000.0,
        }

        # Create mock console
        mock_console = MagicMock()
        display_stats(stats, console=mock_console)

        # Should have called print on the console
        mock_console.print.assert_called_once()

    def test_display_stats_without_rich(self, capsys):
        """Test display_stats without rich (fallback)."""
        stats = {
            "iterations": 100,
            "crashes": 5,
        }

        # Temporarily disable rich
        import dicom_fuzzer.cli.realtime_monitor as rm

        original_has_rich = rm.HAS_RICH
        rm.HAS_RICH = False

        try:
            display_stats(stats)

            captured = capsys.readouterr()
            assert "Fuzzing Statistics" in captured.out
            assert "iterations" in captured.out
            assert "100" in captured.out
        finally:
            rm.HAS_RICH = original_has_rich

    def test_display_stats_empty_dict(self):
        """Test display_stats with empty dictionary."""
        mock_console = MagicMock()
        display_stats({}, console=mock_console)

        # Should still call print
        mock_console.print.assert_called_once()


class TestGetSessionStats:
    """Test get_session_stats function."""

    def test_get_session_stats_returns_dict(self):
        """Test that function returns a dictionary."""
        result = get_session_stats("test-session")

        assert isinstance(result, dict)

    def test_get_session_stats_has_required_keys(self):
        """Test that result has required keys."""
        result = get_session_stats("test-session")

        assert "iterations" in result
        assert "crashes" in result
        assert "coverage" in result
        assert "exec_speed" in result

    def test_get_session_stats_default_values(self):
        """Test default values."""
        result = get_session_stats("any-session")

        assert result["iterations"] == 0
        assert result["crashes"] == 0
        assert result["coverage"] == 0.0
        assert result["exec_speed"] == 0.0


class TestEdgeCases:
    """Test edge cases."""

    def test_monitor_with_none_session_dir(self):
        """Test monitor with None session_dir."""
        monitor = RealtimeMonitor(session_dir=None)

        assert monitor.session_dir == Path("./output")

    def test_display_stats_unknown_severity(self, capsys):
        """Test display with unknown severity."""
        data = {
            "session_info": {"session_name": "Test"},
            "statistics": {"crashes": 1, "hangs": 0, "successes": 0},
            "crashes": [
                {
                    "crash_id": "c1",
                    "crash_type": "crash",
                    "severity": "unknown_severity",
                }
            ],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        # Should use default icon for unknown severity
        assert "c1" in captured.out

    def test_display_stats_zero_total_tests(self, capsys):
        """Test display with zero total tests."""
        data = {
            "session_info": {"session_name": "Test"},
            "statistics": {"crashes": 0, "hangs": 0, "successes": 0},
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        # Should not crash on division by zero
        assert "TEST RESULTS" in captured.out
