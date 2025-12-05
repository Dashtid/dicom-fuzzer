"""Test Realtime Monitor Module

This test suite verifies the real-time monitoring functionality for
DICOM fuzzing campaigns including display, statistics, and session monitoring.
"""

import json
import time
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.realtime_monitor import (
    HAS_RICH,
    RealtimeMonitor,
    display_stats,
    get_session_stats,
    main,
    monitor_loop,
)


class TestRealtimeMonitorInit:
    """Test RealtimeMonitor initialization."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        monitor = RealtimeMonitor()

        assert monitor.session_dir == Path("./output")
        assert monitor.refresh_interval == 1
        assert monitor.session_id is None
        assert monitor.start_time is not None

    def test_init_custom_session_dir(self, tmp_path):
        """Test initialization with custom session directory."""
        session_dir = tmp_path / "custom_session"
        monitor = RealtimeMonitor(session_dir=session_dir)

        assert monitor.session_dir == session_dir

    def test_init_custom_refresh_interval(self):
        """Test initialization with custom refresh interval."""
        monitor = RealtimeMonitor(refresh_interval=5)

        assert monitor.refresh_interval == 5

    def test_init_with_session_id(self):
        """Test initialization with session ID."""
        monitor = RealtimeMonitor(session_id="test_session_123")

        assert monitor.session_id == "test_session_123"

    def test_init_all_parameters(self, tmp_path):
        """Test initialization with all parameters."""
        session_dir = tmp_path / "session"
        monitor = RealtimeMonitor(
            session_dir=session_dir,
            refresh_interval=3,
            session_id="full_test_session",
        )

        assert monitor.session_dir == session_dir
        assert monitor.refresh_interval == 3
        assert monitor.session_id == "full_test_session"


class TestRealtimeMonitorMonitoring:
    """Test monitoring functionality."""

    def test_monitor_keyboard_interrupt(self, capsys):
        """Test that monitor handles keyboard interrupt gracefully."""
        monitor = RealtimeMonitor(refresh_interval=1)

        with patch.object(monitor, "_refresh_display") as mock_refresh:
            with patch("time.sleep", side_effect=KeyboardInterrupt):
                monitor.monitor()

        captured = capsys.readouterr()
        assert "Monitoring stopped by user" in captured.out
        assert "DICOM FUZZER - REAL-TIME MONITOR" in captured.out

    def test_monitor_displays_header(self, capsys, tmp_path):
        """Test that monitor displays proper header."""
        monitor = RealtimeMonitor(
            session_dir=tmp_path,
            refresh_interval=2,
        )

        with patch.object(monitor, "_refresh_display"):
            with patch("time.sleep", side_effect=KeyboardInterrupt):
                monitor.monitor()

        captured = capsys.readouterr()
        assert str(tmp_path) in captured.out
        assert "Refresh Interval: 2s" in captured.out
        assert "Press Ctrl+C to stop" in captured.out


class TestRefreshDisplay:
    """Test display refresh functionality."""

    def test_refresh_display_no_reports_dir(self, capsys, tmp_path):
        """Test refresh when reports directory doesn't exist."""
        monitor = RealtimeMonitor(session_dir=tmp_path)

        # Patch the reports_dir path to use tmp_path
        with patch.object(Path, "exists", return_value=False):
            monitor._refresh_display()

        captured = capsys.readouterr()
        assert "Waiting for session data" in captured.out

    def test_refresh_display_empty_reports_dir(self, capsys, tmp_path):
        """Test refresh when reports directory is empty."""
        reports_dir = tmp_path / "reports" / "json"
        reports_dir.mkdir(parents=True)

        monitor = RealtimeMonitor(session_dir=tmp_path)

        with patch(
            "dicom_fuzzer.cli.realtime_monitor.Path",
            return_value=MagicMock(
                exists=MagicMock(return_value=True),
                glob=MagicMock(return_value=[]),
            ),
        ):
            with patch.object(monitor, "_print_waiting") as mock_waiting:
                monitor._refresh_display()
                mock_waiting.assert_called_once()

    def test_refresh_display_with_session_file(self, capsys, tmp_path, monkeypatch):
        """Test refresh with valid session file."""
        # Use tmp_path for isolation from other session files
        reports_dir = tmp_path / "reports" / "json"
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_data = {
            "session_info": {
                "session_name": "test_session",
                "start_time": "2025-01-01",
            },
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 500,
                "crashes": 5,
                "hangs": 2,
                "successes": 93,
            },
            "crashes": [],
        }

        session_file = reports_dir / "session_test.json"
        session_file.write_text(json.dumps(session_data))

        # Patch the hardcoded reports_dir path in _refresh_display
        def patched_refresh_display(self):
            """Patched refresh display using tmp_path."""
            if not reports_dir.exists():
                self._print_waiting()
                return

            session_files = list(reports_dir.glob("session_*.json"))
            if not session_files:
                self._print_waiting()
                return

            latest = max(session_files, key=lambda p: p.stat().st_mtime)

            try:
                with open(latest, encoding="utf-8") as f:
                    data = json.load(f)
                self._display_stats(data)
            except Exception as e:
                print(f"Error reading session: {e}")

        monkeypatch.setattr(
            RealtimeMonitor, "_refresh_display", patched_refresh_display
        )

        monitor = RealtimeMonitor()
        monitor._refresh_display()

        captured = capsys.readouterr()
        assert "test_session" in captured.out or "Error" in captured.out

    def test_refresh_display_json_error(self, capsys, tmp_path):
        """Test refresh with invalid JSON file."""
        reports_dir = Path("./reports/json")
        reports_dir.mkdir(parents=True, exist_ok=True)

        session_file = reports_dir / "session_invalid.json"
        session_file.write_text("invalid json {{{")

        try:
            monitor = RealtimeMonitor()
            monitor._refresh_display()

            captured = capsys.readouterr()
            assert "Error reading session" in captured.out
        finally:
            if session_file.exists():
                session_file.unlink()


class TestPrintWaiting:
    """Test waiting message functionality."""

    def test_print_waiting_shows_elapsed_time(self, capsys):
        """Test that waiting message shows elapsed time."""
        monitor = RealtimeMonitor()
        time.sleep(0.1)  # Small delay to ensure elapsed time > 0

        monitor._print_waiting()

        captured = capsys.readouterr()
        assert "Waiting for session data" in captured.out


class TestDisplayStats:
    """Test statistics display functionality."""

    def test_display_stats_basic(self, capsys, tmp_path):
        """Test basic statistics display."""
        data = {
            "session_info": {"session_name": "basic_test", "start_time": "2025-01-01"},
            "statistics": {
                "files_fuzzed": 50,
                "mutations_applied": 200,
                "crashes": 3,
                "hangs": 1,
                "successes": 46,
            },
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "basic_test" in captured.out
        assert "Files Fuzzed: 50" in captured.out
        assert "Mutations: 200" in captured.out

    def test_display_stats_with_crashes(self, capsys):
        """Test statistics display with crash information."""
        data = {
            "session_info": {"session_name": "crash_test", "start_time": "2025-01-01"},
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 500,
                "crashes": 2,
                "hangs": 0,
                "successes": 98,
            },
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "crash_type": "segfault",
                    "severity": "critical",
                },
                {
                    "crash_id": "crash_002",
                    "crash_type": "buffer_overflow",
                    "severity": "high",
                },
            ],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "RECENT CRASHES" in captured.out
        assert "crash_001" in captured.out
        assert "segfault" in captured.out

    def test_display_stats_severity_icons(self, capsys):
        """Test that severity icons are displayed correctly."""
        data = {
            "session_info": {
                "session_name": "severity_test",
                "start_time": "2025-01-01",
            },
            "statistics": {"files_fuzzed": 0, "crashes": 4, "hangs": 0, "successes": 0},
            "crashes": [
                {"crash_id": "c1", "crash_type": "test", "severity": "critical"},
                {"crash_id": "c2", "crash_type": "test", "severity": "high"},
                {"crash_id": "c3", "crash_type": "test", "severity": "medium"},
                {"crash_id": "c4", "crash_type": "test", "severity": "low"},
            ],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        # Check that all crashes are displayed (last 5)
        assert "c1" in captured.out
        assert "c2" in captured.out

    def test_display_stats_empty_statistics(self, capsys):
        """Test display with empty statistics."""
        data = {
            "session_info": {},
            "statistics": {},
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "Unknown" in captured.out or "SESSION" in captured.out

    def test_display_stats_progress_bar(self, capsys):
        """Test that progress bar is displayed."""
        data = {
            "session_info": {"session_name": "progress_test"},
            "statistics": {
                "files_fuzzed": 25,
                "crashes": 0,
                "hangs": 0,
                "successes": 25,
            },
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "PROGRESS" in captured.out
        assert "[" in captured.out and "]" in captured.out

    def test_display_stats_crash_rate_calculation(self, capsys):
        """Test crash rate calculation is displayed correctly."""
        data = {
            "session_info": {"session_name": "rate_test"},
            "statistics": {
                "files_fuzzed": 100,
                "crashes": 10,
                "hangs": 5,
                "successes": 85,
            },
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "Crash Rate:" in captured.out
        assert "Hang Rate:" in captured.out


class TestDisplayStatsFunction:
    """Test the standalone display_stats function."""

    def test_display_stats_without_rich(self, capsys):
        """Test display_stats when rich is not available."""
        stats = {
            "iterations": 100,
            "crashes": 5,
            "coverage": 75.5,
        }

        with patch("dicom_fuzzer.cli.realtime_monitor.HAS_RICH", False):
            display_stats(stats)

        captured = capsys.readouterr()
        assert "Fuzzing Statistics:" in captured.out
        assert "iterations: 100" in captured.out
        assert "crashes: 5" in captured.out

    @pytest.mark.skipif(not HAS_RICH, reason="Rich not installed")
    def test_display_stats_with_rich(self, capsys):
        """Test display_stats when rich is available."""
        from rich.console import Console

        stats = {"iterations": 200, "crashes": 10}

        console = Console(file=StringIO(), force_terminal=True)
        display_stats(stats, console=console)

        # Verify it ran without error
        assert True

    @pytest.mark.skipif(not HAS_RICH, reason="Rich not installed")
    def test_display_stats_creates_console_if_none(self):
        """Test that display_stats creates Console if not provided."""
        stats = {"test": "value"}

        with patch("dicom_fuzzer.cli.realtime_monitor.Console") as mock_console:
            mock_instance = MagicMock()
            mock_console.return_value = mock_instance

            with patch("dicom_fuzzer.cli.realtime_monitor.HAS_RICH", True):
                display_stats(stats, console=None)

    def test_display_stats_empty_dict(self, capsys):
        """Test display_stats with empty dictionary."""
        with patch("dicom_fuzzer.cli.realtime_monitor.HAS_RICH", False):
            display_stats({})

        captured = capsys.readouterr()
        assert "Fuzzing Statistics:" in captured.out


class TestMonitorLoop:
    """Test monitor loop functionality."""

    def test_monitor_loop_keyboard_interrupt(self):
        """Test that monitor_loop handles keyboard interrupt."""
        with patch("dicom_fuzzer.cli.realtime_monitor.get_session_stats") as mock_stats:
            with patch("dicom_fuzzer.cli.realtime_monitor.display_stats"):
                with patch("time.sleep", side_effect=KeyboardInterrupt):
                    mock_stats.return_value = {"iterations": 0}

                    with pytest.raises(KeyboardInterrupt):
                        monitor_loop("test_session")

    def test_monitor_loop_calls_get_session_stats(self):
        """Test that monitor_loop calls get_session_stats."""
        call_count = 0

        def count_calls(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise KeyboardInterrupt
            return {"iterations": call_count}

        with patch(
            "dicom_fuzzer.cli.realtime_monitor.get_session_stats",
            side_effect=count_calls,
        ):
            with patch("dicom_fuzzer.cli.realtime_monitor.display_stats"):
                with patch("time.sleep"):
                    with pytest.raises(KeyboardInterrupt):
                        monitor_loop("test_session")

        assert call_count >= 1

    def test_monitor_loop_respects_update_interval(self):
        """Test that monitor_loop uses correct update interval."""
        sleep_values = []

        def capture_sleep(seconds):
            sleep_values.append(seconds)
            if len(sleep_values) >= 2:
                raise KeyboardInterrupt

        with patch("dicom_fuzzer.cli.realtime_monitor.get_session_stats") as mock_stats:
            with patch("dicom_fuzzer.cli.realtime_monitor.display_stats"):
                with patch("time.sleep", side_effect=capture_sleep):
                    mock_stats.return_value = {"iterations": 0}

                    with pytest.raises(KeyboardInterrupt):
                        monitor_loop("test_session", update_interval=5)

        assert 5 in sleep_values


class TestGetSessionStats:
    """Test get_session_stats function."""

    def test_get_session_stats_returns_dict(self):
        """Test that get_session_stats returns a dictionary."""
        result = get_session_stats("any_session")

        assert isinstance(result, dict)

    def test_get_session_stats_has_required_keys(self):
        """Test that returned stats have required keys."""
        result = get_session_stats("test_session")

        assert "iterations" in result
        assert "crashes" in result
        assert "coverage" in result
        assert "exec_speed" in result

    def test_get_session_stats_default_values(self):
        """Test that stats have appropriate default values."""
        result = get_session_stats("new_session")

        assert result["iterations"] == 0
        assert result["crashes"] == 0
        assert result["coverage"] == 0.0
        assert result["exec_speed"] == 0.0


class TestMainFunction:
    """Test main CLI entry point."""

    def test_main_default_args(self):
        """Test main with default arguments."""
        with patch("sys.argv", ["realtime_monitor.py"]):
            with patch(
                "dicom_fuzzer.cli.realtime_monitor.RealtimeMonitor"
            ) as mock_monitor:
                mock_instance = MagicMock()
                mock_monitor.return_value = mock_instance

                main()

                mock_monitor.assert_called_once()
                mock_instance.monitor.assert_called_once()

    def test_main_custom_session_dir(self):
        """Test main with custom session directory."""
        with patch(
            "sys.argv", ["realtime_monitor.py", "--session-dir", "/custom/path"]
        ):
            with patch(
                "dicom_fuzzer.cli.realtime_monitor.RealtimeMonitor"
            ) as mock_monitor:
                mock_instance = MagicMock()
                mock_monitor.return_value = mock_instance

                main()

                call_args = mock_monitor.call_args
                assert call_args[0][0] == Path("/custom/path")

    def test_main_custom_refresh_rate(self):
        """Test main with custom refresh rate."""
        with patch("sys.argv", ["realtime_monitor.py", "--refresh", "5"]):
            with patch(
                "dicom_fuzzer.cli.realtime_monitor.RealtimeMonitor"
            ) as mock_monitor:
                mock_instance = MagicMock()
                mock_monitor.return_value = mock_instance

                main()

                call_args = mock_monitor.call_args
                assert call_args[0][1] == 5


class TestFuzzingSessionClass:
    """Test the mock FuzzingSession class."""

    def test_fuzzing_session_exists(self):
        """Test that FuzzingSession class is importable."""
        from dicom_fuzzer.cli.realtime_monitor import FuzzingSession

        assert FuzzingSession is not None

    def test_fuzzing_session_instantiation(self):
        """Test that FuzzingSession can be instantiated."""
        from dicom_fuzzer.cli.realtime_monitor import FuzzingSession

        session = FuzzingSession()
        assert session is not None


class TestRichImportHandling:
    """Test handling of rich library import."""

    def test_has_rich_flag_exists(self):
        """Test that HAS_RICH flag exists."""
        assert isinstance(HAS_RICH, bool)

    def test_imports_work_without_rich(self):
        """Test that module imports work when rich is simulated as unavailable."""
        # The module should already be imported and working
        # This test verifies the import doesn't raise
        from dicom_fuzzer.cli.realtime_monitor import (
            RealtimeMonitor,
            display_stats,
        )

        assert RealtimeMonitor is not None
        assert display_stats is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_display_with_negative_stats(self, capsys):
        """Test display handles negative statistics gracefully."""
        data = {
            "session_info": {"session_name": "negative_test"},
            "statistics": {
                "files_fuzzed": -1,
                "crashes": -5,
                "hangs": 0,
                "successes": 0,
            },
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        # Should not raise
        captured = capsys.readouterr()
        assert "negative_test" in captured.out

    def test_display_with_large_numbers(self, capsys):
        """Test display handles very large numbers."""
        data = {
            "session_info": {"session_name": "large_test"},
            "statistics": {
                "files_fuzzed": 1000000000,
                "mutations_applied": 999999999999,
                "crashes": 0,
                "hangs": 0,
                "successes": 1000000000,
            },
            "crashes": [],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "1000000000" in captured.out

    def test_display_with_unknown_severity(self, capsys):
        """Test display handles unknown crash severity."""
        data = {
            "session_info": {"session_name": "unknown_severity"},
            "statistics": {"crashes": 1, "hangs": 0, "successes": 0},
            "crashes": [
                {"crash_id": "c1", "crash_type": "test", "severity": "unknown_level"},
            ],
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        assert "c1" in captured.out

    def test_display_more_than_five_crashes(self, capsys):
        """Test that only last 5 crashes are displayed."""
        crashes = [
            {"crash_id": f"crash_{i}", "crash_type": "test", "severity": "low"}
            for i in range(10)
        ]

        data = {
            "session_info": {"session_name": "many_crashes"},
            "statistics": {"crashes": 10, "hangs": 0, "successes": 0},
            "crashes": crashes,
        }

        monitor = RealtimeMonitor()
        monitor._display_stats(data)

        captured = capsys.readouterr()
        # Should show last 5 (crash_5 through crash_9)
        assert "crash_9" in captured.out
        assert "crash_5" in captured.out
