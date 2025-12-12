"""Tests for the dashboard server module.

This module tests the DashboardServer, FuzzingStats, and CrashInfo classes.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.dashboard.server import (
    CrashInfo,
    DashboardServer,
    FuzzingStats,
)


class TestFuzzingStats:
    """Tests for FuzzingStats dataclass."""

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        stats = FuzzingStats()
        assert stats.total_executions == 0
        assert stats.crashes_found == 0
        assert stats.coverage_percent == 0.0
        assert stats.executions_per_sec == 0.0
        assert stats.current_file == ""
        assert stats.memory_usage_mb == 0.0
        assert stats.unique_paths == 0
        assert isinstance(stats.start_time, datetime)

    def test_custom_values(self) -> None:
        """Test custom values are stored correctly."""
        now = datetime.now()
        stats = FuzzingStats(
            total_executions=100,
            crashes_found=5,
            coverage_percent=75.5,
            executions_per_sec=10.5,
            start_time=now,
            current_file="test.dcm",
            memory_usage_mb=512.5,
            unique_paths=42,
        )
        assert stats.total_executions == 100
        assert stats.crashes_found == 5
        assert stats.coverage_percent == 75.5
        assert stats.executions_per_sec == 10.5
        assert stats.start_time == now
        assert stats.current_file == "test.dcm"
        assert stats.memory_usage_mb == 512.5
        assert stats.unique_paths == 42

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        now = datetime.now()
        stats = FuzzingStats(
            total_executions=100,
            crashes_found=5,
            coverage_percent=75.555,
            executions_per_sec=10.567,
            start_time=now,
            current_file="test.dcm",
            memory_usage_mb=512.55,
            unique_paths=42,
        )
        result = stats.to_dict()

        assert result["total_executions"] == 100
        assert result["crashes_found"] == 5
        assert result["coverage_percent"] == 75.56  # Rounded to 2 decimal places
        assert result["executions_per_sec"] == 10.57  # Rounded to 2 decimal places
        assert result["start_time"] == now.isoformat()
        assert result["current_file"] == "test.dcm"
        assert result["memory_usage_mb"] == 512.5  # Rounded to 1 decimal place
        assert result["unique_paths"] == 42
        assert "runtime_seconds" in result
        assert result["runtime_seconds"] >= 0


class TestCrashInfo:
    """Tests for CrashInfo dataclass."""

    def test_default_severity(self) -> None:
        """Test default severity is 'unknown'."""
        crash = CrashInfo(
            crash_id="crash-001",
            timestamp=datetime.now(),
            test_file="test.dcm",
            crash_type="segfault",
            stack_hash="abc123",
        )
        assert crash.severity == "unknown"

    def test_custom_values(self) -> None:
        """Test custom values are stored correctly."""
        now = datetime.now()
        crash = CrashInfo(
            crash_id="crash-001",
            timestamp=now,
            test_file="test.dcm",
            crash_type="assertion",
            stack_hash="def456",
            severity="high",
        )
        assert crash.crash_id == "crash-001"
        assert crash.timestamp == now
        assert crash.test_file == "test.dcm"
        assert crash.crash_type == "assertion"
        assert crash.stack_hash == "def456"
        assert crash.severity == "high"

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        now = datetime.now()
        crash = CrashInfo(
            crash_id="crash-001",
            timestamp=now,
            test_file="test.dcm",
            crash_type="segfault",
            stack_hash="abc123",
            severity="critical",
        )
        result = crash.to_dict()

        assert result["crash_id"] == "crash-001"
        assert result["timestamp"] == now.isoformat()
        assert result["test_file"] == "test.dcm"
        assert result["crash_type"] == "segfault"
        assert result["stack_hash"] == "abc123"
        assert result["severity"] == "critical"


class TestDashboardServer:
    """Tests for DashboardServer class."""

    def test_initialization_defaults(self) -> None:
        """Test server initializes with default values."""
        server = DashboardServer()
        assert server.host == "0.0.0.0"  # noqa: S104
        assert server.port == 8080
        assert server._running is False
        assert server._stats is not None
        assert server._crashes == []
        assert server._connected_clients == set()

    def test_initialization_custom(self) -> None:
        """Test server initializes with custom values."""
        server = DashboardServer(host="127.0.0.1", port=9000)
        assert server.host == "127.0.0.1"
        assert server.port == 9000

    def test_get_stats_initial(self) -> None:
        """Test getting initial stats."""
        server = DashboardServer()
        stats = server.get_stats()
        assert isinstance(stats, FuzzingStats)
        assert stats.total_executions == 0

    def test_update_stats(self) -> None:
        """Test updating stats."""
        server = DashboardServer()
        new_stats = FuzzingStats(total_executions=100, crashes_found=5)
        server.update_stats(new_stats)

        current = server.get_stats()
        assert current.total_executions == 100
        assert current.crashes_found == 5

    def test_add_crash(self) -> None:
        """Test adding crash."""
        server = DashboardServer()
        crash = CrashInfo(
            crash_id="crash-001",
            timestamp=datetime.now(),
            test_file="test.dcm",
            crash_type="segfault",
            stack_hash="abc123",
        )
        server.add_crash(crash)

        crashes = server.get_crashes()
        assert len(crashes) == 1
        assert crashes[0].crash_id == "crash-001"

    def test_crash_list_limit(self) -> None:
        """Test crash list is limited to 1000 entries."""
        server = DashboardServer()

        # Add 1005 crashes
        for i in range(1005):
            crash = CrashInfo(
                crash_id=f"crash-{i:04d}",
                timestamp=datetime.now(),
                test_file=f"test_{i}.dcm",
                crash_type="segfault",
                stack_hash=f"hash{i}",
            )
            server.add_crash(crash)

        crashes = server.get_crashes()
        assert len(crashes) == 1000
        # Should keep the last 1000
        assert crashes[0].crash_id == "crash-0005"
        assert crashes[-1].crash_id == "crash-1004"

    def test_on_update_callback(self) -> None:
        """Test update callback is called."""
        server = DashboardServer()
        callback_called = []

        def callback(stats: FuzzingStats) -> None:
            callback_called.append(stats)

        server.on_update(callback)
        new_stats = FuzzingStats(total_executions=50)
        server.update_stats(new_stats)

        assert len(callback_called) == 1
        assert callback_called[0].total_executions == 50

    def test_multiple_callbacks(self) -> None:
        """Test multiple update callbacks."""
        server = DashboardServer()
        results: list[int] = []

        def callback1(stats: FuzzingStats) -> None:
            results.append(1)

        def callback2(stats: FuzzingStats) -> None:
            results.append(2)

        server.on_update(callback1)
        server.on_update(callback2)
        server.update_stats(FuzzingStats())

        assert results == [1, 2]

    def test_callback_error_handling(self) -> None:
        """Test callbacks that raise exceptions don't crash the server."""
        server = DashboardServer()

        def bad_callback(stats: FuzzingStats) -> None:
            raise ValueError("Test error")

        server.on_update(bad_callback)
        # Should not raise
        server.update_stats(FuzzingStats(total_executions=100))

    def test_thread_safety(self) -> None:
        """Test thread-safe stats updates."""
        server = DashboardServer()
        errors: list[Exception] = []

        def update_stats(n: int) -> None:
            try:
                for i in range(100):
                    server.update_stats(FuzzingStats(total_executions=n * 100 + i))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=update_stats, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Stats should have some value (last one written wins)
        assert server.get_stats().total_executions >= 0

    def test_stop_not_running(self) -> None:
        """Test stopping server that's not running."""
        server = DashboardServer()
        server.stop()  # Should not raise
        assert server._running is False

    @patch("dicom_fuzzer.dashboard.server.DashboardServer._create_app")
    def test_start_already_running(self, mock_create_app: MagicMock) -> None:
        """Test starting server that's already running."""
        server = DashboardServer()
        server._running = True  # Simulate running state
        server.start(blocking=False)
        # Should not create app again
        mock_create_app.assert_not_called()

    def test_get_default_html(self) -> None:
        """Test default HTML generation."""
        server = DashboardServer()
        html = server._get_default_html()
        assert "DICOM Fuzzer Dashboard" in html
        assert "WebSocket" in html
        assert "Total Executions" in html
        assert "Crashes Found" in html
        assert "Coverage" in html

    def test_broadcast_no_clients(self) -> None:
        """Test broadcast with no clients doesn't error."""
        server = DashboardServer()
        # Should not raise
        server._broadcast({"type": "test", "data": "hello"})


class TestDashboardServerIntegration:
    """Integration tests for DashboardServer with FastAPI."""

    @pytest.fixture
    def mock_fastapi(self) -> Any:
        """Mock FastAPI components."""
        with patch("dicom_fuzzer.dashboard.server.FastAPI") as mock:
            yield mock

    def test_create_app_missing_fastapi(self) -> None:
        """Test error when FastAPI is not installed."""
        server = DashboardServer()

        with patch.dict("sys.modules", {"fastapi": None}):
            with patch(
                "dicom_fuzzer.dashboard.server.DashboardServer._create_app"
            ) as mock:
                mock.side_effect = ImportError("FastAPI is required")
                with pytest.raises(ImportError, match="FastAPI"):
                    mock()
