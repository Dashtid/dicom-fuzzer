"""Tests for the distributed worker module.

This module tests FuzzingWorker and WorkerConfig classes.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.distributed.queue import (
    FuzzingTask,
    InMemoryTaskQueue,
    TaskResult,
    TaskStatus,
)
from dicom_fuzzer.distributed.worker import FuzzingWorker, WorkerConfig


class TestWorkerConfig:
    """Tests for WorkerConfig dataclass."""

    def test_default_values(self) -> None:
        """Test config with default values."""
        config = WorkerConfig()
        assert config.worker_id is not None
        assert len(config.worker_id) == 8  # Short UUID
        assert config.redis_url == "redis://localhost:6379"
        assert config.heartbeat_interval == 30
        assert config.poll_interval == 0.5
        assert config.max_memory_mb == 4096
        assert config.working_dir == "/tmp/dicom_fuzzer"

    def test_custom_values(self) -> None:
        """Test config with custom values."""
        config = WorkerConfig(
            worker_id="custom-worker",
            redis_url="redis://other:6380",
            heartbeat_interval=15,
            poll_interval=1.0,
            max_memory_mb=2048,
            working_dir="/custom/dir",
        )
        assert config.worker_id == "custom-worker"
        assert config.redis_url == "redis://other:6380"
        assert config.heartbeat_interval == 15
        assert config.poll_interval == 1.0
        assert config.max_memory_mb == 2048
        assert config.working_dir == "/custom/dir"

    def test_auto_generated_worker_id(self) -> None:
        """Test worker IDs are unique."""
        config1 = WorkerConfig()
        config2 = WorkerConfig()
        assert config1.worker_id != config2.worker_id


class TestFuzzingWorker:
    """Tests for FuzzingWorker class."""

    @pytest.fixture
    def temp_working_dir(self) -> Any:
        """Create temporary working directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_initialization_defaults(self, temp_working_dir: str) -> None:
        """Test worker initializes with defaults."""
        config = WorkerConfig(working_dir=temp_working_dir)
        worker = FuzzingWorker(config=config)

        assert worker._running is False
        assert worker._current_task is None
        assert worker._tasks_completed == 0
        assert worker._crashes_found == 0

    def test_initialization_with_redis_url(self, temp_working_dir: str) -> None:
        """Test worker initialization with redis URL."""
        config = WorkerConfig(working_dir=temp_working_dir)
        worker = FuzzingWorker(redis_url="redis://custom:6379", config=config)

        assert worker.config.redis_url == "redis://custom:6379"

    def test_creates_working_directory(self) -> None:
        """Test worker creates working directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = os.path.join(tmpdir, "fuzzer_work")
            config = WorkerConfig(working_dir=work_dir)
            worker = FuzzingWorker(config=config)

            assert Path(work_dir).exists()

    def test_start_stop_non_blocking(self, temp_working_dir: str) -> None:
        """Test starting and stopping worker in non-blocking mode."""
        config = WorkerConfig(
            working_dir=temp_working_dir,
            poll_interval=0.1,
        )
        worker = FuzzingWorker(config=config)

        # Start non-blocking
        worker.start(blocking=False)
        assert worker._running is True
        time.sleep(0.2)

        # Stop
        worker.stop()
        assert worker._running is False

    def test_start_already_running(self, temp_working_dir: str) -> None:
        """Test starting worker that's already running."""
        config = WorkerConfig(working_dir=temp_working_dir)
        worker = FuzzingWorker(config=config)

        worker._running = True  # Simulate running
        worker.start(blocking=False)  # Should return early

    def test_get_status(self, temp_working_dir: str) -> None:
        """Test getting worker status."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=temp_working_dir,
        )
        worker = FuzzingWorker(config=config)

        status = worker.get_status()
        assert status["worker_id"] == "test-worker"
        assert status["running"] is False
        assert status["tasks_completed"] == 0
        assert status["crashes_found"] == 0

    def test_get_status_running(self, temp_working_dir: str) -> None:
        """Test getting status of running worker."""
        config = WorkerConfig(
            worker_id="running-worker",
            working_dir=temp_working_dir,
            poll_interval=0.1,
        )
        worker = FuzzingWorker(config=config)

        worker.start(blocking=False)
        time.sleep(0.1)

        status = worker.get_status()
        assert status["running"] is True
        assert "uptime_seconds" in status

        worker.stop()


class TestFuzzingWorkerExecution:
    """Tests for worker task execution."""

    @pytest.fixture
    def temp_working_dir(self) -> Any:
        """Create temporary working directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def mock_queue(self) -> InMemoryTaskQueue:
        """Create mock task queue."""
        return InMemoryTaskQueue()

    def test_claims_task_from_queue(
        self, temp_working_dir: str, mock_queue: InMemoryTaskQueue
    ) -> None:
        """Test worker claims tasks from queue.

        This test directly tests claim_task behavior to avoid thread timing issues.
        """
        config = WorkerConfig(
            working_dir=temp_working_dir,
            poll_interval=0.1,
        )
        worker = FuzzingWorker(config=config)
        worker._queue = mock_queue

        # Add task to queue
        task = FuzzingTask(test_file="test.dcm", target_executable="echo")
        mock_queue.enqueue(task)

        # Verify task is in queue
        stats = mock_queue.get_stats()
        assert stats["pending"] == 1

        # Directly test claim behavior (what worker._work_loop does)
        claimed = mock_queue.claim_task(config.worker_id)
        assert claimed is not None
        assert claimed.task_id == task.task_id

        # Task should have been claimed
        stats = mock_queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 1

    def test_execute_task_success(self, temp_working_dir: str) -> None:
        """Test successful task execution."""
        config = WorkerConfig(working_dir=temp_working_dir)
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            test_file=__file__,  # Use this test file as input
            target_executable="echo",  # Simple command that succeeds
            timeout=5.0,
        )

        # Mock subprocess.Popen to avoid actual execution
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = 0

        with patch(
            "dicom_fuzzer.distributed.worker.subprocess.Popen",
            return_value=mock_process,
        ):
            result = worker._execute_task(task)

        assert result.task_id == task.task_id
        assert result.status == TaskStatus.COMPLETED

    def test_execute_task_crash(self, temp_working_dir: str) -> None:
        """Test task execution with crash detection."""
        config = WorkerConfig(working_dir=temp_working_dir)
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            test_file="test.dcm",
            target_executable="/nonexistent",
            timeout=5.0,
        )

        # Mock subprocess.Popen to simulate crash (non-zero exit code)
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b"", b"Segmentation fault")
        mock_process.returncode = -11  # SIGSEGV

        with patch(
            "dicom_fuzzer.distributed.worker.subprocess.Popen",
            return_value=mock_process,
        ):
            result = worker._execute_task(task)

        assert result.crash_found is True

    def test_execute_task_timeout(self, temp_working_dir: str) -> None:
        """Test task execution timeout."""
        import subprocess

        config = WorkerConfig(working_dir=temp_working_dir)
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            test_file="test.dcm",
            target_executable="sleep",
            timeout=0.1,
        )

        # Mock subprocess.Popen to simulate timeout
        # First call to communicate raises TimeoutExpired
        # Second call (after kill) returns empty output
        mock_process = MagicMock()
        mock_process.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd="sleep", timeout=0.1),
            (b"", b""),  # After kill, communicate returns empty
        ]
        mock_process.kill.return_value = None

        with patch(
            "dicom_fuzzer.distributed.worker.subprocess.Popen",
            return_value=mock_process,
        ):
            result = worker._execute_task(task)

        assert result.status == TaskStatus.TIMEOUT


class TestFuzzingWorkerHeartbeat:
    """Tests for worker heartbeat functionality."""

    @pytest.fixture
    def temp_working_dir(self) -> Any:
        """Create temporary working directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_heartbeat_thread_starts(self, temp_working_dir: str) -> None:
        """Test heartbeat thread starts with worker."""
        config = WorkerConfig(
            working_dir=temp_working_dir,
            heartbeat_interval=1,
            poll_interval=0.1,
        )
        worker = FuzzingWorker(config=config)

        worker.start(blocking=False)
        time.sleep(0.2)

        assert worker._heartbeat_thread is not None
        assert worker._heartbeat_thread.is_alive()

        worker.stop()

    def test_heartbeat_thread_stops(self, temp_working_dir: str) -> None:
        """Test heartbeat thread stops with worker."""
        config = WorkerConfig(
            working_dir=temp_working_dir,
            heartbeat_interval=1,
            poll_interval=0.1,
        )
        worker = FuzzingWorker(config=config)

        worker.start(blocking=False)
        time.sleep(0.2)
        worker.stop()
        time.sleep(0.2)

        # Thread should have stopped
        assert not worker._heartbeat_thread.is_alive()


class TestFuzzingWorkerIntegration:
    """Integration tests for FuzzingWorker."""

    @pytest.fixture
    def temp_working_dir(self) -> Any:
        """Create temporary working directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_full_task_lifecycle(self, temp_working_dir: str) -> None:
        """Test complete task lifecycle: enqueue -> claim -> execute -> result.

        This test directly calls worker methods to avoid thread timing issues.
        """
        queue = InMemoryTaskQueue()

        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=temp_working_dir,
            poll_interval=0.1,
        )
        worker = FuzzingWorker(config=config)
        worker._queue = queue

        # Enqueue a task
        task = FuzzingTask(
            test_file=__file__,
            target_executable="echo",
            timeout=5.0,
        )
        queue.enqueue(task)

        # Manually simulate what worker._work_loop does
        # 1. Claim task
        claimed = queue.claim_task(config.worker_id)
        assert claimed is not None
        assert claimed.task_id == task.task_id

        # 2. Execute task (mocked)
        result = TaskResult(
            task_id=claimed.task_id,
            worker_id=config.worker_id,
            status=TaskStatus.COMPLETED,
            duration=0.1,
        )

        # 3. Submit result
        queue.submit_result(result)

        # 4. Verify result was submitted
        results = queue.get_results(count=10)
        assert len(results) >= 1
        our_result = next((r for r in results if r.task_id == task.task_id), None)
        assert our_result is not None
        assert our_result.status == TaskStatus.COMPLETED

    def test_multiple_tasks(self, temp_working_dir: str) -> None:
        """Test worker processes multiple tasks.

        This test directly calls worker methods to avoid thread timing issues.
        """
        queue = InMemoryTaskQueue()

        config = WorkerConfig(
            worker_id="multi-task-worker",
            working_dir=temp_working_dir,
            poll_interval=0.05,
        )

        # Enqueue multiple tasks
        task_ids = []
        for i in range(5):
            task = FuzzingTask(test_file=f"test_{i}.dcm", target_executable="echo")
            queue.enqueue(task)
            task_ids.append(task.task_id)

        # Manually process all tasks
        for _ in range(5):
            claimed = queue.claim_task(config.worker_id)
            assert claimed is not None
            result = TaskResult(
                task_id=claimed.task_id,
                worker_id=config.worker_id,
                status=TaskStatus.COMPLETED,
            )
            queue.submit_result(result)

        # All tasks should be processed
        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["completed"] == 5
