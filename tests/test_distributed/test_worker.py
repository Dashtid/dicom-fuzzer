"""Tests for Distributed Fuzzing Worker module.

Tests for the FuzzingWorker and LocalWorkerPool classes that execute
fuzzing tasks in a distributed environment.
"""

from __future__ import annotations

import signal
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from dicom_fuzzer.distributed.queue import FuzzingTask, TaskStatus
from dicom_fuzzer.distributed.worker import (
    FuzzingWorker,
    LocalWorkerPool,
    WorkerConfig,
)

# =============================================================================
# TestWorkerConfig
# =============================================================================


class TestWorkerConfig:
    """Tests for WorkerConfig dataclass."""

    def test_defaults(self) -> None:
        """Test WorkerConfig has correct defaults."""
        config = WorkerConfig()

        assert len(config.worker_id) == 8  # UUID truncated to 8 chars
        assert config.redis_url == "redis://localhost:6379"
        assert config.heartbeat_interval == 30
        assert config.poll_interval == 0.5
        assert config.max_memory_mb == 4096
        assert config.working_dir == "/tmp/dicom_fuzzer"

    def test_uuid_generation(self) -> None:
        """Test that worker_id is auto-generated."""
        config1 = WorkerConfig()
        config2 = WorkerConfig()

        # Each config should get unique ID
        assert config1.worker_id != config2.worker_id

    def test_custom_values(self) -> None:
        """Test WorkerConfig with custom values."""
        config = WorkerConfig(
            worker_id="custom-worker",
            redis_url="redis://custom:6380",
            heartbeat_interval=60,
            poll_interval=1.0,
            max_memory_mb=8192,
            working_dir="/custom/dir",
        )

        assert config.worker_id == "custom-worker"
        assert config.redis_url == "redis://custom:6380"
        assert config.heartbeat_interval == 60
        assert config.poll_interval == 1.0
        assert config.max_memory_mb == 8192
        assert config.working_dir == "/custom/dir"


# =============================================================================
# TestFuzzingWorkerInit
# =============================================================================


class TestFuzzingWorkerInit:
    """Tests for FuzzingWorker initialization."""

    def test_init_with_defaults(self, tmp_path: Path) -> None:
        """Test FuzzingWorker initialization with defaults."""
        config = WorkerConfig(working_dir=str(tmp_path / "worker"))
        worker = FuzzingWorker(config=config)

        assert worker.config == config
        assert worker._queue is None
        assert worker._running is False
        assert worker._tasks_completed == 0
        assert worker._crashes_found == 0

    def test_init_with_redis_url(self, tmp_path: Path) -> None:
        """Test FuzzingWorker initialization with redis_url."""
        worker = FuzzingWorker(redis_url="redis://test:6379")

        assert worker.config.redis_url == "redis://test:6379"

    def test_init_creates_working_dir(self, tmp_path: Path) -> None:
        """Test that initialization creates working directory."""
        working_dir = tmp_path / "new_worker_dir"
        config = WorkerConfig(working_dir=str(working_dir))

        FuzzingWorker(config=config)

        assert working_dir.exists()


# =============================================================================
# TestFuzzingWorkerStart
# =============================================================================


class TestFuzzingWorkerStart:
    """Tests for FuzzingWorker.start method."""

    def test_start_non_blocking(self, tmp_path: Path) -> None:
        """Test starting worker in non-blocking mode."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        try:
            worker.start(blocking=False)

            assert worker._running is True
            assert worker._queue is not None
            assert worker._heartbeat_thread is not None
            assert worker._worker_thread is not None
        finally:
            worker.stop()

    def test_start_already_running(self, tmp_path: Path) -> None:
        """Test starting worker when already running."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        try:
            worker.start(blocking=False)
            worker.start(blocking=False)  # Should log warning but not raise

            assert worker._running is True
        finally:
            worker.stop()


# =============================================================================
# TestFuzzingWorkerStop
# =============================================================================


class TestFuzzingWorkerStop:
    """Tests for FuzzingWorker.stop method."""

    def test_stop_running_worker(self, tmp_path: Path) -> None:
        """Test stopping a running worker."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        worker.start(blocking=False)
        assert worker._running is True

        worker.stop()
        assert worker._running is False

    def test_stop_without_start(self, tmp_path: Path) -> None:
        """Test stopping worker that was never started."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        # Should not raise
        worker.stop()
        assert worker._running is False


# =============================================================================
# TestExecuteTask
# =============================================================================


class TestExecuteTask:
    """Tests for FuzzingWorker._execute_task method."""

    def test_execute_task_success(self, tmp_path: Path) -> None:
        """Test executing a task that succeeds."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            task_id="task-001",
            test_file="/path/to/test.dcm",
            target_executable="/bin/viewer",
            timeout=30.0,
        )

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.communicate.return_value = (b"output", b"")
            process.returncode = 0
            mock_popen.return_value = process

            result = worker._execute_task(task)

        assert result.task_id == "task-001"
        assert result.worker_id == "test-worker"
        assert result.status == TaskStatus.COMPLETED
        assert result.crash_found is False

    def test_execute_task_crash(self, tmp_path: Path) -> None:
        """Test executing a task that crashes."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            task_id="task-002",
            test_file="/path/to/test.dcm",
            target_executable="/bin/viewer",
        )

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.communicate.return_value = (b"output", b"error")
            process.returncode = 1
            mock_popen.return_value = process

            result = worker._execute_task(task)

        assert result.crash_found is True
        assert result.output_data["exit_code"] == 1

    def test_execute_task_signal_crash(self, tmp_path: Path) -> None:
        """Test executing a task that crashes with signal."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            task_id="task-003",
            test_file="/path/to/test.dcm",
            target_executable="/bin/viewer",
        )

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.communicate.return_value = (b"", b"")
            process.returncode = -signal.SIGSEGV  # Negative = signal
            mock_popen.return_value = process

            result = worker._execute_task(task)

        assert result.crash_found is True
        assert result.output_data["signal"] == signal.SIGSEGV
        assert result.output_data["signal_name"] == "SIGSEGV"

    def test_execute_task_timeout(self, tmp_path: Path) -> None:
        """Test executing a task that times out."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            task_id="task-004",
            test_file="/path/to/test.dcm",
            target_executable="/bin/viewer",
            timeout=1.0,
        )

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            # First call raises TimeoutExpired, second call (after kill) returns normally
            process.communicate.side_effect = [
                subprocess.TimeoutExpired(cmd="/bin/viewer", timeout=1.0),
                (b"", b""),  # Return value for second communicate() after kill()
            ]
            process.kill = MagicMock()
            mock_popen.return_value = process

            result = worker._execute_task(task)

        assert result.status == TaskStatus.TIMEOUT
        assert "Timeout" in result.error_message
        process.kill.assert_called_once()

    def test_execute_task_not_found(self, tmp_path: Path) -> None:
        """Test executing a task with missing executable."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        task = FuzzingTask(
            task_id="task-005",
            test_file="/path/to/test.dcm",
            target_executable="/nonexistent/viewer",
        )

        with patch("subprocess.Popen") as mock_popen:
            mock_popen.side_effect = FileNotFoundError("No such file")

            result = worker._execute_task(task)

        assert result.status == TaskStatus.FAILED
        assert "not found" in result.error_message


# =============================================================================
# TestSignalName
# =============================================================================


class TestSignalName:
    """Tests for FuzzingWorker._signal_name method."""

    def test_known_signals(self, tmp_path: Path) -> None:
        """Test signal name lookup for known signals."""
        config = WorkerConfig(working_dir=str(tmp_path / "worker"))
        worker = FuzzingWorker(config=config)

        assert worker._signal_name(signal.SIGSEGV) == "SIGSEGV"
        assert worker._signal_name(signal.SIGABRT) == "SIGABRT"
        assert worker._signal_name(signal.SIGFPE) == "SIGFPE"
        assert worker._signal_name(signal.SIGILL) == "SIGILL"

    def test_unknown_signal(self, tmp_path: Path) -> None:
        """Test signal name for unknown signal."""
        config = WorkerConfig(working_dir=str(tmp_path / "worker"))
        worker = FuzzingWorker(config=config)

        result = worker._signal_name(999)
        assert result == "SIG999"

    def test_sigbus_platform_specific(self, tmp_path: Path) -> None:
        """Test SIGBUS handling (not available on Windows)."""
        config = WorkerConfig(working_dir=str(tmp_path / "worker"))
        worker = FuzzingWorker(config=config)

        if hasattr(signal, "SIGBUS"):
            assert worker._signal_name(signal.SIGBUS) == "SIGBUS"


# =============================================================================
# TestGetStatus
# =============================================================================


class TestGetStatus:
    """Tests for FuzzingWorker.get_status method."""

    def test_get_status_not_running(self, tmp_path: Path) -> None:
        """Test get_status when not running."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        status = worker.get_status()

        assert status["worker_id"] == "test-worker"
        assert status["running"] is False
        assert status["current_task"] is None
        assert status["tasks_completed"] == 0
        assert status["uptime_seconds"] == 0

    def test_get_status_running(self, tmp_path: Path) -> None:
        """Test get_status when running."""
        config = WorkerConfig(
            worker_id="test-worker",
            working_dir=str(tmp_path / "worker"),
        )
        worker = FuzzingWorker(config=config)

        try:
            worker.start(blocking=False)
            time.sleep(0.1)  # Small delay for startup

            status = worker.get_status()

            assert status["running"] is True
            assert status["uptime_seconds"] > 0
            assert "hostname" in status
        finally:
            worker.stop()


# =============================================================================
# TestWorkLoop
# =============================================================================


class TestWorkLoop:
    """Tests for FuzzingWorker._work_loop method."""

    def test_work_loop_handles_queue_not_initialized(self, tmp_path: Path) -> None:
        """Test _work_loop handles uninitialized queue."""
        config = WorkerConfig(working_dir=str(tmp_path / "worker"))
        worker = FuzzingWorker(config=config)

        # Should not raise, just log error and return
        worker._work_loop()

        # Verify worker is still functional
        assert worker is not None


# =============================================================================
# TestLocalWorkerPoolInit
# =============================================================================


class TestLocalWorkerPoolInit:
    """Tests for LocalWorkerPool initialization."""

    def test_init_defaults(self, tmp_path: Path) -> None:
        """Test LocalWorkerPool initialization with defaults."""
        pool = LocalWorkerPool(
            num_workers=4,
            working_dir=str(tmp_path / "pool"),
        )

        assert pool.num_workers == 4
        assert pool._running is False
        assert len(pool._workers) == 0

    def test_init_creates_working_dir(self, tmp_path: Path) -> None:
        """Test that initialization creates working directory."""
        working_dir = tmp_path / "new_pool_dir"

        LocalWorkerPool(working_dir=str(working_dir))

        assert working_dir.exists()


# =============================================================================
# TestLocalWorkerPoolStart
# =============================================================================


class TestLocalWorkerPoolStart:
    """Tests for LocalWorkerPool.start method."""

    def test_start_creates_queue_and_workers(self, tmp_path: Path) -> None:
        """Test starting pool creates queue and workers."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test.dcm").touch()

        pool = LocalWorkerPool(
            num_workers=2,
            working_dir=str(tmp_path / "pool"),
        )

        try:
            pool.start(
                target="/bin/viewer",
                corpus=str(corpus_dir),
                timeout=10.0,
            )

            assert pool._running is True
            assert pool._queue is not None
            assert len(pool._workers) == 2
        finally:
            pool.stop()

    def test_start_already_running(self, tmp_path: Path) -> None:
        """Test starting pool when already running."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        pool = LocalWorkerPool(
            num_workers=2,
            working_dir=str(tmp_path / "pool"),
        )

        try:
            pool.start(target="/bin/viewer", corpus=str(corpus_dir))
            pool.start(target="/bin/viewer", corpus=str(corpus_dir))  # Should not raise

            assert pool._running is True
        finally:
            pool.stop()

    def test_start_loads_corpus(self, tmp_path: Path) -> None:
        """Test that start loads DICOM files from corpus."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test1.dcm").touch()
        (corpus_dir / "test2.dicom").touch()
        (corpus_dir / "ignored.txt").touch()

        pool = LocalWorkerPool(
            num_workers=1,
            working_dir=str(tmp_path / "pool"),
        )

        try:
            pool.start(target="/bin/viewer", corpus=str(corpus_dir))

            stats = pool._queue.get_stats()
            assert stats["pending"] == 2  # Only .dcm and .dicom files
        finally:
            pool.stop()


# =============================================================================
# TestLocalWorkerPoolStats
# =============================================================================


class TestLocalWorkerPoolStats:
    """Tests for LocalWorkerPool statistics methods."""

    def test_is_running_false_initially(self, tmp_path: Path) -> None:
        """Test is_running returns False initially."""
        pool = LocalWorkerPool(working_dir=str(tmp_path / "pool"))

        assert pool.is_running() is False

    def test_is_running_true_when_started(self, tmp_path: Path) -> None:
        """Test is_running returns True when started."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        pool = LocalWorkerPool(
            num_workers=1,
            working_dir=str(tmp_path / "pool"),
        )

        try:
            pool.start(target="/bin/viewer", corpus=str(corpus_dir))
            assert pool.is_running() is True
        finally:
            pool.stop()

    def test_get_stats(self, tmp_path: Path) -> None:
        """Test get_stats returns correct statistics."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        pool = LocalWorkerPool(
            num_workers=2,
            working_dir=str(tmp_path / "pool"),
        )

        try:
            pool.start(target="/bin/viewer", corpus=str(corpus_dir))

            stats = pool.get_stats()

            assert "active_workers" in stats
            assert "total_workers" in stats
            assert stats["total_workers"] == 2
            assert "tasks_completed" in stats
            assert "crashes_found" in stats
        finally:
            pool.stop()

    def test_get_results_empty(self, tmp_path: Path) -> None:
        """Test get_results returns empty list initially."""
        pool = LocalWorkerPool(working_dir=str(tmp_path / "pool"))

        results = pool.get_results()
        assert results == []

    def test_get_results_with_queue(self, tmp_path: Path) -> None:
        """Test get_results delegates to queue."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        pool = LocalWorkerPool(
            num_workers=1,
            working_dir=str(tmp_path / "pool"),
        )

        try:
            pool.start(target="/bin/viewer", corpus=str(corpus_dir))

            results = pool.get_results()
            assert isinstance(results, list)
        finally:
            pool.stop()


# =============================================================================
# TestLocalWorkerPoolStop
# =============================================================================


class TestLocalWorkerPoolStop:
    """Tests for LocalWorkerPool.stop method."""

    def test_stop_clears_workers(self, tmp_path: Path) -> None:
        """Test that stop clears worker list."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        pool = LocalWorkerPool(
            num_workers=2,
            working_dir=str(tmp_path / "pool"),
        )

        pool.start(target="/bin/viewer", corpus=str(corpus_dir))
        assert len(pool._workers) == 2

        pool.stop()
        assert len(pool._workers) == 0
        assert pool._running is False
