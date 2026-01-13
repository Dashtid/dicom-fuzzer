"""Tests for Distributed Fuzzing Coordinator.

Tests for the FuzzingCoordinator class and related dataclasses that manage
distributed fuzzing campaigns across multiple workers.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.distributed.coordinator import (
    CampaignConfig,
    CampaignStats,
    FuzzingCoordinator,
    WorkerInfo,
)
from dicom_fuzzer.distributed.queue import TaskPriority, TaskResult

# =============================================================================
# TestCampaignConfig
# =============================================================================


class TestCampaignConfig:
    """Tests for CampaignConfig dataclass."""

    def test_creation_with_required_fields(self) -> None:
        """Test CampaignConfig creation with required fields."""
        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir="/path/to/corpus",
        )

        assert config.campaign_id == "test-001"
        assert config.target_executable == "/bin/viewer"
        assert config.corpus_dir == "/path/to/corpus"

    def test_creation_with_defaults(self) -> None:
        """Test CampaignConfig has correct defaults."""
        config = CampaignConfig(
            campaign_id="test-002",
            target_executable="/bin/viewer",
            corpus_dir="/path/to/corpus",
        )

        assert config.output_dir == "./artifacts/fuzzed"
        assert config.timeout == 30.0
        assert config.strategy == "coverage_guided"
        assert config.max_workers == 4
        assert config.duration == 0  # Unlimited

    def test_creation_with_custom_values(self) -> None:
        """Test CampaignConfig with custom values."""
        config = CampaignConfig(
            campaign_id="custom-001",
            target_executable="/custom/viewer",
            corpus_dir="/custom/corpus",
            output_dir="/custom/output",
            timeout=60.0,
            strategy="random",
            max_workers=8,
            duration=3600,
        )

        assert config.timeout == 60.0
        assert config.strategy == "random"
        assert config.max_workers == 8
        assert config.duration == 3600


# =============================================================================
# TestCampaignStats
# =============================================================================


class TestCampaignStats:
    """Tests for CampaignStats dataclass."""

    def test_creation_with_defaults(self) -> None:
        """Test CampaignStats creation with defaults."""
        stats = CampaignStats(campaign_id="test-001")

        assert stats.campaign_id == "test-001"
        assert stats.total_tasks == 0
        assert stats.completed_tasks == 0
        assert stats.crashes_found == 0
        assert stats.coverage_percent == 0.0
        assert stats.active_workers == 0
        assert stats.executions_per_sec == 0.0
        assert isinstance(stats.start_time, datetime)

    def test_to_dict(self) -> None:
        """Test CampaignStats to_dict conversion."""
        stats = CampaignStats(
            campaign_id="test-001",
            total_tasks=100,
            completed_tasks=50,
            crashes_found=5,
            coverage_percent=75.5,
            active_workers=4,
            executions_per_sec=10.5,
        )

        result = stats.to_dict()

        assert result["campaign_id"] == "test-001"
        assert result["total_tasks"] == 100
        assert result["completed_tasks"] == 50
        assert result["crashes_found"] == 5
        assert result["coverage_percent"] == 75.5
        assert result["active_workers"] == 4
        assert result["executions_per_sec"] == 10.5
        assert "start_time" in result
        assert "runtime_seconds" in result

    def test_to_dict_runtime_calculation(self) -> None:
        """Test that runtime_seconds is calculated correctly."""
        past_time = datetime.now() - timedelta(seconds=60)
        stats = CampaignStats(campaign_id="test-001", start_time=past_time)

        result = stats.to_dict()

        # Should be approximately 60 seconds (allow some tolerance)
        assert 59 <= result["runtime_seconds"] <= 62


# =============================================================================
# TestWorkerInfo
# =============================================================================


class TestWorkerInfo:
    """Tests for WorkerInfo dataclass."""

    def test_creation_with_required_fields(self) -> None:
        """Test WorkerInfo creation with required fields."""
        worker = WorkerInfo(worker_id="worker-001")

        assert worker.worker_id == "worker-001"
        assert worker.hostname == ""
        assert worker.tasks_completed == 0
        assert worker.crashes_found == 0
        assert isinstance(worker.last_heartbeat, datetime)

    def test_creation_with_all_fields(self) -> None:
        """Test WorkerInfo creation with all fields."""
        now = datetime.now()
        worker = WorkerInfo(
            worker_id="worker-001",
            hostname="worker-node-1",
            last_heartbeat=now,
            tasks_completed=50,
            crashes_found=3,
        )

        assert worker.worker_id == "worker-001"
        assert worker.hostname == "worker-node-1"
        assert worker.last_heartbeat == now
        assert worker.tasks_completed == 50
        assert worker.crashes_found == 3


# =============================================================================
# TestFuzzingCoordinatorInit
# =============================================================================


class TestFuzzingCoordinatorInit:
    """Tests for FuzzingCoordinator initialization."""

    def test_init_defaults(self) -> None:
        """Test FuzzingCoordinator initialization with defaults."""
        coordinator = FuzzingCoordinator()

        assert coordinator.redis_url is None
        assert coordinator.requeue_interval == 60
        assert coordinator.heartbeat_timeout == 120
        assert coordinator._queue is None
        assert coordinator._config is None
        assert coordinator._running is False

    def test_init_custom_values(self) -> None:
        """Test FuzzingCoordinator with custom values."""
        coordinator = FuzzingCoordinator(
            redis_url="redis://localhost:6379",
            requeue_interval=30,
            heartbeat_timeout=60,
        )

        assert coordinator.redis_url == "redis://localhost:6379"
        assert coordinator.requeue_interval == 30
        assert coordinator.heartbeat_timeout == 60

    def test_init_internal_state(self) -> None:
        """Test FuzzingCoordinator internal state initialization."""
        coordinator = FuzzingCoordinator()

        assert coordinator._workers == {}
        assert coordinator._crashes == []
        assert coordinator._on_crash_callbacks == []
        assert coordinator._on_progress_callbacks == []


# =============================================================================
# TestStartCampaign
# =============================================================================


class TestStartCampaign:
    """Tests for start_campaign method."""

    def test_start_campaign_creates_queue(self, tmp_path: Path) -> None:
        """Test that start_campaign creates the queue."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            assert coordinator._queue is not None
            assert coordinator._running is True
            assert coordinator._stats is not None
            assert coordinator._stats.campaign_id == "test-001"
        finally:
            coordinator.stop()

    def test_start_campaign_already_running_raises(self, tmp_path: Path) -> None:
        """Test that starting campaign twice raises error."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            with pytest.raises(RuntimeError, match="already running"):
                coordinator.start_campaign(config)
        finally:
            coordinator.stop()

    def test_start_campaign_creates_tasks_from_corpus(self, tmp_path: Path) -> None:
        """Test that start_campaign creates tasks from corpus files."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test1.dcm").touch()
        (corpus_dir / "test2.dcm").touch()
        (corpus_dir / "test3.dicom").touch()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            # Should have created 3 tasks
            assert coordinator._stats is not None
            assert coordinator._stats.total_tasks == 3
        finally:
            coordinator.stop()

    def test_start_campaign_handles_empty_corpus(self, tmp_path: Path) -> None:
        """Test that start_campaign handles empty corpus."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            assert coordinator._stats is not None
            assert coordinator._stats.total_tasks == 0
        finally:
            coordinator.stop()

    def test_start_campaign_handles_missing_corpus(self, tmp_path: Path) -> None:
        """Test that start_campaign handles missing corpus directory."""
        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(tmp_path / "nonexistent"),
        )

        coordinator = FuzzingCoordinator()

        try:
            # Should not raise, just log warning
            coordinator.start_campaign(config)

            assert coordinator._stats is not None
            assert coordinator._stats.total_tasks == 0
        finally:
            coordinator.stop()


# =============================================================================
# TestStopCampaign
# =============================================================================


class TestStopCampaign:
    """Tests for stop method."""

    def test_stop_sets_running_false(self, tmp_path: Path) -> None:
        """Test that stop sets _running to False."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()
        coordinator.start_campaign(config)

        assert coordinator._running is True

        coordinator.stop()

        assert coordinator._running is False

    def test_stop_without_start(self) -> None:
        """Test that stop works without starting."""
        coordinator = FuzzingCoordinator()

        # Should not raise
        coordinator.stop()

        assert coordinator._running is False


# =============================================================================
# TestIsRunning
# =============================================================================


class TestIsRunning:
    """Tests for is_running method."""

    def test_is_running_false_initially(self) -> None:
        """Test is_running returns False initially."""
        coordinator = FuzzingCoordinator()

        assert coordinator.is_running() is False

    def test_is_running_true_after_start(self, tmp_path: Path) -> None:
        """Test is_running returns True after start."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)
            assert coordinator.is_running() is True
        finally:
            coordinator.stop()


# =============================================================================
# TestAddTask
# =============================================================================


class TestAddTask:
    """Tests for add_task method."""

    def test_add_task_enqueues(self, tmp_path: Path) -> None:
        """Test that add_task adds to queue."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)
            initial_tasks = coordinator._stats.total_tasks

            coordinator.add_task("/new/test.dcm")

            assert coordinator._stats.total_tasks == initial_tasks + 1
        finally:
            coordinator.stop()

    def test_add_task_with_priority(self, tmp_path: Path) -> None:
        """Test add_task with custom priority."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            coordinator.add_task("/new/test.dcm", priority=TaskPriority.HIGH)

            # Task should be added (just verify no error)
            assert coordinator._stats.total_tasks >= 1
        finally:
            coordinator.stop()

    def test_add_task_not_running_raises(self) -> None:
        """Test add_task raises when not running."""
        coordinator = FuzzingCoordinator()

        with pytest.raises(RuntimeError, match="not running"):
            coordinator.add_task("/test.dcm")


# =============================================================================
# TestGetStats
# =============================================================================


class TestGetStats:
    """Tests for get_stats method."""

    def test_get_stats_returns_none_before_start(self) -> None:
        """Test get_stats returns None before starting."""
        coordinator = FuzzingCoordinator()

        assert coordinator.get_stats() is None

    def test_get_stats_returns_campaign_stats(self, tmp_path: Path) -> None:
        """Test get_stats returns CampaignStats."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test.dcm").touch()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            stats = coordinator.get_stats()

            assert stats is not None
            assert stats.campaign_id == "test-001"
            assert stats.total_tasks == 1
        finally:
            coordinator.stop()


# =============================================================================
# TestGetCrashes
# =============================================================================


class TestGetCrashes:
    """Tests for get_crashes method."""

    def test_get_crashes_empty_initially(self) -> None:
        """Test get_crashes returns empty list initially."""
        coordinator = FuzzingCoordinator()

        crashes = coordinator.get_crashes()

        assert crashes == []

    def test_get_crashes_returns_copy(self, tmp_path: Path) -> None:
        """Test get_crashes returns a copy."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            crashes1 = coordinator.get_crashes()
            crashes2 = coordinator.get_crashes()

            assert crashes1 is not crashes2
        finally:
            coordinator.stop()


# =============================================================================
# TestGetWorkers
# =============================================================================


class TestGetWorkers:
    """Tests for get_workers method."""

    def test_get_workers_empty_initially(self) -> None:
        """Test get_workers returns empty list initially."""
        coordinator = FuzzingCoordinator()

        workers = coordinator.get_workers()

        assert workers == []

    def test_get_workers_after_heartbeat(self, tmp_path: Path) -> None:
        """Test get_workers after worker heartbeat."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)
            coordinator.worker_heartbeat("worker-001", "node-1")

            workers = coordinator.get_workers()

            assert len(workers) == 1
            assert workers[0].worker_id == "worker-001"
            assert workers[0].hostname == "node-1"
        finally:
            coordinator.stop()


# =============================================================================
# TestProcessResult
# =============================================================================


class TestProcessResult:
    """Tests for _process_result method."""

    def test_process_result_updates_worker_stats(self, tmp_path: Path) -> None:
        """Test _process_result updates worker stats."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
                status="completed",
                crash_found=False,
            )

            coordinator._process_result(result)

            # Worker should be registered
            assert "worker-001" in coordinator._workers
            assert coordinator._workers["worker-001"].tasks_completed == 1
        finally:
            coordinator.stop()

    def test_process_result_tracks_crash(self, tmp_path: Path) -> None:
        """Test _process_result tracks crashes."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
                status="completed",
                crash_found=True,
                output_data={"crash_type": "segfault"},
            )

            coordinator._process_result(result)

            assert len(coordinator._crashes) == 1
            assert coordinator._crashes[0]["task_id"] == "task-001"
            assert coordinator._stats.crashes_found == 1
        finally:
            coordinator.stop()

    def test_process_result_triggers_crash_callback(self, tmp_path: Path) -> None:
        """Test _process_result triggers crash callbacks."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        crash_data = []

        def on_crash(data: dict) -> None:
            crash_data.append(data)

        try:
            coordinator.start_campaign(config)
            coordinator.on_crash(on_crash)

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
                status="completed",
                crash_found=True,
            )

            coordinator._process_result(result)

            assert len(crash_data) == 1
            assert crash_data[0]["task_id"] == "task-001"
        finally:
            coordinator.stop()

    def test_process_result_updates_coverage(self, tmp_path: Path) -> None:
        """Test _process_result updates coverage."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)
            initial_coverage = coordinator._stats.coverage_percent

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
                coverage_delta=5.0,
            )

            coordinator._process_result(result)

            assert coordinator._stats.coverage_percent == initial_coverage + 5.0
        finally:
            coordinator.stop()


# =============================================================================
# TestWorkerHeartbeat
# =============================================================================


class TestWorkerHeartbeat:
    """Tests for worker_heartbeat method."""

    def test_heartbeat_registers_new_worker(self) -> None:
        """Test heartbeat registers new worker."""
        coordinator = FuzzingCoordinator()

        coordinator.worker_heartbeat("worker-001", "node-1")

        assert "worker-001" in coordinator._workers
        assert coordinator._workers["worker-001"].hostname == "node-1"

    def test_heartbeat_updates_existing_worker(self) -> None:
        """Test heartbeat updates existing worker timestamp."""
        coordinator = FuzzingCoordinator()

        # First heartbeat
        coordinator.worker_heartbeat("worker-001", "node-1")
        first_heartbeat = coordinator._workers["worker-001"].last_heartbeat

        # Wait a tiny bit
        time.sleep(0.01)

        # Second heartbeat
        coordinator.worker_heartbeat("worker-001", "node-1")
        second_heartbeat = coordinator._workers["worker-001"].last_heartbeat

        assert second_heartbeat > first_heartbeat


# =============================================================================
# TestPruneDeadWorkers
# =============================================================================


class TestPruneDeadWorkers:
    """Tests for _prune_dead_workers method."""

    def test_prune_removes_stale_workers(self) -> None:
        """Test prune removes workers with old heartbeats."""
        coordinator = FuzzingCoordinator(heartbeat_timeout=1)

        # Add worker with old heartbeat
        coordinator._workers["stale-worker"] = WorkerInfo(
            worker_id="stale-worker",
            last_heartbeat=datetime.now() - timedelta(seconds=10),
        )

        # Add fresh worker
        coordinator._workers["fresh-worker"] = WorkerInfo(
            worker_id="fresh-worker",
            last_heartbeat=datetime.now(),
        )

        coordinator._prune_dead_workers()

        assert "stale-worker" not in coordinator._workers
        assert "fresh-worker" in coordinator._workers

    def test_prune_keeps_active_workers(self) -> None:
        """Test prune keeps workers with recent heartbeats."""
        coordinator = FuzzingCoordinator(heartbeat_timeout=120)

        coordinator._workers["active-worker"] = WorkerInfo(
            worker_id="active-worker",
            last_heartbeat=datetime.now(),
        )

        coordinator._prune_dead_workers()

        assert "active-worker" in coordinator._workers


# =============================================================================
# TestCallbacks
# =============================================================================


class TestCallbacks:
    """Tests for callback registration."""

    def test_on_crash_registers_callback(self) -> None:
        """Test on_crash registers callback."""
        coordinator = FuzzingCoordinator()

        callback = MagicMock()
        coordinator.on_crash(callback)

        assert callback in coordinator._on_crash_callbacks

    def test_on_progress_registers_callback(self) -> None:
        """Test on_progress registers callback."""
        coordinator = FuzzingCoordinator()

        callback = MagicMock()
        coordinator.on_progress(callback)

        assert callback in coordinator._on_progress_callbacks

    def test_progress_callback_invoked(self, tmp_path: Path) -> None:
        """Test progress callback is invoked on result processing."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        progress_data = []

        def on_progress(data: dict) -> None:
            progress_data.append(data)

        try:
            coordinator.start_campaign(config)
            coordinator.on_progress(on_progress)

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
            )

            coordinator._process_result(result)

            assert len(progress_data) == 1
            assert progress_data[0]["campaign_id"] == "test-001"
        finally:
            coordinator.stop()


# =============================================================================
# TestMaintenanceLoop
# =============================================================================


class TestMaintenanceLoop:
    """Tests for _maintenance_loop method."""

    def test_maintenance_requeues_stale_tasks(self, tmp_path: Path) -> None:
        """Test that maintenance loop requeues stale tasks."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator(requeue_interval=1)

        try:
            coordinator.start_campaign(config)

            # Mock the queue's requeue method to track calls
            original_requeue = coordinator._queue.requeue_stale_tasks
            requeue_count = [0]

            def mock_requeue() -> int:
                requeue_count[0] += 1
                return original_requeue()

            coordinator._queue.requeue_stale_tasks = mock_requeue

            # Wait for maintenance loop to run
            time.sleep(1.5)

            # Should have been called at least once
            assert requeue_count[0] >= 1
        finally:
            coordinator.stop()

    def test_maintenance_respects_duration(self, tmp_path: Path) -> None:
        """Test that maintenance loop respects campaign duration."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
            duration=1,  # 1 second duration
        )

        coordinator = FuzzingCoordinator(requeue_interval=0.5)

        try:
            coordinator.start_campaign(config)

            # Wait for campaign to expire
            time.sleep(2)

            # Should have stopped
            assert coordinator._running is False
        finally:
            coordinator.stop()


# =============================================================================
# TestCreateCorpusTasks
# =============================================================================


class TestCreateCorpusTasks:
    """Tests for _create_corpus_tasks method."""

    def test_create_corpus_tasks_filters_by_extension(self, tmp_path: Path) -> None:
        """Test that only .dcm and .dicom files are included."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "valid1.dcm").touch()
        (corpus_dir / "valid2.dicom").touch()
        (corpus_dir / "invalid.txt").touch()
        (corpus_dir / "invalid.jpg").touch()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            # Should only count .dcm and .dicom files
            assert coordinator._stats.total_tasks == 2
        finally:
            coordinator.stop()

    def test_create_corpus_tasks_handles_subdirs(self, tmp_path: Path) -> None:
        """Test that subdirectories are searched."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test1.dcm").touch()

        subdir = corpus_dir / "subdir"
        subdir.mkdir()
        (subdir / "test2.dcm").touch()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        try:
            coordinator.start_campaign(config)

            # Should find both files
            assert coordinator._stats.total_tasks == 2
        finally:
            coordinator.stop()

    def test_create_corpus_tasks_not_initialized(self) -> None:
        """Test _create_corpus_tasks handles uninitialized state."""
        coordinator = FuzzingCoordinator()

        # Should not raise, just log error
        coordinator._create_corpus_tasks()

        # Verify coordinator is still functional
        assert coordinator is not None


# =============================================================================
# TestResultProcessor
# =============================================================================


class TestResultProcessor:
    """Tests for _result_processor method."""

    def test_result_processor_handles_queue_not_initialized(self) -> None:
        """Test _result_processor handles uninitialized queue."""
        coordinator = FuzzingCoordinator()

        # Should not raise, just log error and return
        coordinator._result_processor()

        # Verify coordinator is still functional
        assert coordinator is not None


# =============================================================================
# TestCallbackExceptionHandling
# =============================================================================


class TestCallbackExceptionHandling:
    """Tests for callback exception handling."""

    def test_crash_callback_exception_handled(self, tmp_path: Path) -> None:
        """Test that exceptions in crash callbacks are handled."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        def failing_callback(data: dict) -> None:
            raise ValueError("Intentional failure")

        try:
            coordinator.start_campaign(config)
            coordinator.on_crash(failing_callback)

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
                crash_found=True,
            )

            # Should not raise
            coordinator._process_result(result)

            # Crash should still be recorded
            assert len(coordinator._crashes) == 1
        finally:
            coordinator.stop()

    def test_progress_callback_exception_handled(self, tmp_path: Path) -> None:
        """Test that exceptions in progress callbacks are handled."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = CampaignConfig(
            campaign_id="test-001",
            target_executable="/bin/viewer",
            corpus_dir=str(corpus_dir),
        )

        coordinator = FuzzingCoordinator()

        def failing_callback(data: dict) -> None:
            raise ValueError("Intentional failure")

        try:
            coordinator.start_campaign(config)
            coordinator.on_progress(failing_callback)

            result = TaskResult(
                task_id="task-001",
                worker_id="worker-001",
            )

            # Should not raise
            coordinator._process_result(result)

            # Verify coordinator still processed despite callback failure
            assert coordinator is not None
        finally:
            coordinator.stop()
