"""Tests for distributed task queue module.

Tests for the task queue implementation including:
- TaskStatus and TaskPriority enums
- FuzzingTask and TaskResult dataclasses
- InMemoryTaskQueue for testing
- TaskQueue with mocked Redis
- create_task_queue factory function
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.distributed.queue import (
    FuzzingTask,
    InMemoryTaskQueue,
    TaskPriority,
    TaskQueue,
    TaskResult,
    TaskStatus,
    create_task_queue,
)

# =============================================================================
# TestEnums
# =============================================================================


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_status_values(self) -> None:
        """Test all status values are defined."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.IN_PROGRESS.value == "in_progress"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.TIMEOUT.value == "timeout"

    def test_status_count(self) -> None:
        """Test correct number of statuses."""
        assert len(TaskStatus) == 5


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_priority_values(self) -> None:
        """Test priority values are integers."""
        assert TaskPriority.LOW.value == 0
        assert TaskPriority.NORMAL.value == 1
        assert TaskPriority.HIGH.value == 2
        assert TaskPriority.CRITICAL.value == 3

    def test_priority_ordering(self) -> None:
        """Test priorities are correctly ordered."""
        assert TaskPriority.LOW.value < TaskPriority.NORMAL.value
        assert TaskPriority.NORMAL.value < TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value < TaskPriority.CRITICAL.value


# =============================================================================
# TestFuzzingTask
# =============================================================================


class TestFuzzingTask:
    """Tests for FuzzingTask dataclass."""

    def test_task_creation_defaults(self) -> None:
        """Test creating task with default values."""
        task = FuzzingTask()

        assert task.task_id  # UUID generated
        assert task.test_file == ""
        assert task.target_executable == ""
        assert task.timeout == 30.0
        assert task.strategy == "coverage_guided"
        assert task.priority == TaskPriority.NORMAL
        assert isinstance(task.created_at, datetime)
        assert task.metadata == {}

    def test_task_creation_custom(self) -> None:
        """Test creating task with custom values."""
        task = FuzzingTask(
            task_id="custom-id",
            test_file="/path/to/test.dcm",
            target_executable="/path/to/target.exe",
            timeout=60.0,
            strategy="grammar",
            priority=TaskPriority.HIGH,
            metadata={"key": "value"},
        )

        assert task.task_id == "custom-id"
        assert task.test_file == "/path/to/test.dcm"
        assert task.target_executable == "/path/to/target.exe"
        assert task.timeout == 60.0
        assert task.strategy == "grammar"
        assert task.priority == TaskPriority.HIGH
        assert task.metadata == {"key": "value"}

    def test_task_to_dict(self) -> None:
        """Test task serialization to dictionary."""
        task = FuzzingTask(
            task_id="test-123",
            test_file="/test.dcm",
            priority=TaskPriority.HIGH,
        )

        d = task.to_dict()

        assert d["task_id"] == "test-123"
        assert d["test_file"] == "/test.dcm"
        assert d["priority"] == TaskPriority.HIGH.value  # Integer value
        assert "created_at" in d  # ISO format string

    def test_task_from_dict(self) -> None:
        """Test task deserialization from dictionary."""
        data = {
            "task_id": "from-dict-123",
            "test_file": "/test.dcm",
            "target_executable": "/target.exe",
            "timeout": 45.0,
            "strategy": "mutation",
            "priority": 2,  # HIGH
            "created_at": "2025-01-15T10:30:00",
            "metadata": {"source": "test"},
        }

        task = FuzzingTask.from_dict(data)

        assert task.task_id == "from-dict-123"
        assert task.test_file == "/test.dcm"
        assert task.timeout == 45.0
        assert task.priority == TaskPriority.HIGH
        assert task.metadata == {"source": "test"}

    def test_task_from_dict_minimal(self) -> None:
        """Test task deserialization with minimal data."""
        data = {}

        task = FuzzingTask.from_dict(data)

        # Should use defaults
        assert task.task_id  # Generated
        assert task.test_file == ""
        assert task.timeout == 30.0
        assert task.priority == TaskPriority.NORMAL


# =============================================================================
# TestTaskResult
# =============================================================================


class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating task result."""
        result = TaskResult(
            task_id="task-123",
            worker_id="worker-1",
        )

        assert result.task_id == "task-123"
        assert result.worker_id == "worker-1"
        assert result.status == TaskStatus.COMPLETED
        assert result.duration == 0.0
        assert result.crash_found is False
        assert result.coverage_delta == 0.0
        assert result.error_message == ""
        assert result.output_data == {}

    def test_result_creation_full(self) -> None:
        """Test creating task result with all fields."""
        result = TaskResult(
            task_id="task-456",
            worker_id="worker-2",
            status=TaskStatus.FAILED,
            duration=5.5,
            crash_found=True,
            coverage_delta=0.05,
            error_message="Crash detected",
            output_data={"crash_file": "/path/to/crash"},
        )

        assert result.task_id == "task-456"
        assert result.status == TaskStatus.FAILED
        assert result.crash_found is True
        assert result.error_message == "Crash detected"

    def test_result_to_dict(self) -> None:
        """Test result serialization to dictionary."""
        result = TaskResult(
            task_id="task-789",
            worker_id="worker-3",
            status=TaskStatus.COMPLETED,
            crash_found=True,
        )

        d = result.to_dict()

        assert d["task_id"] == "task-789"
        assert d["worker_id"] == "worker-3"
        assert d["status"] == "completed"
        assert d["crash_found"] is True

    def test_result_from_dict(self) -> None:
        """Test result deserialization from dictionary."""
        data = {
            "task_id": "result-123",
            "worker_id": "worker-1",
            "status": "failed",
            "duration": 10.0,
            "crash_found": True,
            "coverage_delta": 0.1,
            "error_message": "Test error",
            "output_data": {"key": "value"},
        }

        result = TaskResult.from_dict(data)

        assert result.task_id == "result-123"
        assert result.worker_id == "worker-1"
        assert result.status == TaskStatus.FAILED
        assert result.crash_found is True

    def test_result_from_dict_missing_task_id(self) -> None:
        """Test result deserialization fails without task_id."""
        data = {"worker_id": "worker-1"}

        with pytest.raises(KeyError, match="task_id"):
            TaskResult.from_dict(data)

    def test_result_from_dict_missing_worker_id(self) -> None:
        """Test result deserialization fails without worker_id."""
        data = {"task_id": "task-123"}

        with pytest.raises(KeyError, match="worker_id"):
            TaskResult.from_dict(data)


# =============================================================================
# TestInMemoryTaskQueue
# =============================================================================


class TestInMemoryTaskQueue:
    """Tests for InMemoryTaskQueue class."""

    @pytest.fixture
    def queue(self) -> InMemoryTaskQueue:
        """Create in-memory queue for testing."""
        return InMemoryTaskQueue()

    def test_queue_creation(self, queue: InMemoryTaskQueue) -> None:
        """Test queue initialization."""
        stats = queue.get_stats()

        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["results"] == 0
        assert stats["completed"] == 0
        assert stats["crashes"] == 0

    def test_connect_disconnect_noop(self, queue: InMemoryTaskQueue) -> None:
        """Test connect/disconnect are no-ops."""
        queue.connect()  # Should not raise
        queue.disconnect()  # Should not raise

        # Verify queue is still functional
        assert queue is not None

    def test_enqueue_single_task(self, queue: InMemoryTaskQueue) -> None:
        """Test enqueueing a single task."""
        task = FuzzingTask(task_id="test-1")

        queue.enqueue(task)

        stats = queue.get_stats()
        assert stats["pending"] == 1

    def test_enqueue_batch(self, queue: InMemoryTaskQueue) -> None:
        """Test enqueueing multiple tasks."""
        tasks = [FuzzingTask(task_id=f"test-{i}") for i in range(5)]

        queue.enqueue_batch(tasks)

        stats = queue.get_stats()
        assert stats["pending"] == 5

    def test_claim_task_returns_task(self, queue: InMemoryTaskQueue) -> None:
        """Test claiming a task returns the task."""
        task = FuzzingTask(task_id="claim-test")
        queue.enqueue(task)

        claimed = queue.claim_task("worker-1")

        assert claimed is not None
        assert claimed.task_id == "claim-test"

    def test_claim_task_empty_queue(self, queue: InMemoryTaskQueue) -> None:
        """Test claiming from empty queue returns None."""
        claimed = queue.claim_task("worker-1")

        assert claimed is None

    def test_claim_task_priority_order(self, queue: InMemoryTaskQueue) -> None:
        """Test tasks are claimed in priority order."""
        low = FuzzingTask(task_id="low", priority=TaskPriority.LOW)
        high = FuzzingTask(task_id="high", priority=TaskPriority.HIGH)
        normal = FuzzingTask(task_id="normal", priority=TaskPriority.NORMAL)

        queue.enqueue(low)
        queue.enqueue(normal)
        queue.enqueue(high)

        first = queue.claim_task("worker-1")
        second = queue.claim_task("worker-1")
        third = queue.claim_task("worker-1")

        assert first.task_id == "high"
        assert second.task_id == "normal"
        assert third.task_id == "low"

    def test_claim_task_moves_to_in_progress(self, queue: InMemoryTaskQueue) -> None:
        """Test claiming moves task to in_progress."""
        task = FuzzingTask(task_id="progress-test")
        queue.enqueue(task)

        queue.claim_task("worker-1")

        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 1

    def test_submit_result_removes_in_progress(self, queue: InMemoryTaskQueue) -> None:
        """Test submitting result removes from in_progress."""
        task = FuzzingTask(task_id="result-test")
        queue.enqueue(task)
        queue.claim_task("worker-1")

        result = TaskResult(task_id="result-test", worker_id="worker-1")
        queue.submit_result(result)

        stats = queue.get_stats()
        assert stats["in_progress"] == 0
        assert stats["results"] == 1
        assert stats["completed"] == 1

    def test_submit_result_crash_stats(self, queue: InMemoryTaskQueue) -> None:
        """Test crash count is incremented."""
        task = FuzzingTask(task_id="crash-test")
        queue.enqueue(task)
        queue.claim_task("worker-1")

        result = TaskResult(
            task_id="crash-test",
            worker_id="worker-1",
            crash_found=True,
        )
        queue.submit_result(result)

        stats = queue.get_stats()
        assert stats["crashes"] == 1

    def test_get_results(self, queue: InMemoryTaskQueue) -> None:
        """Test retrieving results."""
        # Submit some results
        for i in range(3):
            result = TaskResult(task_id=f"task-{i}", worker_id="worker-1")
            queue._results.append(result)

        results = queue.get_results(count=2)

        assert len(results) == 2
        assert results[0].task_id == "task-0"
        assert results[1].task_id == "task-1"

        # Remaining results
        remaining = queue.get_results()
        assert len(remaining) == 1
        assert remaining[0].task_id == "task-2"

    def test_requeue_stale_tasks_returns_zero(self, queue: InMemoryTaskQueue) -> None:
        """Test requeue_stale_tasks returns 0 for in-memory queue."""
        result = queue.requeue_stale_tasks()

        assert result == 0

    def test_clear(self, queue: InMemoryTaskQueue) -> None:
        """Test clearing the queue."""
        queue.enqueue(FuzzingTask(task_id="test-1"))
        queue.claim_task("worker-1")
        queue._results.append(TaskResult(task_id="test-1", worker_id="worker-1"))

        queue.clear()

        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["results"] == 0
        assert stats["completed"] == 0
        assert stats["crashes"] == 0


# =============================================================================
# TestTaskQueueRedis
# =============================================================================


class TestTaskQueueRedis:
    """Tests for TaskQueue with mocked Redis."""

    @pytest.fixture
    def mock_redis_module(self):
        """Mock the redis module."""
        with patch("dicom_fuzzer.distributed.queue.HAS_REDIS", True):
            with patch("dicom_fuzzer.distributed.queue.redis") as mock_redis:
                mock_client = MagicMock()
                mock_redis.from_url.return_value = mock_client
                yield mock_client

    def test_init_without_redis_raises(self) -> None:
        """Test initialization fails without redis installed."""
        with patch("dicom_fuzzer.distributed.queue.HAS_REDIS", False):
            with pytest.raises(ImportError, match="redis is required"):
                TaskQueue()

    def test_init_with_redis(self, mock_redis_module: MagicMock) -> None:
        """Test initialization with redis available."""
        queue = TaskQueue(redis_url="redis://localhost:6379")

        assert queue.redis_url == "redis://localhost:6379"
        assert queue.visibility_timeout == 300
        assert queue.max_retries == 3

    def test_connect_success(self, mock_redis_module: MagicMock) -> None:
        """Test successful connection."""
        queue = TaskQueue()

        queue.connect()

        mock_redis_module.ping.assert_called_once()

    def test_connect_failure(self, mock_redis_module: MagicMock) -> None:
        """Test connection failure."""
        mock_redis_module.ping.side_effect = Exception("Connection refused")

        queue = TaskQueue()

        with pytest.raises(Exception, match="Connection refused"):
            queue.connect()

    def test_connect_already_connected(self, mock_redis_module: MagicMock) -> None:
        """Test connect is no-op if already connected."""
        queue = TaskQueue()
        queue.connect()

        # Second connect should not call ping again
        mock_redis_module.ping.reset_mock()
        queue.connect()

        mock_redis_module.ping.assert_not_called()

    def test_disconnect(self, mock_redis_module: MagicMock) -> None:
        """Test disconnection."""
        queue = TaskQueue()
        queue.connect()

        queue.disconnect()

        mock_redis_module.close.assert_called_once()

    def test_enqueue_stores_task(self, mock_redis_module: MagicMock) -> None:
        """Test enqueueing stores task in Redis."""
        queue = TaskQueue()
        task = FuzzingTask(task_id="redis-task")

        queue.enqueue(task)

        # Check set was called for task data
        mock_redis_module.set.assert_called()
        # Check zadd was called for priority queue
        mock_redis_module.zadd.assert_called()

    def test_enqueue_batch_uses_pipeline(self, mock_redis_module: MagicMock) -> None:
        """Test batch enqueue uses pipeline."""
        mock_pipe = MagicMock()
        mock_redis_module.pipeline.return_value = mock_pipe

        queue = TaskQueue()
        tasks = [FuzzingTask(task_id=f"batch-{i}") for i in range(3)]

        queue.enqueue_batch(tasks)

        # Pipeline should be used
        mock_redis_module.pipeline.assert_called_once()
        mock_pipe.execute.assert_called_once()

    def test_claim_task_pops_from_queue(self, mock_redis_module: MagicMock) -> None:
        """Test claiming pops from priority queue."""
        mock_redis_module.zpopmax.return_value = [(b"task-123", 1.0)]
        mock_redis_module.get.return_value = json.dumps(
            {
                "task_id": "task-123",
                "test_file": "/test.dcm",
            }
        )

        queue = TaskQueue()
        claimed = queue.claim_task("worker-1")

        mock_redis_module.zpopmax.assert_called()
        assert claimed is not None
        assert claimed.task_id == "task-123"

    def test_claim_task_string_task_id(self, mock_redis_module: MagicMock) -> None:
        """Test claiming handles string task_id (not bytes)."""
        mock_redis_module.zpopmax.return_value = [("task-string", 1.0)]
        mock_redis_module.get.return_value = json.dumps(
            {
                "task_id": "task-string",
            }
        )

        queue = TaskQueue()
        claimed = queue.claim_task("worker-1")

        assert claimed.task_id == "task-string"

    def test_claim_task_missing_data(self, mock_redis_module: MagicMock) -> None:
        """Test claiming handles missing task data."""
        mock_redis_module.zpopmax.return_value = [(b"task-missing", 1.0)]
        mock_redis_module.get.return_value = None  # Data not found

        queue = TaskQueue()
        claimed = queue.claim_task("worker-1")

        assert claimed is None

    def test_claim_task_empty_queue(self, mock_redis_module: MagicMock) -> None:
        """Test claiming from empty queue returns None."""
        mock_redis_module.zpopmax.return_value = []

        queue = TaskQueue()
        claimed = queue.claim_task("worker-1")

        assert claimed is None

    def test_submit_result_pipeline(self, mock_redis_module: MagicMock) -> None:
        """Test result submission uses pipeline."""
        mock_pipe = MagicMock()
        mock_redis_module.pipeline.return_value = mock_pipe

        queue = TaskQueue()
        result = TaskResult(task_id="task-123", worker_id="worker-1")

        queue.submit_result(result)

        # Pipeline should be executed
        mock_pipe.execute.assert_called_once()

    def test_submit_result_with_crash(self, mock_redis_module: MagicMock) -> None:
        """Test result submission increments crash counter."""
        mock_pipe = MagicMock()
        mock_redis_module.pipeline.return_value = mock_pipe

        queue = TaskQueue()
        result = TaskResult(
            task_id="task-123",
            worker_id="worker-1",
            crash_found=True,
        )

        queue.submit_result(result)

        # Should call hincrby twice (completed and crashes)
        assert mock_pipe.hincrby.call_count >= 2

    def test_get_results_decodes_bytes(self, mock_redis_module: MagicMock) -> None:
        """Test get_results decodes byte strings."""
        result_data = json.dumps(
            {
                "task_id": "result-1",
                "worker_id": "worker-1",
                "status": "completed",
            }
        )
        mock_redis_module.rpop.side_effect = [
            result_data.encode(),  # bytes
            None,  # End of results
        ]

        queue = TaskQueue()
        results = queue.get_results(count=2)

        assert len(results) == 1
        assert results[0].task_id == "result-1"

    def test_get_results_handles_string(self, mock_redis_module: MagicMock) -> None:
        """Test get_results handles string responses."""
        result_data = json.dumps(
            {
                "task_id": "result-2",
                "worker_id": "worker-1",
                "status": "completed",
            }
        )
        mock_redis_module.rpop.side_effect = [
            result_data,  # Already string
            None,
        ]

        queue = TaskQueue()
        results = queue.get_results(count=1)

        assert len(results) == 1
        assert results[0].task_id == "result-2"

    def test_get_stats(self, mock_redis_module: MagicMock) -> None:
        """Test get_stats returns correct counts."""
        mock_redis_module.zcard.return_value = 5
        mock_redis_module.hlen.return_value = 2
        mock_redis_module.llen.side_effect = [10, 0]  # results, dead_letter
        mock_redis_module.hgetall.return_value = {
            b"completed": b"100",
            b"crashes": b"3",
        }

        queue = TaskQueue()
        stats = queue.get_stats()

        assert stats["pending"] == 5
        assert stats["in_progress"] == 2
        assert stats["results"] == 10
        assert stats["dead_letter"] == 0
        assert stats["completed"] == 100
        assert stats["crashes"] == 3

    def test_get_stats_handles_string_keys(self, mock_redis_module: MagicMock) -> None:
        """Test get_stats handles string keys in stats."""
        mock_redis_module.zcard.return_value = 0
        mock_redis_module.hlen.return_value = 0
        mock_redis_module.llen.return_value = 0
        mock_redis_module.hgetall.return_value = {
            "completed": "50",  # String keys
            "crashes": "1",
        }

        queue = TaskQueue()
        stats = queue.get_stats()

        assert stats["completed"] == 50
        assert stats["crashes"] == 1

    def test_requeue_stale_tasks(self, mock_redis_module: MagicMock) -> None:
        """Test requeuing stale tasks."""
        # Setup stale task
        current_time = time.time()
        claim_data = json.dumps(
            {
                "worker_id": "worker-1",
                "claimed_at": current_time - 400,  # 400 seconds ago
                "timeout": 300,  # 5 minute timeout
            }
        )
        mock_redis_module.hgetall.return_value = {
            b"stale-task": claim_data.encode(),
        }

        queue = TaskQueue()
        requeued = queue.requeue_stale_tasks()

        assert requeued == 1
        mock_redis_module.hdel.assert_called()
        mock_redis_module.zadd.assert_called()

    def test_requeue_stale_tasks_not_stale(self, mock_redis_module: MagicMock) -> None:
        """Test tasks not requeued if not stale."""
        current_time = time.time()
        claim_data = json.dumps(
            {
                "worker_id": "worker-1",
                "claimed_at": current_time - 60,  # Only 60 seconds ago
                "timeout": 300,
            }
        )
        mock_redis_module.hgetall.return_value = {
            b"fresh-task": claim_data.encode(),
        }

        queue = TaskQueue()
        requeued = queue.requeue_stale_tasks()

        assert requeued == 0

    def test_clear_deletes_all_keys(self, mock_redis_module: MagicMock) -> None:
        """Test clear deletes all queue keys."""
        mock_pipe = MagicMock()
        mock_redis_module.pipeline.return_value = mock_pipe
        mock_redis_module.scan_iter.return_value = [
            b"dicom_fuzzer:task:1",
            b"dicom_fuzzer:task:2",
        ]

        queue = TaskQueue()
        queue.clear()

        mock_pipe.execute.assert_called_once()
        # Should delete task data keys
        assert mock_pipe.delete.call_count >= 5  # 5 queue keys + task data


# =============================================================================
# TestCreateTaskQueue
# =============================================================================


class TestCreateTaskQueue:
    """Tests for create_task_queue factory function."""

    def test_create_in_memory_queue_no_url(self) -> None:
        """Test creating in-memory queue when no URL provided."""
        queue = create_task_queue(redis_url=None)

        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_in_memory_queue_no_redis(self) -> None:
        """Test fallback to in-memory when redis not installed."""
        with patch("dicom_fuzzer.distributed.queue.HAS_REDIS", False):
            queue = create_task_queue(redis_url="redis://localhost:6379")

        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_redis_queue_connection_fails(self) -> None:
        """Test fallback to in-memory when connection fails."""
        with patch("dicom_fuzzer.distributed.queue.HAS_REDIS", True):
            with patch("dicom_fuzzer.distributed.queue.redis") as mock_redis:
                mock_client = MagicMock()
                mock_redis.from_url.return_value = mock_client
                mock_client.ping.side_effect = Exception("Connection failed")

                queue = create_task_queue(redis_url="redis://localhost:6379")

        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_redis_queue_success(self) -> None:
        """Test creating Redis queue when connection succeeds."""
        with patch("dicom_fuzzer.distributed.queue.HAS_REDIS", True):
            with patch("dicom_fuzzer.distributed.queue.redis") as mock_redis:
                mock_client = MagicMock()
                mock_redis.from_url.return_value = mock_client

                queue = create_task_queue(redis_url="redis://localhost:6379")

        assert isinstance(queue, TaskQueue)


# =============================================================================
# TestTaskQueueIntegration
# =============================================================================


class TestTaskQueueIntegration:
    """Integration tests using InMemoryTaskQueue."""

    def test_full_workflow(self) -> None:
        """Test complete task lifecycle."""
        queue = InMemoryTaskQueue()

        # 1. Enqueue tasks with different priorities
        tasks = [
            FuzzingTask(task_id="high-1", priority=TaskPriority.HIGH),
            FuzzingTask(task_id="normal-1", priority=TaskPriority.NORMAL),
            FuzzingTask(task_id="critical-1", priority=TaskPriority.CRITICAL),
        ]
        queue.enqueue_batch(tasks)

        # 2. Claim tasks (should be in priority order)
        claimed1 = queue.claim_task("worker-1")
        assert claimed1.task_id == "critical-1"

        claimed2 = queue.claim_task("worker-2")
        assert claimed2.task_id == "high-1"

        # 3. Submit results
        result1 = TaskResult(
            task_id="critical-1",
            worker_id="worker-1",
            crash_found=True,
        )
        queue.submit_result(result1)

        result2 = TaskResult(
            task_id="high-1",
            worker_id="worker-2",
            crash_found=False,
        )
        queue.submit_result(result2)

        # 4. Check stats
        stats = queue.get_stats()
        assert stats["pending"] == 1  # normal-1 still pending
        assert stats["in_progress"] == 0
        assert stats["completed"] == 2
        assert stats["crashes"] == 1

        # 5. Get results
        results = queue.get_results()
        assert len(results) == 2

    def test_multiple_workers(self) -> None:
        """Test multiple workers claiming tasks."""
        queue = InMemoryTaskQueue()

        # Enqueue many tasks
        for i in range(10):
            queue.enqueue(FuzzingTask(task_id=f"task-{i}"))

        # Multiple workers claim tasks
        claimed_by_worker1 = []
        claimed_by_worker2 = []

        for _ in range(5):
            task1 = queue.claim_task("worker-1")
            if task1:
                claimed_by_worker1.append(task1)

            task2 = queue.claim_task("worker-2")
            if task2:
                claimed_by_worker2.append(task2)

        # All tasks should be claimed
        total_claimed = len(claimed_by_worker1) + len(claimed_by_worker2)
        assert total_claimed == 10

        # No duplicates
        all_ids = [t.task_id for t in claimed_by_worker1 + claimed_by_worker2]
        assert len(all_ids) == len(set(all_ids))
