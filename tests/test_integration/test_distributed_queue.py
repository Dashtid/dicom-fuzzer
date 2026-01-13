"""Tests for the distributed queue module.

This module tests TaskQueue, InMemoryTaskQueue, and related classes.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from datetime import datetime
from typing import Any

import pytest

from dicom_fuzzer.distributed.queue import (
    FuzzingTask,
    InMemoryTaskQueue,
    TaskPriority,
    TaskResult,
    TaskStatus,
    create_task_queue,
)


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_values(self) -> None:
        """Test enum values."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.IN_PROGRESS.value == "in_progress"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.TIMEOUT.value == "timeout"


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_values(self) -> None:
        """Test priority values are ordered correctly."""
        assert TaskPriority.LOW.value == 0
        assert TaskPriority.NORMAL.value == 1
        assert TaskPriority.HIGH.value == 2
        assert TaskPriority.CRITICAL.value == 3

    def test_comparison(self) -> None:
        """Test priorities can be compared."""
        assert TaskPriority.LOW.value < TaskPriority.NORMAL.value
        assert TaskPriority.NORMAL.value < TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value < TaskPriority.CRITICAL.value


class TestFuzzingTask:
    """Tests for FuzzingTask dataclass."""

    def test_default_values(self) -> None:
        """Test default task values."""
        task = FuzzingTask()
        assert task.task_id is not None
        assert len(task.task_id) == 36  # UUID length
        assert task.test_file == ""
        assert task.target_executable == ""
        assert task.timeout == 30.0
        assert task.strategy == "coverage_guided"
        assert task.priority == TaskPriority.NORMAL
        assert isinstance(task.created_at, datetime)
        assert task.metadata == {}

    def test_custom_values(self) -> None:
        """Test custom task values."""
        task = FuzzingTask(
            task_id="custom-id",
            test_file="/path/to/test.dcm",
            target_executable="/path/to/target",
            timeout=60.0,
            strategy="mutation_based",
            priority=TaskPriority.HIGH,
            metadata={"key": "value"},
        )
        assert task.task_id == "custom-id"
        assert task.test_file == "/path/to/test.dcm"
        assert task.target_executable == "/path/to/target"
        assert task.timeout == 60.0
        assert task.strategy == "mutation_based"
        assert task.priority == TaskPriority.HIGH
        assert task.metadata == {"key": "value"}

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        now = datetime.now()
        task = FuzzingTask(
            task_id="test-id",
            test_file="test.dcm",
            target_executable="target.exe",
            timeout=45.0,
            strategy="random",
            priority=TaskPriority.CRITICAL,
            created_at=now,
            metadata={"foo": "bar"},
        )
        result = task.to_dict()

        assert result["task_id"] == "test-id"
        assert result["test_file"] == "test.dcm"
        assert result["target_executable"] == "target.exe"
        assert result["timeout"] == 45.0
        assert result["strategy"] == "random"
        assert result["priority"] == TaskPriority.CRITICAL.value
        assert result["created_at"] == now.isoformat()
        assert result["metadata"] == {"foo": "bar"}

    def test_from_dict(self) -> None:
        """Test creation from dictionary."""
        now = datetime.now()
        data = {
            "task_id": "from-dict-id",
            "test_file": "input.dcm",
            "target_executable": "viewer.exe",
            "timeout": 120.0,
            "strategy": "coverage",
            "priority": TaskPriority.LOW.value,
            "created_at": now.isoformat(),
            "metadata": {"version": 1},
        }
        task = FuzzingTask.from_dict(data)

        assert task.task_id == "from-dict-id"
        assert task.test_file == "input.dcm"
        assert task.target_executable == "viewer.exe"
        assert task.timeout == 120.0
        assert task.strategy == "coverage"
        assert task.priority == TaskPriority.LOW
        assert task.metadata == {"version": 1}

    def test_from_dict_defaults(self) -> None:
        """Test from_dict with missing optional fields."""
        data: dict[str, Any] = {}
        task = FuzzingTask.from_dict(data)

        assert task.task_id is not None
        assert task.test_file == ""
        assert task.timeout == 30.0
        assert task.priority == TaskPriority.NORMAL

    def test_roundtrip(self) -> None:
        """Test to_dict/from_dict roundtrip."""
        original = FuzzingTask(
            test_file="test.dcm",
            timeout=50.0,
            priority=TaskPriority.HIGH,
        )
        data = original.to_dict()
        restored = FuzzingTask.from_dict(data)

        assert restored.task_id == original.task_id
        assert restored.test_file == original.test_file
        assert restored.timeout == original.timeout
        assert restored.priority == original.priority


class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_required_fields(self) -> None:
        """Test result with required fields."""
        result = TaskResult(task_id="task-1", worker_id="worker-1")
        assert result.task_id == "task-1"
        assert result.worker_id == "worker-1"
        assert result.status == TaskStatus.COMPLETED
        assert result.duration == 0.0
        assert result.crash_found is False
        assert result.coverage_delta == 0.0
        assert result.error_message == ""
        assert result.output_data == {}

    def test_full_result(self) -> None:
        """Test result with all fields."""
        result = TaskResult(
            task_id="task-2",
            worker_id="worker-2",
            status=TaskStatus.FAILED,
            duration=15.5,
            crash_found=True,
            coverage_delta=2.5,
            error_message="Segmentation fault",
            output_data={"crash_file": "crash_001.dcm"},
        )
        assert result.status == TaskStatus.FAILED
        assert result.duration == 15.5
        assert result.crash_found is True
        assert result.coverage_delta == 2.5
        assert result.error_message == "Segmentation fault"
        assert result.output_data == {"crash_file": "crash_001.dcm"}

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        result = TaskResult(
            task_id="task-3",
            worker_id="worker-3",
            status=TaskStatus.TIMEOUT,
            duration=30.0,
        )
        data = result.to_dict()

        assert data["task_id"] == "task-3"
        assert data["worker_id"] == "worker-3"
        assert data["status"] == "timeout"
        assert data["duration"] == 30.0

    def test_from_dict(self) -> None:
        """Test creation from dictionary."""
        data = {
            "task_id": "task-4",
            "worker_id": "worker-4",
            "status": "completed",
            "duration": 5.0,
            "crash_found": True,
            "coverage_delta": 1.5,
        }
        result = TaskResult.from_dict(data)

        assert result.task_id == "task-4"
        assert result.worker_id == "worker-4"
        assert result.status == TaskStatus.COMPLETED
        assert result.crash_found is True

    def test_from_dict_missing_task_id(self) -> None:
        """Test from_dict raises error without task_id."""
        with pytest.raises(KeyError, match="task_id"):
            TaskResult.from_dict({"worker_id": "w1"})

    def test_from_dict_missing_worker_id(self) -> None:
        """Test from_dict raises error without worker_id."""
        with pytest.raises(KeyError, match="worker_id"):
            TaskResult.from_dict({"task_id": "t1"})


class TestInMemoryTaskQueue:
    """Tests for InMemoryTaskQueue class."""

    def test_initialization(self) -> None:
        """Test queue initializes empty."""
        queue = InMemoryTaskQueue()
        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["completed"] == 0

    def test_enqueue_single(self) -> None:
        """Test enqueueing a single task."""
        queue = InMemoryTaskQueue()
        task = FuzzingTask(test_file="test.dcm")
        queue.enqueue(task)
        stats = queue.get_stats()
        assert stats["pending"] == 1

    def test_enqueue_multiple(self) -> None:
        """Test enqueueing multiple tasks."""
        queue = InMemoryTaskQueue()
        for i in range(5):
            queue.enqueue(FuzzingTask(test_file=f"test_{i}.dcm"))
        stats = queue.get_stats()
        assert stats["pending"] == 5

    def test_enqueue_batch(self) -> None:
        """Test enqueueing batch of tasks."""
        queue = InMemoryTaskQueue()
        tasks = [FuzzingTask(test_file=f"test_{i}.dcm") for i in range(10)]
        queue.enqueue_batch(tasks)
        stats = queue.get_stats()
        assert stats["pending"] == 10

    def test_claim_task(self) -> None:
        """Test claiming a task."""
        queue = InMemoryTaskQueue()
        task = FuzzingTask(test_file="test.dcm")
        queue.enqueue(task)

        claimed = queue.claim_task("worker-1")
        assert claimed is not None
        assert claimed.task_id == task.task_id
        assert claimed.test_file == "test.dcm"

    def test_claim_empty_queue(self) -> None:
        """Test claiming from empty queue returns None."""
        queue = InMemoryTaskQueue()
        claimed = queue.claim_task("worker-1")
        assert claimed is None

    def test_priority_ordering(self) -> None:
        """Test tasks are claimed in priority order."""
        queue = InMemoryTaskQueue()

        low = FuzzingTask(test_file="low.dcm", priority=TaskPriority.LOW)
        normal = FuzzingTask(test_file="normal.dcm", priority=TaskPriority.NORMAL)
        high = FuzzingTask(test_file="high.dcm", priority=TaskPriority.HIGH)
        critical = FuzzingTask(test_file="critical.dcm", priority=TaskPriority.CRITICAL)

        # Enqueue in random order
        queue.enqueue(normal)
        queue.enqueue(low)
        queue.enqueue(critical)
        queue.enqueue(high)

        # Should come out in priority order (highest first)
        claimed1 = queue.claim_task("w1")
        claimed2 = queue.claim_task("w2")
        claimed3 = queue.claim_task("w3")
        claimed4 = queue.claim_task("w4")

        assert claimed1 is not None and claimed1.test_file == "critical.dcm"
        assert claimed2 is not None and claimed2.test_file == "high.dcm"
        assert claimed3 is not None and claimed3.test_file == "normal.dcm"
        assert claimed4 is not None and claimed4.test_file == "low.dcm"

    def test_submit_result(self) -> None:
        """Test submitting task result."""
        queue = InMemoryTaskQueue()
        task = FuzzingTask(test_file="test.dcm")
        queue.enqueue(task)

        claimed = queue.claim_task("worker-1")
        assert claimed is not None

        result = TaskResult(
            task_id=claimed.task_id,
            worker_id="worker-1",
            status=TaskStatus.COMPLETED,
        )
        queue.submit_result(result)

        # Check stats updated
        stats = queue.get_stats()
        assert stats["completed"] == 1
        assert stats["in_progress"] == 0

    def test_submit_result_with_crash(self) -> None:
        """Test submitting result with crash updates stats."""
        queue = InMemoryTaskQueue()
        task = FuzzingTask(test_file="test.dcm")
        queue.enqueue(task)

        claimed = queue.claim_task("worker-1")
        assert claimed is not None

        result = TaskResult(
            task_id=claimed.task_id,
            worker_id="worker-1",
            status=TaskStatus.COMPLETED,
            crash_found=True,
        )
        queue.submit_result(result)

        stats = queue.get_stats()
        assert stats["crashes"] == 1

    def test_get_results(self) -> None:
        """Test getting results."""
        queue = InMemoryTaskQueue()

        # Enqueue and process tasks
        for i in range(5):
            task = FuzzingTask(test_file=f"test_{i}.dcm")
            queue.enqueue(task)

        for i in range(5):
            claimed = queue.claim_task(f"worker-{i}")
            assert claimed is not None
            result = TaskResult(
                task_id=claimed.task_id,
                worker_id=f"worker-{i}",
            )
            queue.submit_result(result)

        # Get results
        results = queue.get_results(count=3)
        assert len(results) == 3

        # Remaining results
        results = queue.get_results(count=10)
        assert len(results) == 2

    def test_get_stats(self) -> None:
        """Test getting queue statistics."""
        queue = InMemoryTaskQueue()

        # Enqueue tasks
        for i in range(5):
            queue.enqueue(FuzzingTask(test_file=f"test_{i}.dcm"))

        # Claim and complete one with crash
        task = queue.claim_task("w1")
        assert task is not None
        queue.submit_result(
            TaskResult(task_id=task.task_id, worker_id="w1", crash_found=True)
        )

        stats = queue.get_stats()
        assert stats["pending"] == 4
        assert stats["in_progress"] == 0
        assert stats["completed"] == 1
        assert stats["crashes"] == 1
        assert stats["results"] == 1  # One result in the results list

    def test_clear(self) -> None:
        """Test clearing the queue."""
        queue = InMemoryTaskQueue()
        for i in range(10):
            queue.enqueue(FuzzingTask(test_file=f"test_{i}.dcm"))

        stats = queue.get_stats()
        assert stats["pending"] == 10

        queue.clear()

        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["completed"] == 0

    def test_connect_disconnect(self) -> None:
        """Test connect/disconnect (no-op for in-memory)."""
        queue = InMemoryTaskQueue()
        queue.connect()  # Should not raise
        queue.disconnect()  # Should not raise

        # Verify queue is still functional
        assert queue is not None

    def test_requeue_stale_tasks(self) -> None:
        """Test requeue_stale_tasks returns 0 for in-memory queue."""
        queue = InMemoryTaskQueue()
        task = FuzzingTask(test_file="test.dcm")
        queue.enqueue(task)
        queue.claim_task("worker-1")

        # In-memory queue doesn't track visibility timeouts
        requeued = queue.requeue_stale_tasks()
        assert requeued == 0

    def test_claim_removes_from_pending(self) -> None:
        """Test claiming removes task from pending and adds to in_progress."""
        queue = InMemoryTaskQueue()
        task = FuzzingTask(test_file="test.dcm")
        queue.enqueue(task)

        stats = queue.get_stats()
        assert stats["pending"] == 1
        assert stats["in_progress"] == 0

        queue.claim_task("worker-1")

        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 1

    def test_concurrent_claim(self) -> None:
        """Test concurrent task claiming."""
        queue = InMemoryTaskQueue()
        for i in range(100):
            queue.enqueue(FuzzingTask(test_file=f"test_{i}.dcm"))

        claimed_tasks: list[FuzzingTask] = []
        lock = threading.Lock()

        def claim_tasks(worker_id: str) -> None:
            while True:
                task = queue.claim_task(worker_id)
                if task is None:
                    break
                with lock:
                    claimed_tasks.append(task)

        threads = [
            threading.Thread(target=claim_tasks, args=(f"w{i}",)) for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All tasks should be claimed exactly once
        assert len(claimed_tasks) == 100
        task_ids = [t.task_id for t in claimed_tasks]
        assert len(set(task_ids)) == 100  # No duplicates


class TestCreateTaskQueue:
    """Tests for create_task_queue factory function."""

    def test_create_in_memory_with_none(self) -> None:
        """Test creating in-memory queue when no redis URL."""
        queue = create_task_queue(None)
        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_in_memory_with_empty_string(self) -> None:
        """Test creating in-memory queue with empty string falls back to in-memory."""
        # Empty string is falsy, so it creates in-memory queue
        queue = create_task_queue("")
        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_with_invalid_redis_falls_back(self) -> None:
        """Test creating with invalid Redis URL falls back to in-memory."""
        # This should fail to connect and fall back to in-memory
        queue = create_task_queue("redis://invalid-host-that-does-not-exist:6379")
        assert isinstance(queue, InMemoryTaskQueue)


# ============================================================================
# Test TaskQueue with mocked Redis
# ============================================================================


# Check if redis is available
HAS_REDIS = importlib.util.find_spec("redis") is not None


@pytest.mark.skipif(not HAS_REDIS, reason="redis package not installed")
class TestTaskQueueMocked:
    """Tests for TaskQueue with mocked Redis client."""

    @pytest.fixture
    def mock_redis(self, mocker):
        """Create a mock Redis client."""
        mock_client = mocker.MagicMock()
        mock_client.ping.return_value = True
        return mock_client

    @pytest.fixture
    def queue_with_mock(self, mocker, mock_redis):
        """Create TaskQueue with mocked Redis."""
        from dicom_fuzzer.distributed.queue import TaskQueue

        # Mock redis.from_url
        mocker.patch(
            "dicom_fuzzer.distributed.queue.redis.from_url",
            return_value=mock_redis,
        )

        queue = TaskQueue(redis_url="redis://localhost:6379")
        return queue, mock_redis

    def test_connect_success(self, queue_with_mock):
        """Test successful connection."""
        queue, mock_redis = queue_with_mock
        queue.connect()

        assert queue._connected is True
        mock_redis.ping.assert_called_once()

    def test_connect_already_connected(self, queue_with_mock):
        """Test connect when already connected."""
        queue, mock_redis = queue_with_mock
        queue.connect()
        mock_redis.ping.reset_mock()

        # Second connect should be no-op
        queue.connect()
        mock_redis.ping.assert_not_called()

    def test_disconnect(self, queue_with_mock):
        """Test disconnect."""
        queue, mock_redis = queue_with_mock
        queue.connect()
        queue.disconnect()

        assert queue._connected is False
        mock_redis.close.assert_called_once()

    def test_enqueue(self, queue_with_mock):
        """Test enqueueing a task."""
        queue, mock_redis = queue_with_mock
        task = FuzzingTask(task_id="test-task", test_file="test.dcm")

        queue.enqueue(task)

        mock_redis.set.assert_called_once()
        mock_redis.zadd.assert_called_once()

    def test_enqueue_batch(self, queue_with_mock):
        """Test enqueueing batch of tasks."""
        queue, mock_redis = queue_with_mock
        mock_pipe = mock_redis.pipeline.return_value

        tasks = [
            FuzzingTask(task_id=f"task-{i}", test_file=f"test_{i}.dcm")
            for i in range(3)
        ]

        queue.enqueue_batch(tasks)

        assert mock_pipe.set.call_count == 3
        assert mock_pipe.zadd.call_count == 3
        mock_pipe.execute.assert_called_once()

    def test_claim_task_success(self, queue_with_mock):
        """Test claiming a task successfully."""
        queue, mock_redis = queue_with_mock

        task_data = {
            "task_id": "test-task",
            "test_file": "test.dcm",
            "target_executable": "target.exe",
            "timeout": 30.0,
            "strategy": "coverage_guided",
            "priority": 1,
            "created_at": "2024-01-01T00:00:00",
            "metadata": {},
        }

        mock_redis.zpopmax.return_value = [(b"test-task", 1.0)]
        mock_redis.get.return_value = json.dumps(task_data).encode()

        claimed = queue.claim_task("worker-1")

        assert claimed is not None
        assert claimed.task_id == "test-task"
        mock_redis.hset.assert_called_once()

    def test_claim_task_empty_queue(self, queue_with_mock):
        """Test claiming from empty queue."""
        queue, mock_redis = queue_with_mock
        mock_redis.zpopmax.return_value = []

        claimed = queue.claim_task("worker-1")

        assert claimed is None

    def test_claim_task_missing_data(self, queue_with_mock):
        """Test claiming when task data is missing."""
        queue, mock_redis = queue_with_mock
        mock_redis.zpopmax.return_value = [("test-task", 1.0)]
        mock_redis.get.return_value = None

        claimed = queue.claim_task("worker-1")

        assert claimed is None

    def test_submit_result(self, queue_with_mock):
        """Test submitting a result."""
        queue, mock_redis = queue_with_mock
        mock_pipe = mock_redis.pipeline.return_value

        result = TaskResult(
            task_id="test-task",
            worker_id="worker-1",
            status=TaskStatus.COMPLETED,
            crash_found=True,
        )

        queue.submit_result(result)

        mock_pipe.hdel.assert_called_once()
        mock_pipe.lpush.assert_called_once()
        assert mock_pipe.hincrby.call_count == 2  # completed + crashes
        mock_pipe.delete.assert_called_once()
        mock_pipe.execute.assert_called_once()

    def test_get_results(self, queue_with_mock):
        """Test getting results."""
        queue, mock_redis = queue_with_mock

        result_data = {
            "task_id": "task-1",
            "worker_id": "worker-1",
            "status": "completed",
            "duration": 5.0,
            "crash_found": False,
            "coverage_delta": 1.0,
            "error_message": "",
            "output_data": {},
        }
        mock_redis.rpop.side_effect = [json.dumps(result_data).encode(), None]

        results = queue.get_results(count=10)

        assert len(results) == 1
        assert results[0].task_id == "task-1"

    def test_get_stats(self, queue_with_mock):
        """Test getting queue statistics."""
        queue, mock_redis = queue_with_mock

        mock_redis.zcard.return_value = 10
        mock_redis.hlen.return_value = 5
        mock_redis.llen.side_effect = [3, 1]  # results, dead_letter
        mock_redis.hgetall.return_value = {b"completed": b"50", b"crashes": b"2"}

        stats = queue.get_stats()

        assert stats["pending"] == 10
        assert stats["in_progress"] == 5
        assert stats["results"] == 3
        assert stats["dead_letter"] == 1
        assert stats["completed"] == 50
        assert stats["crashes"] == 2

    def test_requeue_stale_tasks(self, queue_with_mock):
        """Test requeuing stale tasks."""
        import time

        queue, mock_redis = queue_with_mock

        # Task claimed 1000 seconds ago with 60 second timeout
        old_claim_time = time.time() - 1000
        claim_data = json.dumps(
            {
                "worker_id": "worker-1",
                "claimed_at": old_claim_time,
                "timeout": 60,
            }
        )

        mock_redis.hgetall.return_value = {
            b"stale-task-1": claim_data.encode(),
        }

        requeued = queue.requeue_stale_tasks()

        assert requeued == 1
        mock_redis.hdel.assert_called_once()
        mock_redis.zadd.assert_called_once()

    def test_requeue_no_stale_tasks(self, queue_with_mock):
        """Test requeue when no tasks are stale."""
        import time

        queue, mock_redis = queue_with_mock

        # Task just claimed
        claim_data = json.dumps(
            {
                "worker_id": "worker-1",
                "claimed_at": time.time(),
                "timeout": 60,
            }
        )

        mock_redis.hgetall.return_value = {
            b"fresh-task": claim_data.encode(),
        }

        requeued = queue.requeue_stale_tasks()

        assert requeued == 0

    def test_clear(self, queue_with_mock):
        """Test clearing all queues."""
        queue, mock_redis = queue_with_mock
        mock_pipe = mock_redis.pipeline.return_value
        mock_redis.scan_iter.return_value = [b"task:1", b"task:2"]

        queue.clear()

        assert mock_pipe.delete.call_count >= 5
        mock_pipe.execute.assert_called_once()


# ============================================================================
# Test TaskQueue with fakeredis (realistic Redis behavior)
# ============================================================================

# Check if fakeredis is available
try:
    import fakeredis

    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False


@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis package not installed")
class TestTaskQueueFakeredis:
    """Tests for TaskQueue using fakeredis for realistic Redis behavior."""

    @pytest.fixture
    def fake_redis_server(self):
        """Create a fakeredis server for realistic multi-connection testing."""
        return fakeredis.FakeServer()

    @pytest.fixture
    def fake_redis(self, fake_redis_server):
        """Create a fakeredis client."""
        return fakeredis.FakeStrictRedis(server=fake_redis_server)

    @pytest.fixture
    def task_queue(self, mocker, fake_redis):
        """Create TaskQueue with fakeredis."""
        from dicom_fuzzer.distributed.queue import TaskQueue

        mocker.patch(
            "dicom_fuzzer.distributed.queue.redis.from_url",
            return_value=fake_redis,
        )
        queue = TaskQueue(redis_url="redis://fake:6379")
        queue.connect()
        yield queue
        queue.disconnect()

    def test_full_workflow(self, task_queue):
        """Test complete task workflow: enqueue -> claim -> submit -> get results."""
        # Enqueue a task
        task = FuzzingTask(
            task_id="workflow-task",
            test_file="test.dcm",
            target_executable="target.exe",
            priority=TaskPriority.HIGH,
        )
        task_queue.enqueue(task)

        # Verify pending
        stats = task_queue.get_stats()
        assert stats["pending"] == 1
        assert stats["in_progress"] == 0

        # Claim task
        claimed = task_queue.claim_task("worker-1")
        assert claimed is not None
        assert claimed.task_id == "workflow-task"

        # Verify in progress
        stats = task_queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 1

        # Submit result
        result = TaskResult(
            task_id="workflow-task",
            worker_id="worker-1",
            status=TaskStatus.COMPLETED,
            duration=5.0,
            crash_found=True,
        )
        task_queue.submit_result(result)

        # Verify completed
        stats = task_queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["completed"] == 1
        assert stats["crashes"] == 1

        # Get results
        results = task_queue.get_results(count=10)
        assert len(results) == 1
        assert results[0].task_id == "workflow-task"
        assert results[0].crash_found is True

    def test_priority_ordering_fakeredis(self, task_queue):
        """Test priority-based task ordering with real Redis sorted set."""
        # Enqueue tasks in mixed order
        tasks = [
            FuzzingTask(task_id="low", priority=TaskPriority.LOW),
            FuzzingTask(task_id="critical", priority=TaskPriority.CRITICAL),
            FuzzingTask(task_id="normal", priority=TaskPriority.NORMAL),
            FuzzingTask(task_id="high", priority=TaskPriority.HIGH),
        ]
        for t in tasks:
            task_queue.enqueue(t)

        # Should claim in priority order (highest first)
        claimed1 = task_queue.claim_task("w1")
        claimed2 = task_queue.claim_task("w2")
        claimed3 = task_queue.claim_task("w3")
        claimed4 = task_queue.claim_task("w4")

        assert claimed1 is not None and claimed1.task_id == "critical"
        assert claimed2 is not None and claimed2.task_id == "high"
        assert claimed3 is not None and claimed3.task_id == "normal"
        assert claimed4 is not None and claimed4.task_id == "low"

    def test_batch_enqueue(self, task_queue):
        """Test batch enqueueing with atomic pipeline."""
        tasks = [
            FuzzingTask(task_id=f"batch-{i}", test_file=f"test_{i}.dcm")
            for i in range(50)
        ]

        task_queue.enqueue_batch(tasks)

        stats = task_queue.get_stats()
        assert stats["pending"] == 50

    def test_claim_empty_queue(self, task_queue):
        """Test claiming from empty queue returns None."""
        claimed = task_queue.claim_task("worker-1")
        assert claimed is None

    def test_claim_nonexistent_task_data(self, task_queue, fake_redis):
        """Test claim when task data is missing."""
        # Add task ID to queue but no task data
        fake_redis.zadd(
            "dicom_fuzzer:tasks:pending",
            {"orphan-task": TaskPriority.NORMAL.value},
        )

        claimed = task_queue.claim_task("worker-1")
        assert claimed is None

    def test_submit_result_without_crash(self, task_queue):
        """Test submitting result without crash doesn't increment crash counter."""
        task = FuzzingTask(task_id="no-crash-task")
        task_queue.enqueue(task)
        task_queue.claim_task("worker-1")

        result = TaskResult(
            task_id="no-crash-task",
            worker_id="worker-1",
            crash_found=False,
        )
        task_queue.submit_result(result)

        stats = task_queue.get_stats()
        assert stats["completed"] == 1
        assert stats["crashes"] == 0

    def test_multiple_results(self, task_queue):
        """Test retrieving multiple results."""
        # Process multiple tasks
        for i in range(5):
            task = FuzzingTask(task_id=f"multi-{i}")
            task_queue.enqueue(task)
            claimed = task_queue.claim_task(f"worker-{i}")
            assert claimed is not None
            result = TaskResult(
                task_id=f"multi-{i}",
                worker_id=f"worker-{i}",
                crash_found=i % 2 == 0,  # Alternate crashes
            )
            task_queue.submit_result(result)

        stats = task_queue.get_stats()
        assert stats["completed"] == 5
        assert stats["crashes"] == 3  # indices 0, 2, 4

        # Get results one at a time
        results = task_queue.get_results(count=2)
        assert len(results) == 2

        # Get remaining
        results = task_queue.get_results(count=10)
        assert len(results) == 3

    def test_requeue_stale_task(self, task_queue, fake_redis, mocker):
        """Test requeuing stale tasks that exceed visibility timeout."""
        import time as time_module

        # Enqueue and claim a task
        task = FuzzingTask(task_id="stale-task")
        task_queue.enqueue(task)

        # Claim with short timeout
        claimed = task_queue.claim_task("worker-1", visibility_timeout=1)
        assert claimed is not None

        stats = task_queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 1

        # Mock time to be 10 seconds in the future
        original_time = time_module.time
        mocker.patch("time.time", return_value=original_time() + 10)

        # Requeue stale tasks
        requeued = task_queue.requeue_stale_tasks()
        assert requeued == 1

        # Restore time for stats check
        mocker.patch("time.time", return_value=original_time())

        stats = task_queue.get_stats()
        assert stats["pending"] == 1
        assert stats["in_progress"] == 0

    def test_no_stale_tasks_to_requeue(self, task_queue):
        """Test requeue when no tasks are stale."""
        task = FuzzingTask(task_id="fresh-task")
        task_queue.enqueue(task)
        task_queue.claim_task("worker-1", visibility_timeout=3600)

        # Task just claimed, shouldn't be requeued
        requeued = task_queue.requeue_stale_tasks()
        assert requeued == 0

    def test_clear_all_data(self, task_queue):
        """Test clearing all queue data."""
        # Enqueue several tasks
        for i in range(10):
            task_queue.enqueue(FuzzingTask(task_id=f"clear-{i}"))

        # Claim and complete some
        for i in range(3):
            claimed = task_queue.claim_task(f"worker-{i}")
            assert claimed is not None
            task_queue.submit_result(
                TaskResult(
                    task_id=claimed.task_id,
                    worker_id=f"worker-{i}",
                )
            )

        stats_before = task_queue.get_stats()
        assert stats_before["pending"] == 7
        assert stats_before["completed"] == 3

        # Clear everything
        task_queue.clear()

        stats_after = task_queue.get_stats()
        assert stats_after["pending"] == 0
        assert stats_after["in_progress"] == 0
        assert stats_after["completed"] == 0
        assert stats_after["results"] == 0

    def test_task_data_cleaned_on_completion(self, task_queue, fake_redis):
        """Test that task data is deleted after completion."""
        task = FuzzingTask(task_id="cleanup-task")
        task_queue.enqueue(task)

        # Verify task data exists
        task_key = "dicom_fuzzer:task:cleanup-task"
        assert fake_redis.exists(task_key)

        # Claim and complete
        task_queue.claim_task("worker-1")
        task_queue.submit_result(
            TaskResult(task_id="cleanup-task", worker_id="worker-1")
        )

        # Task data should be deleted
        assert not fake_redis.exists(task_key)

    def test_connect_already_connected(self, task_queue):
        """Test that calling connect when already connected is idempotent."""
        # Already connected via fixture
        task_queue.connect()  # Should not raise

        # Verify queue is still functional
        assert task_queue is not None

    def test_get_results_empty(self, task_queue):
        """Test getting results from empty queue."""
        results = task_queue.get_results(count=10)
        assert results == []

    def test_task_metadata_preserved(self, task_queue):
        """Test that task metadata is preserved through the workflow."""
        task = FuzzingTask(
            task_id="metadata-task",
            metadata={"custom_key": "custom_value", "count": 42},
        )
        task_queue.enqueue(task)

        claimed = task_queue.claim_task("worker-1")
        assert claimed is not None
        assert claimed.metadata == {"custom_key": "custom_value", "count": 42}


@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis package not installed")
class TestTaskQueueConcurrentFakeredis:
    """Tests for TaskQueue concurrent operations with fakeredis."""

    @pytest.fixture
    def fake_redis_server(self):
        """Create shared fakeredis server."""
        return fakeredis.FakeServer()

    @pytest.fixture
    def task_queue(self, mocker, fake_redis_server):
        """Create TaskQueue with fakeredis."""
        from dicom_fuzzer.distributed.queue import TaskQueue

        fake_redis = fakeredis.FakeStrictRedis(server=fake_redis_server)
        mocker.patch(
            "dicom_fuzzer.distributed.queue.redis.from_url",
            return_value=fake_redis,
        )
        queue = TaskQueue(redis_url="redis://fake:6379")
        queue.connect()
        yield queue
        queue.disconnect()

    def test_concurrent_claims(self, task_queue):
        """Test concurrent task claiming doesn't cause duplicates."""
        # Enqueue many tasks
        for i in range(50):
            task_queue.enqueue(FuzzingTask(task_id=f"concurrent-{i}"))

        claimed_tasks: list[FuzzingTask] = []
        lock = threading.Lock()

        def claim_worker(worker_id: str) -> None:
            while True:
                task = task_queue.claim_task(worker_id)
                if task is None:
                    break
                with lock:
                    claimed_tasks.append(task)

        # Simulate 5 concurrent workers
        threads = [
            threading.Thread(target=claim_worker, args=(f"worker-{i}",))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All tasks should be claimed exactly once
        assert len(claimed_tasks) == 50
        task_ids = [t.task_id for t in claimed_tasks]
        assert len(set(task_ids)) == 50  # No duplicates
