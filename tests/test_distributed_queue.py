"""Tests for the distributed queue module.

This module tests TaskQueue, InMemoryTaskQueue, and related classes.
"""

from __future__ import annotations

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
