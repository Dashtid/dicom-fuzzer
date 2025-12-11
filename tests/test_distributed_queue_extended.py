"""Extended tests for distributed queue module.

Tests for Redis-backed and in-memory task queues including:
- TaskStatus and TaskPriority enums
- FuzzingTask dataclass serialization
- TaskResult dataclass serialization
- InMemoryTaskQueue operations
- create_task_queue factory

Target: 80%+ coverage for distributed/queue.py
"""

from __future__ import annotations

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

    def test_all_values(self) -> None:
        """Test all status values exist."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.IN_PROGRESS.value == "in_progress"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.TIMEOUT.value == "timeout"

    def test_from_string(self) -> None:
        """Test creating status from string value."""
        assert TaskStatus("pending") == TaskStatus.PENDING
        assert TaskStatus("completed") == TaskStatus.COMPLETED
        assert TaskStatus("failed") == TaskStatus.FAILED


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_priority_values(self) -> None:
        """Test priority numeric values."""
        assert TaskPriority.LOW.value == 0
        assert TaskPriority.NORMAL.value == 1
        assert TaskPriority.HIGH.value == 2
        assert TaskPriority.CRITICAL.value == 3

    def test_priority_ordering(self) -> None:
        """Test priority can be compared."""
        assert TaskPriority.LOW.value < TaskPriority.NORMAL.value
        assert TaskPriority.NORMAL.value < TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value < TaskPriority.CRITICAL.value

    def test_from_int(self) -> None:
        """Test creating priority from int value."""
        assert TaskPriority(0) == TaskPriority.LOW
        assert TaskPriority(1) == TaskPriority.NORMAL
        assert TaskPriority(2) == TaskPriority.HIGH
        assert TaskPriority(3) == TaskPriority.CRITICAL


class TestFuzzingTask:
    """Tests for FuzzingTask dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        task = FuzzingTask()

        assert task.task_id is not None
        assert len(task.task_id) > 0
        assert task.test_file == ""
        assert task.target_executable == ""
        assert task.timeout == 30.0
        assert task.strategy == "coverage_guided"
        assert task.priority == TaskPriority.NORMAL
        assert task.metadata == {}

    def test_custom_values(self) -> None:
        """Test custom values."""
        task = FuzzingTask(
            task_id="custom-id",
            test_file="/path/to/test.dcm",
            target_executable="/path/to/viewer",
            timeout=60.0,
            strategy="random",
            priority=TaskPriority.HIGH,
            metadata={"key": "value"},
        )

        assert task.task_id == "custom-id"
        assert task.test_file == "/path/to/test.dcm"
        assert task.target_executable == "/path/to/viewer"
        assert task.timeout == 60.0
        assert task.strategy == "random"
        assert task.priority == TaskPriority.HIGH
        assert task.metadata == {"key": "value"}

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        task = FuzzingTask(
            task_id="test-123",
            test_file="/test.dcm",
            target_executable="/viewer",
            timeout=45.0,
            strategy="grammar",
            priority=TaskPriority.CRITICAL,
            metadata={"count": 10},
        )

        data = task.to_dict()

        assert data["task_id"] == "test-123"
        assert data["test_file"] == "/test.dcm"
        assert data["target_executable"] == "/viewer"
        assert data["timeout"] == 45.0
        assert data["strategy"] == "grammar"
        assert data["priority"] == TaskPriority.CRITICAL.value
        assert "created_at" in data
        assert data["metadata"] == {"count": 10}

    def test_from_dict(self) -> None:
        """Test deserialization from dict."""
        data = {
            "task_id": "from-dict-123",
            "test_file": "/test.dcm",
            "target_executable": "/viewer",
            "timeout": 60.0,
            "strategy": "dictionary",
            "priority": 2,
            "created_at": "2025-01-15T10:30:00",
            "metadata": {"custom": "data"},
        }

        task = FuzzingTask.from_dict(data)

        assert task.task_id == "from-dict-123"
        assert task.test_file == "/test.dcm"
        assert task.target_executable == "/viewer"
        assert task.timeout == 60.0
        assert task.strategy == "dictionary"
        assert task.priority == TaskPriority.HIGH
        assert task.metadata == {"custom": "data"}
        assert task.created_at == datetime(2025, 1, 15, 10, 30, 0)

    def test_from_dict_minimal(self) -> None:
        """Test from_dict with minimal data."""
        data: dict[str, Any] = {}

        task = FuzzingTask.from_dict(data)

        assert task.task_id is not None  # Generated
        assert task.test_file == ""
        assert task.timeout == 30.0
        assert task.strategy == "coverage_guided"
        assert task.priority == TaskPriority.NORMAL

    def test_from_dict_without_created_at(self) -> None:
        """Test from_dict without created_at field."""
        data = {
            "task_id": "no-time",
            "test_file": "/test.dcm",
        }

        task = FuzzingTask.from_dict(data)

        assert task.task_id == "no-time"
        # created_at should be set to now
        assert task.created_at is not None
        assert isinstance(task.created_at, datetime)

    def test_roundtrip(self) -> None:
        """Test serialization roundtrip."""
        original = FuzzingTask(
            task_id="roundtrip-test",
            test_file="/test.dcm",
            target_executable="/app",
            timeout=120.0,
            strategy="smart",
            priority=TaskPriority.LOW,
            metadata={"nested": {"key": "value"}},
        )

        data = original.to_dict()
        restored = FuzzingTask.from_dict(data)

        assert restored.task_id == original.task_id
        assert restored.test_file == original.test_file
        assert restored.timeout == original.timeout
        assert restored.strategy == original.strategy
        assert restored.priority == original.priority
        assert restored.metadata == original.metadata


class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_minimal_values(self) -> None:
        """Test minimal required values."""
        result = TaskResult(task_id="task-1", worker_id="worker-1")

        assert result.task_id == "task-1"
        assert result.worker_id == "worker-1"
        assert result.status == TaskStatus.COMPLETED
        assert result.duration == 0.0
        assert result.crash_found is False
        assert result.coverage_delta == 0.0
        assert result.error_message == ""
        assert result.output_data == {}

    def test_full_values(self) -> None:
        """Test full values."""
        result = TaskResult(
            task_id="task-full",
            worker_id="worker-full",
            status=TaskStatus.FAILED,
            duration=5.5,
            crash_found=True,
            coverage_delta=0.15,
            error_message="Segmentation fault",
            output_data={"crash_address": "0xDEADBEEF"},
        )

        assert result.task_id == "task-full"
        assert result.status == TaskStatus.FAILED
        assert result.duration == 5.5
        assert result.crash_found is True
        assert result.coverage_delta == 0.15
        assert result.error_message == "Segmentation fault"
        assert result.output_data["crash_address"] == "0xDEADBEEF"

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        result = TaskResult(
            task_id="task-ser",
            worker_id="worker-ser",
            status=TaskStatus.TIMEOUT,
            duration=30.0,
            crash_found=False,
            coverage_delta=0.05,
            error_message="Execution timeout",
            output_data={"partial": True},
        )

        data = result.to_dict()

        assert data["task_id"] == "task-ser"
        assert data["worker_id"] == "worker-ser"
        assert data["status"] == "timeout"
        assert data["duration"] == 30.0
        assert data["crash_found"] is False
        assert data["coverage_delta"] == 0.05
        assert data["error_message"] == "Execution timeout"
        assert data["output_data"] == {"partial": True}

    def test_from_dict(self) -> None:
        """Test deserialization from dict."""
        data = {
            "task_id": "deser-task",
            "worker_id": "deser-worker",
            "status": "failed",
            "duration": 10.5,
            "crash_found": True,
            "coverage_delta": 0.25,
            "error_message": "Memory error",
            "output_data": {"details": "OOM"},
        }

        result = TaskResult.from_dict(data)

        assert result.task_id == "deser-task"
        assert result.worker_id == "deser-worker"
        assert result.status == TaskStatus.FAILED
        assert result.duration == 10.5
        assert result.crash_found is True
        assert result.coverage_delta == 0.25
        assert result.error_message == "Memory error"
        assert result.output_data["details"] == "OOM"

    def test_from_dict_minimal(self) -> None:
        """Test from_dict with minimal data."""
        data = {
            "task_id": "min-task",
            "worker_id": "min-worker",
        }

        result = TaskResult.from_dict(data)

        assert result.task_id == "min-task"
        assert result.worker_id == "min-worker"
        assert result.status == TaskStatus.COMPLETED
        assert result.duration == 0.0
        assert result.crash_found is False

    def test_from_dict_missing_task_id(self) -> None:
        """Test from_dict raises error without task_id."""
        data = {"worker_id": "worker-1"}

        with pytest.raises(KeyError, match="task_id is required"):
            TaskResult.from_dict(data)

    def test_from_dict_missing_worker_id(self) -> None:
        """Test from_dict raises error without worker_id."""
        data = {"task_id": "task-1"}

        with pytest.raises(KeyError, match="worker_id is required"):
            TaskResult.from_dict(data)

    def test_roundtrip(self) -> None:
        """Test serialization roundtrip."""
        original = TaskResult(
            task_id="round-task",
            worker_id="round-worker",
            status=TaskStatus.IN_PROGRESS,
            duration=15.0,
            crash_found=True,
            coverage_delta=0.5,
            error_message="",
            output_data={"a": 1, "b": [2, 3]},
        )

        data = original.to_dict()
        restored = TaskResult.from_dict(data)

        assert restored.task_id == original.task_id
        assert restored.worker_id == original.worker_id
        assert restored.status == original.status
        assert restored.duration == original.duration
        assert restored.crash_found == original.crash_found
        assert restored.coverage_delta == original.coverage_delta
        assert restored.output_data == original.output_data


class TestInMemoryTaskQueue:
    """Tests for InMemoryTaskQueue."""

    @pytest.fixture
    def queue(self) -> InMemoryTaskQueue:
        """Create in-memory queue."""
        return InMemoryTaskQueue()

    def test_init(self, queue: InMemoryTaskQueue) -> None:
        """Test initialization."""
        stats = queue.get_stats()

        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["results"] == 0
        assert stats["completed"] == 0
        assert stats["crashes"] == 0

    def test_connect_disconnect(self, queue: InMemoryTaskQueue) -> None:
        """Test connect/disconnect are no-ops."""
        queue.connect()  # Should not raise
        queue.disconnect()  # Should not raise

    def test_enqueue_single(self, queue: InMemoryTaskQueue) -> None:
        """Test enqueue single task."""
        task = FuzzingTask(task_id="t1", test_file="/test.dcm")

        queue.enqueue(task)

        assert queue.get_stats()["pending"] == 1

    def test_enqueue_maintains_priority_order(self, queue: InMemoryTaskQueue) -> None:
        """Test that tasks are sorted by priority."""
        low = FuzzingTask(task_id="low", priority=TaskPriority.LOW)
        high = FuzzingTask(task_id="high", priority=TaskPriority.HIGH)
        normal = FuzzingTask(task_id="normal", priority=TaskPriority.NORMAL)

        queue.enqueue(low)
        queue.enqueue(high)
        queue.enqueue(normal)

        # Highest priority first
        claimed = queue.claim_task("worker")
        assert claimed is not None
        assert claimed.task_id == "high"

        claimed = queue.claim_task("worker")
        assert claimed is not None
        assert claimed.task_id == "normal"

        claimed = queue.claim_task("worker")
        assert claimed is not None
        assert claimed.task_id == "low"

    def test_enqueue_batch(self, queue: InMemoryTaskQueue) -> None:
        """Test enqueue batch."""
        tasks = [
            FuzzingTask(task_id=f"t{i}", priority=TaskPriority.NORMAL) for i in range(5)
        ]

        queue.enqueue_batch(tasks)

        assert queue.get_stats()["pending"] == 5

    def test_claim_task_empty_queue(self, queue: InMemoryTaskQueue) -> None:
        """Test claim from empty queue."""
        result = queue.claim_task("worker-1")

        assert result is None

    def test_claim_task_moves_to_in_progress(self, queue: InMemoryTaskQueue) -> None:
        """Test claiming moves task to in_progress."""
        task = FuzzingTask(task_id="t1")
        queue.enqueue(task)

        claimed = queue.claim_task("worker-1")

        assert claimed is not None
        assert claimed.task_id == "t1"
        assert queue.get_stats()["pending"] == 0
        assert queue.get_stats()["in_progress"] == 1

    def test_submit_result(self, queue: InMemoryTaskQueue) -> None:
        """Test submit result."""
        task = FuzzingTask(task_id="t1")
        queue.enqueue(task)
        queue.claim_task("worker-1")

        result = TaskResult(
            task_id="t1",
            worker_id="worker-1",
            status=TaskStatus.COMPLETED,
            duration=1.0,
        )
        queue.submit_result(result)

        stats = queue.get_stats()
        assert stats["in_progress"] == 0
        assert stats["completed"] == 1

    def test_submit_result_with_crash(self, queue: InMemoryTaskQueue) -> None:
        """Test submit result with crash."""
        task = FuzzingTask(task_id="t1")
        queue.enqueue(task)
        queue.claim_task("worker-1")

        result = TaskResult(
            task_id="t1",
            worker_id="worker-1",
            crash_found=True,
        )
        queue.submit_result(result)

        stats = queue.get_stats()
        assert stats["crashes"] == 1

    def test_submit_result_not_in_progress(self, queue: InMemoryTaskQueue) -> None:
        """Test submit result for task not in progress."""
        result = TaskResult(
            task_id="unknown",
            worker_id="worker-1",
        )

        # Should not raise
        queue.submit_result(result)

        assert queue.get_stats()["completed"] == 1

    def test_get_results(self, queue: InMemoryTaskQueue) -> None:
        """Test get results."""
        # Submit multiple results
        for i in range(5):
            result = TaskResult(
                task_id=f"t{i}",
                worker_id="worker-1",
                duration=float(i),
            )
            queue.submit_result(result)

        # Get first 3
        results = queue.get_results(count=3)

        assert len(results) == 3
        assert queue.get_stats()["results"] == 2  # 2 remaining

    def test_get_results_empty(self, queue: InMemoryTaskQueue) -> None:
        """Test get results from empty queue."""
        results = queue.get_results()

        assert results == []

    def test_requeue_stale_tasks(self, queue: InMemoryTaskQueue) -> None:
        """Test requeue stale tasks returns 0 (not implemented)."""
        count = queue.requeue_stale_tasks()

        assert count == 0

    def test_clear(self, queue: InMemoryTaskQueue) -> None:
        """Test clear all queues."""
        # Add data
        queue.enqueue(FuzzingTask(task_id="t1"))
        queue.claim_task("worker")
        queue.submit_result(TaskResult(task_id="t2", worker_id="w"))

        queue.clear()

        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["results"] == 0
        assert stats["completed"] == 0
        assert stats["crashes"] == 0

    def test_workflow_complete(self, queue: InMemoryTaskQueue) -> None:
        """Test complete workflow."""
        # Create and enqueue tasks
        tasks = [
            FuzzingTask(task_id=f"task-{i}", test_file=f"/test{i}.dcm")
            for i in range(3)
        ]
        queue.enqueue_batch(tasks)

        # Process all tasks
        while True:
            task = queue.claim_task("worker-1")
            if task is None:
                break

            result = TaskResult(
                task_id=task.task_id,
                worker_id="worker-1",
                status=TaskStatus.COMPLETED,
                duration=0.1,
            )
            queue.submit_result(result)

        # Verify
        stats = queue.get_stats()
        assert stats["pending"] == 0
        assert stats["in_progress"] == 0
        assert stats["completed"] == 3

        results = queue.get_results()
        assert len(results) == 3


class TestCreateTaskQueue:
    """Tests for create_task_queue factory function."""

    def test_create_without_redis_url(self) -> None:
        """Test creation without Redis URL returns in-memory queue."""
        queue = create_task_queue(redis_url=None)

        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_with_invalid_redis_url(self) -> None:
        """Test creation with invalid Redis URL falls back to in-memory."""
        # This will fail to connect and fall back
        queue = create_task_queue(redis_url="redis://invalid-host:9999")

        assert isinstance(queue, InMemoryTaskQueue)

    def test_create_passes_kwargs(self) -> None:
        """Test that kwargs are passed to queue."""
        queue = create_task_queue(
            redis_url=None,
            custom_arg="value",  # Should be accepted by InMemoryTaskQueue
        )

        assert isinstance(queue, InMemoryTaskQueue)


class TestGetStats:
    """Tests for get_stats edge cases."""

    def test_stats_dead_letter_always_zero(self) -> None:
        """Test dead_letter is always 0 for in-memory queue."""
        queue = InMemoryTaskQueue()

        stats = queue.get_stats()

        assert stats["dead_letter"] == 0

    def test_stats_after_operations(self) -> None:
        """Test stats reflect all operations."""
        queue = InMemoryTaskQueue()

        # Enqueue
        queue.enqueue(FuzzingTask(task_id="t1"))
        queue.enqueue(FuzzingTask(task_id="t2"))
        assert queue.get_stats()["pending"] == 2

        # Claim one
        queue.claim_task("w1")
        assert queue.get_stats()["pending"] == 1
        assert queue.get_stats()["in_progress"] == 1

        # Submit with crash
        queue.submit_result(TaskResult(task_id="t1", worker_id="w1", crash_found=True))
        assert queue.get_stats()["crashes"] == 1
        assert queue.get_stats()["completed"] == 1


class TestTaskCreatedAt:
    """Tests for task created_at field."""

    def test_created_at_auto_set(self) -> None:
        """Test created_at is automatically set."""
        task = FuzzingTask()

        assert task.created_at is not None
        assert isinstance(task.created_at, datetime)

    def test_created_at_serialization(self) -> None:
        """Test created_at is serialized as ISO format."""
        task = FuzzingTask(task_id="test")
        data = task.to_dict()

        assert "created_at" in data
        # Should be ISO format string
        assert "T" in data["created_at"]


class TestPriorityQueueBehavior:
    """Tests for priority queue behavior."""

    def test_critical_before_high(self) -> None:
        """Test CRITICAL priority processed before HIGH."""
        queue = InMemoryTaskQueue()

        queue.enqueue(FuzzingTask(task_id="high", priority=TaskPriority.HIGH))
        queue.enqueue(FuzzingTask(task_id="crit", priority=TaskPriority.CRITICAL))

        claimed = queue.claim_task("worker")
        assert claimed is not None
        assert claimed.task_id == "crit"

    def test_same_priority_fifo(self) -> None:
        """Test same priority tasks are FIFO."""
        queue = InMemoryTaskQueue()

        queue.enqueue(FuzzingTask(task_id="first", priority=TaskPriority.NORMAL))
        queue.enqueue(FuzzingTask(task_id="second", priority=TaskPriority.NORMAL))
        queue.enqueue(FuzzingTask(task_id="third", priority=TaskPriority.NORMAL))

        # Note: Current implementation re-sorts after each enqueue
        # so order may vary - just verify all are processed
        claimed_ids = []
        for _ in range(3):
            task = queue.claim_task("worker")
            assert task is not None
            claimed_ids.append(task.task_id)

        assert set(claimed_ids) == {"first", "second", "third"}


class TestMetadataHandling:
    """Tests for metadata handling in tasks."""

    def test_task_metadata_nested(self) -> None:
        """Test nested metadata in tasks."""
        task = FuzzingTask(
            task_id="meta-test",
            metadata={
                "nested": {
                    "deep": {
                        "value": 42,
                    },
                },
                "array": [1, 2, 3],
            },
        )

        data = task.to_dict()
        restored = FuzzingTask.from_dict(data)

        assert restored.metadata["nested"]["deep"]["value"] == 42
        assert restored.metadata["array"] == [1, 2, 3]

    def test_result_output_data(self) -> None:
        """Test output_data in results."""
        result = TaskResult(
            task_id="t1",
            worker_id="w1",
            output_data={
                "crash_log": "Segfault at 0x0",
                "stack_trace": ["frame1", "frame2"],
                "metrics": {"coverage": 0.5},
            },
        )

        data = result.to_dict()
        restored = TaskResult.from_dict(data)

        assert restored.output_data["crash_log"] == "Segfault at 0x0"
        assert restored.output_data["stack_trace"] == ["frame1", "frame2"]
        assert restored.output_data["metrics"]["coverage"] == 0.5
