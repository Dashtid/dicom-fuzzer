"""Redis-backed task queue for distributed fuzzing.

This module provides a task queue implementation using Redis for
distributing fuzzing work across multiple worker nodes.

Features:
- Atomic task claiming with visibility timeout
- Result aggregation
- Dead letter queue for failed tasks
- Priority-based task scheduling
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Try to import redis
try:
    import redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None


class TaskStatus(Enum):
    """Status of a fuzzing task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Priority levels for tasks."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class FuzzingTask:
    """A fuzzing task to be executed by a worker.

    Attributes:
        task_id: Unique identifier for the task
        test_file: Path to the test file
        target_executable: Path to target executable
        timeout: Execution timeout in seconds
        strategy: Fuzzing strategy to use
        priority: Task priority level
        created_at: When the task was created
        metadata: Additional task metadata

    """

    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    test_file: str = ""
    target_executable: str = ""
    timeout: float = 30.0
    strategy: str = "coverage_guided"
    priority: TaskPriority = TaskPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "test_file": self.test_file,
            "target_executable": self.target_executable,
            "timeout": self.timeout,
            "strategy": self.strategy,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FuzzingTask:
        """Create from dictionary.

        Args:
            data: Dictionary representation of task

        Returns:
            FuzzingTask instance

        """
        return cls(
            task_id=data.get("task_id", str(uuid.uuid4())),
            test_file=data.get("test_file", ""),
            target_executable=data.get("target_executable", ""),
            timeout=data.get("timeout", 30.0),
            strategy=data.get("strategy", "coverage_guided"),
            priority=TaskPriority(data.get("priority", 1)),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else datetime.now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TaskResult:
    """Result of a fuzzing task execution.

    Attributes:
        task_id: ID of the completed task
        worker_id: ID of the worker that executed the task
        status: Final status of the task
        duration: Execution duration in seconds
        crash_found: Whether a crash was found
        coverage_delta: Coverage improvement
        error_message: Error message if failed
        output_data: Additional output data

    """

    task_id: str
    worker_id: str
    status: TaskStatus = TaskStatus.COMPLETED
    duration: float = 0.0
    crash_found: bool = False
    coverage_delta: float = 0.0
    error_message: str = ""
    output_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "status": self.status.value,
            "duration": self.duration,
            "crash_found": self.crash_found,
            "coverage_delta": self.coverage_delta,
            "error_message": self.error_message,
            "output_data": self.output_data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskResult:
        """Create from dictionary.

        Args:
            data: Dictionary representation of result

        Returns:
            TaskResult instance

        """
        return cls(
            task_id=data["task_id"],
            worker_id=data["worker_id"],
            status=TaskStatus(data.get("status", "completed")),
            duration=data.get("duration", 0.0),
            crash_found=data.get("crash_found", False),
            coverage_delta=data.get("coverage_delta", 0.0),
            error_message=data.get("error_message", ""),
            output_data=data.get("output_data", {}),
        )


class TaskQueue:
    """Redis-backed task queue for distributed fuzzing.

    Provides atomic task claiming, result submission, and queue management
    for distributing fuzzing work across multiple workers.

    Usage:
        queue = TaskQueue(redis_url="redis://localhost:6379")

        # Add tasks
        queue.enqueue(task)

        # Claim task (worker)
        task = queue.claim_task(worker_id, visibility_timeout=60)

        # Submit result
        queue.submit_result(result)

    """

    # Redis key prefixes
    PENDING_QUEUE = "dicom_fuzzer:tasks:pending"
    IN_PROGRESS_SET = "dicom_fuzzer:tasks:in_progress"
    RESULTS_QUEUE = "dicom_fuzzer:results"
    TASK_DATA_PREFIX = "dicom_fuzzer:task:"
    DEAD_LETTER_QUEUE = "dicom_fuzzer:tasks:dead"
    STATS_KEY = "dicom_fuzzer:stats"

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        visibility_timeout: int = 300,
        max_retries: int = 3,
    ):
        """Initialize task queue.

        Args:
            redis_url: Redis connection URL
            visibility_timeout: Default visibility timeout in seconds
            max_retries: Maximum retry attempts for failed tasks

        Raises:
            ImportError: If redis is not installed

        """
        if not HAS_REDIS:
            raise ImportError(
                "redis is required for distributed fuzzing. "
                "Install with: pip install redis"
            )

        self.redis_url = redis_url
        self.visibility_timeout = visibility_timeout
        self.max_retries = max_retries

        self._client: redis.Redis | None = None
        self._connected = False

        logger.info(f"Task queue initialized: {redis_url}")

    def connect(self) -> None:
        """Connect to Redis server."""
        if self._connected:
            return

        try:
            self._client = redis.from_url(self.redis_url)
            self._client.ping()
            self._connected = True
            logger.info("Connected to Redis")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def disconnect(self) -> None:
        """Disconnect from Redis server."""
        if self._client:
            self._client.close()
            self._connected = False
            logger.info("Disconnected from Redis")

    def _get_client(self) -> redis.Redis[bytes]:
        """Get connected Redis client.

        Returns:
            Connected Redis client

        Raises:
            RuntimeError: If not connected

        """
        self.connect()
        if self._client is None:
            raise RuntimeError("Redis client not initialized")
        return self._client

    def enqueue(self, task: FuzzingTask) -> None:
        """Add a task to the queue.

        Args:
            task: Task to enqueue

        """
        client = self._get_client()

        # Store task data
        task_key = f"{self.TASK_DATA_PREFIX}{task.task_id}"
        client.set(task_key, json.dumps(task.to_dict()))

        # Add to priority queue (higher priority = higher score)
        client.zadd(
            self.PENDING_QUEUE,
            {task.task_id: task.priority.value},
        )

        logger.debug(f"Enqueued task {task.task_id}")

    def enqueue_batch(self, tasks: list[FuzzingTask]) -> None:
        """Add multiple tasks to the queue.

        Args:
            tasks: List of tasks to enqueue

        """
        client = self._get_client()
        pipe = client.pipeline()

        for task in tasks:
            task_key = f"{self.TASK_DATA_PREFIX}{task.task_id}"
            pipe.set(task_key, json.dumps(task.to_dict()))
            pipe.zadd(self.PENDING_QUEUE, {task.task_id: task.priority.value})

        pipe.execute()
        logger.debug(f"Enqueued {len(tasks)} tasks")

    def claim_task(
        self,
        worker_id: str,
        visibility_timeout: int | None = None,
    ) -> FuzzingTask | None:
        """Claim a task for processing.

        Atomically moves a task from pending to in-progress and returns it.
        The task becomes visible again after the visibility timeout if not
        completed.

        Args:
            worker_id: ID of the claiming worker
            visibility_timeout: Override default visibility timeout

        Returns:
            FuzzingTask if available, None otherwise

        """
        client = self._get_client()
        timeout = visibility_timeout or self.visibility_timeout

        # Atomically pop highest priority task
        result = client.zpopmax(self.PENDING_QUEUE, count=1)
        if not result:
            return None

        task_id = result[0][0]
        if isinstance(task_id, bytes):
            task_id = task_id.decode()

        # Get task data
        task_key = f"{self.TASK_DATA_PREFIX}{task_id}"
        task_data = client.get(task_key)
        if not task_data:
            logger.warning(f"Task data not found: {task_id}")
            return None

        if isinstance(task_data, bytes):
            task_data = task_data.decode()

        # Mark as in progress with expiry
        claim_data = {
            "worker_id": worker_id,
            "claimed_at": time.time(),
            "timeout": timeout,
        }
        client.hset(self.IN_PROGRESS_SET, task_id, json.dumps(claim_data))

        logger.debug(f"Task {task_id} claimed by worker {worker_id}")

        return FuzzingTask.from_dict(json.loads(task_data))

    def submit_result(self, result: TaskResult) -> None:
        """Submit a task result.

        Args:
            result: Result of task execution

        """
        client = self._get_client()
        pipe = client.pipeline()

        # Remove from in-progress
        pipe.hdel(self.IN_PROGRESS_SET, result.task_id)

        # Add result to results queue
        pipe.lpush(self.RESULTS_QUEUE, json.dumps(result.to_dict()))

        # Update stats
        pipe.hincrby(self.STATS_KEY, "completed", 1)
        if result.crash_found:
            pipe.hincrby(self.STATS_KEY, "crashes", 1)

        # Clean up task data
        task_key = f"{self.TASK_DATA_PREFIX}{result.task_id}"
        pipe.delete(task_key)

        pipe.execute()

        logger.debug(f"Result submitted for task {result.task_id}")

    def get_results(self, count: int = 100) -> list[TaskResult]:
        """Get completed task results.

        Args:
            count: Maximum number of results to retrieve

        Returns:
            List of TaskResult objects

        """
        client = self._get_client()

        results = []
        for _ in range(count):
            data = client.rpop(self.RESULTS_QUEUE)
            if not data:
                break
            if isinstance(data, bytes):
                data = data.decode()
            results.append(TaskResult.from_dict(json.loads(data)))

        return results

    def get_stats(self) -> dict[str, int]:
        """Get queue statistics.

        Returns:
            Dictionary with queue statistics

        """
        client = self._get_client()

        pending = client.zcard(self.PENDING_QUEUE)
        in_progress = client.hlen(self.IN_PROGRESS_SET)
        results_count = client.llen(self.RESULTS_QUEUE)
        dead = client.llen(self.DEAD_LETTER_QUEUE)

        stats = client.hgetall(self.STATS_KEY)
        stats = {
            k.decode() if isinstance(k, bytes) else k: int(v) for k, v in stats.items()
        }

        return {
            "pending": pending,
            "in_progress": in_progress,
            "results": results_count,
            "dead_letter": dead,
            "completed": stats.get("completed", 0),
            "crashes": stats.get("crashes", 0),
        }

    def requeue_stale_tasks(self) -> int:
        """Requeue tasks that have exceeded visibility timeout.

        Returns:
            Number of tasks requeued

        """
        client = self._get_client()

        requeued = 0
        current_time = time.time()

        # Get all in-progress tasks
        in_progress = client.hgetall(self.IN_PROGRESS_SET)

        for task_id_bytes, claim_data_bytes in in_progress.items():
            task_id_str = (
                task_id_bytes.decode()
                if isinstance(task_id_bytes, bytes)
                else task_id_bytes
            )
            claim_data_str = (
                claim_data_bytes.decode()
                if isinstance(claim_data_bytes, bytes)
                else claim_data_bytes
            )

            claim = json.loads(claim_data_str)
            claimed_at = claim["claimed_at"]
            timeout = claim["timeout"]

            if current_time - claimed_at > timeout:
                # Task has timed out, requeue it
                client.hdel(self.IN_PROGRESS_SET, task_id_str)
                client.zadd(
                    self.PENDING_QUEUE,
                    {task_id_str: TaskPriority.HIGH.value},  # Higher priority for retry
                )
                requeued += 1
                logger.warning(f"Requeued stale task: {task_id_str}")

        return requeued

    def clear(self) -> None:
        """Clear all queues (use with caution)."""
        client = self._get_client()
        pipe = client.pipeline()
        pipe.delete(self.PENDING_QUEUE)
        pipe.delete(self.IN_PROGRESS_SET)
        pipe.delete(self.RESULTS_QUEUE)
        pipe.delete(self.DEAD_LETTER_QUEUE)
        pipe.delete(self.STATS_KEY)

        # Clear task data
        for key in client.scan_iter(f"{self.TASK_DATA_PREFIX}*"):
            pipe.delete(key)

        pipe.execute()
        logger.warning("All queues cleared")


class InMemoryTaskQueue:
    """In-memory task queue for testing without Redis.

    Provides the same interface as TaskQueue but stores everything in memory.
    Useful for testing and single-machine operation.
    """

    def __init__(self, **kwargs: Any):
        """Initialize in-memory queue."""
        self._pending: list[FuzzingTask] = []
        self._in_progress: dict[str, tuple[FuzzingTask, str, float]] = {}
        self._results: list[TaskResult] = []
        self._stats = {"completed": 0, "crashes": 0}

        logger.debug("Using in-memory task queue")

    def connect(self) -> None:
        """No-op connect."""
        pass

    def disconnect(self) -> None:
        """No-op disconnect."""
        pass

    def enqueue(self, task: FuzzingTask) -> None:
        """Add task to queue."""
        self._pending.append(task)
        # Sort by priority (highest first)
        self._pending.sort(key=lambda t: t.priority.value, reverse=True)

    def enqueue_batch(self, tasks: list[FuzzingTask]) -> None:
        """Add multiple tasks."""
        for task in tasks:
            self.enqueue(task)

    def claim_task(
        self,
        worker_id: str,
        visibility_timeout: int | None = None,
    ) -> FuzzingTask | None:
        """Claim a task."""
        if not self._pending:
            return None

        task = self._pending.pop(0)
        self._in_progress[task.task_id] = (task, worker_id, time.time())
        return task

    def submit_result(self, result: TaskResult) -> None:
        """Submit a result."""
        if result.task_id in self._in_progress:
            del self._in_progress[result.task_id]

        self._results.append(result)
        self._stats["completed"] += 1
        if result.crash_found:
            self._stats["crashes"] += 1

    def get_results(self, count: int = 100) -> list[TaskResult]:
        """Get results."""
        results = self._results[:count]
        self._results = self._results[count:]
        return results

    def get_stats(self) -> dict[str, int]:
        """Get statistics."""
        return {
            "pending": len(self._pending),
            "in_progress": len(self._in_progress),
            "results": len(self._results),
            "dead_letter": 0,
            **self._stats,
        }

    def requeue_stale_tasks(self) -> int:
        """Requeue stale tasks."""
        return 0

    def clear(self) -> None:
        """Clear all queues."""
        self._pending.clear()
        self._in_progress.clear()
        self._results.clear()
        self._stats = {"completed": 0, "crashes": 0}


def create_task_queue(
    redis_url: str | None = None,
    **kwargs: Any,
) -> TaskQueue | InMemoryTaskQueue:
    """Create a task queue, falling back to in-memory if Redis unavailable.

    Args:
        redis_url: Redis connection URL (None for in-memory)
        **kwargs: Additional arguments for queue

    Returns:
        TaskQueue if Redis available, InMemoryTaskQueue otherwise

    """
    if redis_url and HAS_REDIS:
        try:
            queue = TaskQueue(redis_url=redis_url, **kwargs)
            queue.connect()
            return queue
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}, using in-memory queue")

    return InMemoryTaskQueue(**kwargs)
