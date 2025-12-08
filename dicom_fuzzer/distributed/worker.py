"""Distributed fuzzing worker node.

This module provides the worker component for distributed fuzzing,
responsible for executing fuzzing tasks assigned by the coordinator.

Features:
- Task execution
- Crash detection and reporting
- Coverage tracking
- Heartbeat mechanism
"""

from __future__ import annotations

import logging
import platform
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.distributed.queue import (
    FuzzingTask,
    InMemoryTaskQueue,
    TaskQueue,
    TaskResult,
    TaskStatus,
    create_task_queue,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class WorkerConfig:
    """Configuration for a fuzzing worker.

    Attributes:
        worker_id: Unique worker identifier (auto-generated if not provided)
        redis_url: Redis connection URL
        heartbeat_interval: Seconds between heartbeats
        poll_interval: Seconds between task polls
        max_memory_mb: Maximum memory usage before restart
        working_dir: Directory for temporary files

    """

    worker_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    redis_url: str = "redis://localhost:6379"
    heartbeat_interval: int = 30
    poll_interval: float = 0.5
    max_memory_mb: int = 4096
    working_dir: str = "/tmp/dicom_fuzzer"  # nosec B108 - Configurable default


class FuzzingWorker:
    """Worker node for distributed fuzzing.

    Executes fuzzing tasks assigned by the coordinator, reports results,
    and maintains heartbeat for liveness monitoring.

    Usage:
        worker = FuzzingWorker(redis_url="redis://localhost:6379")
        worker.start()  # Blocks until stopped

        # Or run in background
        worker.start(blocking=False)
        # ... do other things ...
        worker.stop()

    """

    def __init__(
        self,
        redis_url: str | None = None,
        config: WorkerConfig | None = None,
    ):
        """Initialize worker.

        Args:
            redis_url: Redis connection URL
            config: Worker configuration

        """
        self.config = config or WorkerConfig()
        if redis_url:
            self.config.redis_url = redis_url

        self._queue: TaskQueue | InMemoryTaskQueue | None = None
        self._running = False
        self._current_task: FuzzingTask | None = None
        self._lock = threading.Lock()

        # Threads
        self._worker_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None

        # Statistics
        self._tasks_completed = 0
        self._crashes_found = 0
        self._start_time: datetime | None = None

        # Create working directory
        Path(self.config.working_dir).mkdir(parents=True, exist_ok=True)

        logger.info(f"Worker {self.config.worker_id} initialized")

    def start(self, blocking: bool = True) -> None:
        """Start the worker.

        Args:
            blocking: If True, block until worker stops

        """
        if self._running:
            logger.warning("Worker already running")
            return

        self._running = True
        self._start_time = datetime.now()

        # Connect to queue
        self._queue = create_task_queue(self.config.redis_url)

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
        )
        self._heartbeat_thread.start()

        logger.info(f"Worker {self.config.worker_id} started")

        if blocking:
            self._work_loop()
        else:
            self._worker_thread = threading.Thread(
                target=self._work_loop,
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self) -> None:
        """Stop the worker gracefully."""
        logger.info(f"Stopping worker {self.config.worker_id}")
        self._running = False

        if self._worker_thread:
            self._worker_thread.join(timeout=10)
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)

        if self._queue:
            self._queue.disconnect()

        logger.info(
            f"Worker stopped. Tasks: {self._tasks_completed}, "
            f"Crashes: {self._crashes_found}"
        )

    def _work_loop(self) -> None:
        """Main work loop - claim and execute tasks."""
        if self._queue is None:
            logger.error("Queue not initialized")
            return

        while self._running:
            try:
                # Claim a task with default visibility timeout
                task = self._queue.claim_task(
                    self.config.worker_id,
                    visibility_timeout=60,
                )

                if task:
                    with self._lock:
                        self._current_task = task

                    # Execute the task
                    result = self._execute_task(task)

                    # Submit result
                    self._queue.submit_result(result)

                    with self._lock:
                        self._current_task = None
                        self._tasks_completed += 1
                        if result.crash_found:
                            self._crashes_found += 1

                else:
                    # No task available, wait
                    time.sleep(self.config.poll_interval)

            except Exception as e:
                logger.error(f"Work loop error: {e}")
                time.sleep(1)

    def _execute_task(self, task: FuzzingTask) -> TaskResult:
        """Execute a single fuzzing task.

        Args:
            task: Task to execute

        Returns:
            TaskResult with execution outcome

        """
        start_time = time.time()
        crash_found = False
        error_message = ""
        status = TaskStatus.COMPLETED
        output_data: dict[str, Any] = {}

        try:
            # Build command
            cmd = [task.target_executable, task.test_file]

            # Run the target
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.config.working_dir,
            )

            try:
                stdout, stderr = process.communicate(timeout=task.timeout)
                exit_code = process.returncode

                # Check for crash
                if exit_code != 0:
                    crash_found = True
                    output_data = {
                        "exit_code": exit_code,
                        "stdout": stdout.decode(errors="ignore")[:1000],
                        "stderr": stderr.decode(errors="ignore")[:1000],
                        "test_file": task.test_file,
                    }

                    # Check for common crash signals
                    if exit_code < 0:
                        signal_num = -exit_code
                        output_data["signal"] = signal_num
                        output_data["signal_name"] = self._signal_name(signal_num)

            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                status = TaskStatus.TIMEOUT
                error_message = f"Timeout after {task.timeout}s"

        except FileNotFoundError:
            status = TaskStatus.FAILED
            error_message = f"Target not found: {task.target_executable}"
        except Exception as e:
            status = TaskStatus.FAILED
            error_message = str(e)

        duration = time.time() - start_time

        return TaskResult(
            task_id=task.task_id,
            worker_id=self.config.worker_id,
            status=status,
            duration=duration,
            crash_found=crash_found,
            error_message=error_message,
            output_data=output_data,
        )

    def _signal_name(self, signal_num: int) -> str:
        """Get signal name from number.

        Args:
            signal_num: Signal number

        Returns:
            Signal name or "UNKNOWN"

        """
        signal_names: dict[int, str] = {
            signal.SIGSEGV: "SIGSEGV",
            signal.SIGABRT: "SIGABRT",
            signal.SIGFPE: "SIGFPE",
            signal.SIGILL: "SIGILL",
        }
        # SIGBUS is not available on Windows
        if hasattr(signal, "SIGBUS"):
            signal_names[signal.SIGBUS] = "SIGBUS"
        return signal_names.get(signal_num, f"SIG{signal_num}")

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to coordinator."""
        while self._running:
            try:
                # Heartbeat is sent via Redis key update
                # In a full implementation, this would update a Redis key
                # that the coordinator monitors

                logger.debug(
                    f"Heartbeat: worker={self.config.worker_id}, "
                    f"tasks={self._tasks_completed}, crashes={self._crashes_found}"
                )

                time.sleep(self.config.heartbeat_interval)

            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
                time.sleep(5)

    def get_status(self) -> dict[str, Any]:
        """Get current worker status.

        Returns:
            Dictionary with worker status

        """
        with self._lock:
            current_task = self._current_task.task_id if self._current_task else None

        return {
            "worker_id": self.config.worker_id,
            "hostname": platform.node(),
            "running": self._running,
            "current_task": current_task,
            "tasks_completed": self._tasks_completed,
            "crashes_found": self._crashes_found,
            "uptime_seconds": (
                (datetime.now() - self._start_time).total_seconds()
                if self._start_time
                else 0
            ),
        }


class LocalWorkerPool:
    """Pool of local workers for single-machine parallel fuzzing.

    Manages multiple worker instances on a single machine without
    requiring Redis.

    Usage:
        pool = LocalWorkerPool(num_workers=4)
        pool.start(target="/path/to/viewer", corpus="/path/to/corpus")

        # Monitor progress
        while pool.is_running():
            stats = pool.get_stats()
            time.sleep(1)

        pool.stop()

    """

    def __init__(
        self,
        num_workers: int = 4,
        working_dir: str = "/tmp/dicom_fuzzer_pool",  # nosec B108 - Configurable default
    ):
        """Initialize worker pool.

        Args:
            num_workers: Number of workers to run
            working_dir: Base working directory

        """
        self.num_workers = num_workers
        self.working_dir = Path(working_dir)
        self.working_dir.mkdir(parents=True, exist_ok=True)

        self._workers: list[FuzzingWorker] = []
        self._queue: InMemoryTaskQueue | None = None
        self._running = False

        logger.info(f"Worker pool initialized with {num_workers} workers")

    def start(
        self,
        target: str,
        corpus: str | Path,
        timeout: float = 30.0,
    ) -> None:
        """Start the worker pool.

        Args:
            target: Path to target executable
            corpus: Path to corpus directory
            timeout: Per-execution timeout

        """
        if self._running:
            logger.warning("Pool already running")
            return

        self._running = True

        # Create shared in-memory queue
        self._queue = InMemoryTaskQueue()

        # Load corpus
        corpus_path = Path(corpus)
        for file_path in corpus_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in (".dcm", ".dicom"):
                task = FuzzingTask(
                    test_file=str(file_path),
                    target_executable=target,
                    timeout=timeout,
                )
                self._queue.enqueue(task)

        # Start workers
        for i in range(self.num_workers):
            config = WorkerConfig(
                worker_id=f"local_{i}",
                working_dir=str(self.working_dir / f"worker_{i}"),
            )
            worker = FuzzingWorker(config=config)
            worker._queue = self._queue  # Share the queue
            worker.start(blocking=False)
            self._workers.append(worker)

        logger.info(f"Started {len(self._workers)} workers")

    def stop(self) -> None:
        """Stop all workers."""
        self._running = False

        for worker in self._workers:
            worker.stop()

        self._workers.clear()
        logger.info("Worker pool stopped")

    def is_running(self) -> bool:
        """Check if pool is running.

        Returns:
            True if pool is active

        """
        return self._running and any(w._running for w in self._workers)

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics.

        Returns:
            Dictionary with pool stats

        """
        total_tasks = sum(w._tasks_completed for w in self._workers)
        total_crashes = sum(w._crashes_found for w in self._workers)
        active_workers = sum(1 for w in self._workers if w._running)

        queue_stats = self._queue.get_stats() if self._queue else {}

        return {
            "active_workers": active_workers,
            "total_workers": len(self._workers),
            "tasks_completed": total_tasks,
            "crashes_found": total_crashes,
            "queue_pending": queue_stats.get("pending", 0),
            "queue_in_progress": queue_stats.get("in_progress", 0),
        }

    def get_results(self) -> list[TaskResult]:
        """Get completed task results.

        Returns:
            List of TaskResult objects

        """
        if self._queue:
            return self._queue.get_results()
        return []
