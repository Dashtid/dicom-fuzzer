"""Distributed fuzzing coordinator (master node).

This module provides the coordinator component for distributed fuzzing,
responsible for distributing work across workers and aggregating results.

Features:
- Campaign management
- Task distribution
- Result aggregation
- Worker monitoring
- Corpus synchronization
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.distributed.queue import (
    FuzzingTask,
    InMemoryTaskQueue,
    TaskPriority,
    TaskQueue,
    TaskResult,
    create_task_queue,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


@dataclass
class CampaignConfig:
    """Configuration for a fuzzing campaign.

    Attributes:
        campaign_id: Unique identifier for the campaign
        target_executable: Path to target application
        corpus_dir: Directory containing seed corpus
        output_dir: Directory for results and crashes
        timeout: Per-execution timeout in seconds
        strategy: Fuzzing strategy
        max_workers: Maximum number of workers
        duration: Campaign duration in seconds (0 for unlimited)

    """

    campaign_id: str
    target_executable: str
    corpus_dir: str
    output_dir: str = "./fuzzing_output"
    timeout: float = 30.0
    strategy: str = "coverage_guided"
    max_workers: int = 4
    duration: int = 0  # 0 = unlimited


@dataclass
class CampaignStats:
    """Statistics for a fuzzing campaign.

    Attributes:
        campaign_id: Campaign identifier
        start_time: When the campaign started
        total_tasks: Total tasks created
        completed_tasks: Tasks completed
        crashes_found: Unique crashes found
        coverage_percent: Current coverage
        active_workers: Number of active workers
        executions_per_sec: Current execution rate

    """

    campaign_id: str
    start_time: datetime = field(default_factory=datetime.now)
    total_tasks: int = 0
    completed_tasks: int = 0
    crashes_found: int = 0
    coverage_percent: float = 0.0
    active_workers: int = 0
    executions_per_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "start_time": self.start_time.isoformat(),
            "runtime_seconds": (datetime.now() - self.start_time).total_seconds(),
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "crashes_found": self.crashes_found,
            "coverage_percent": self.coverage_percent,
            "active_workers": self.active_workers,
            "executions_per_sec": self.executions_per_sec,
        }


@dataclass
class WorkerInfo:
    """Information about a connected worker.

    Attributes:
        worker_id: Unique worker identifier
        hostname: Worker hostname
        last_heartbeat: Last heartbeat time
        tasks_completed: Tasks completed by this worker
        crashes_found: Crashes found by this worker

    """

    worker_id: str
    hostname: str = ""
    last_heartbeat: datetime = field(default_factory=datetime.now)
    tasks_completed: int = 0
    crashes_found: int = 0


class FuzzingCoordinator:
    """Coordinator for distributed fuzzing campaigns.

    Manages the distribution of fuzzing tasks across multiple workers,
    aggregates results, and tracks campaign progress.

    Usage:
        coordinator = FuzzingCoordinator(redis_url="redis://localhost:6379")
        coordinator.start_campaign(config)

        # Monitor progress
        while coordinator.is_running():
            stats = coordinator.get_stats()
            print(f"Completed: {stats.completed_tasks}")
            time.sleep(1)

        # Get results
        crashes = coordinator.get_crashes()
        coordinator.stop()

    """

    def __init__(
        self,
        redis_url: str | None = None,
        requeue_interval: int = 60,
        heartbeat_timeout: int = 120,
    ):
        """Initialize coordinator.

        Args:
            redis_url: Redis connection URL (None for in-memory)
            requeue_interval: Seconds between stale task checks
            heartbeat_timeout: Seconds before worker considered dead

        """
        self.redis_url = redis_url
        self.requeue_interval = requeue_interval
        self.heartbeat_timeout = heartbeat_timeout

        self._queue: TaskQueue | InMemoryTaskQueue | None = None
        self._config: CampaignConfig | None = None
        self._stats: CampaignStats | None = None
        self._workers: dict[str, WorkerInfo] = {}
        self._crashes: list[dict[str, Any]] = []
        self._running = False
        self._lock = threading.Lock()

        # Background threads
        self._result_thread: threading.Thread | None = None
        self._maintenance_thread: threading.Thread | None = None

        # Callbacks
        self._on_crash_callbacks: list[Callable[[dict[str, Any]], None]] = []
        self._on_progress_callbacks: list[Callable[[dict[str, Any]], None]] = []

        logger.info("Fuzzing coordinator initialized")

    def start_campaign(self, config: CampaignConfig) -> None:
        """Start a new fuzzing campaign.

        Args:
            config: Campaign configuration

        """
        if self._running:
            raise RuntimeError("Campaign already running")

        self._config = config
        self._stats = CampaignStats(campaign_id=config.campaign_id)
        self._crashes = []
        self._workers = {}

        # Initialize queue
        self._queue = create_task_queue(self.redis_url)

        # Clear any existing tasks
        self._queue.clear()

        # Create initial tasks from corpus
        self._create_corpus_tasks()

        # Start background threads
        self._running = True
        self._result_thread = threading.Thread(
            target=self._result_processor,
            daemon=True,
        )
        self._result_thread.start()

        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop,
            daemon=True,
        )
        self._maintenance_thread.start()

        logger.info(f"Campaign {config.campaign_id} started")

    def _create_corpus_tasks(self) -> None:
        """Create tasks from corpus files."""
        if self._config is None or self._queue is None or self._stats is None:
            logger.error("Campaign not properly initialized")
            return

        corpus_dir = Path(self._config.corpus_dir)
        if not corpus_dir.exists():
            logger.warning(f"Corpus directory not found: {corpus_dir}")
            return

        tasks = []
        for file_path in corpus_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in (".dcm", ".dicom"):
                task = FuzzingTask(
                    test_file=str(file_path),
                    target_executable=self._config.target_executable,
                    timeout=self._config.timeout,
                    strategy=self._config.strategy,
                    priority=TaskPriority.NORMAL,
                )
                tasks.append(task)

        if tasks:
            self._queue.enqueue_batch(tasks)
            self._stats.total_tasks = len(tasks)
            logger.info(f"Created {len(tasks)} tasks from corpus")
        else:
            logger.warning("No DICOM files found in corpus")

    def stop(self) -> None:
        """Stop the campaign."""
        self._running = False

        if self._result_thread and self._result_thread.is_alive():
            self._result_thread.join(timeout=5)
            if self._result_thread.is_alive():
                logger.warning("Result processor thread did not stop within timeout")

        if self._maintenance_thread and self._maintenance_thread.is_alive():
            self._maintenance_thread.join(timeout=5)
            if self._maintenance_thread.is_alive():
                logger.warning("Maintenance thread did not stop within timeout")

        if self._queue:
            self._queue.disconnect()

        logger.info("Campaign stopped")

    def is_running(self) -> bool:
        """Check if campaign is running.

        Returns:
            True if campaign is active

        """
        return self._running

    def add_task(
        self, test_file: str, priority: TaskPriority = TaskPriority.NORMAL
    ) -> None:
        """Add a new task to the queue.

        Args:
            test_file: Path to test file
            priority: Task priority

        """
        if not self._running or not self._queue or not self._config or not self._stats:
            raise RuntimeError("Campaign not running")

        task = FuzzingTask(
            test_file=test_file,
            target_executable=self._config.target_executable,
            timeout=self._config.timeout,
            strategy=self._config.strategy,
            priority=priority,
        )

        self._queue.enqueue(task)

        with self._lock:
            self._stats.total_tasks += 1

    def get_stats(self) -> CampaignStats | None:
        """Get current campaign statistics.

        Returns:
            CampaignStats or None if not running

        """
        if not self._stats:
            return None

        with self._lock:
            # Update queue stats
            if self._queue:
                queue_stats = self._queue.get_stats()
                self._stats.completed_tasks = queue_stats.get("completed", 0)
                self._stats.active_workers = len(self._workers)

            return self._stats

    def get_crashes(self) -> list[dict[str, Any]]:
        """Get list of discovered crashes.

        Returns:
            List of crash dictionaries

        """
        with self._lock:
            return list(self._crashes)

    def get_workers(self) -> list[WorkerInfo]:
        """Get list of connected workers.

        Returns:
            List of WorkerInfo objects

        """
        with self._lock:
            return list(self._workers.values())

    def _result_processor(self) -> None:
        """Background thread for processing results."""
        if self._queue is None:
            logger.error("Queue not initialized")
            return

        last_count = 0

        while self._running:
            try:
                results = self._queue.get_results(count=50)

                for result in results:
                    self._process_result(result)

                # Calculate execution rate (protected by lock since _stats is shared)
                with self._lock:
                    if self._stats is not None:
                        current_count = self._stats.completed_tasks
                        elapsed = (
                            datetime.now() - self._stats.start_time
                        ).total_seconds()
                        if elapsed > 0:
                            self._stats.executions_per_sec = (
                                current_count - last_count
                            ) / max(1, elapsed / 60)
                        last_count = current_count

                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Result processor error: {e}")
                time.sleep(1)

    def _process_result(self, result: TaskResult) -> None:
        """Process a single task result.

        Args:
            result: Task result to process

        """
        with self._lock:
            # Update worker stats
            if result.worker_id in self._workers:
                self._workers[result.worker_id].tasks_completed += 1
                if result.crash_found:
                    self._workers[result.worker_id].crashes_found += 1
            else:
                self._workers[result.worker_id] = WorkerInfo(
                    worker_id=result.worker_id,
                    tasks_completed=1,
                    crashes_found=1 if result.crash_found else 0,
                )

            # Track crashes
            if result.crash_found and self._stats is not None:
                crash_info = {
                    "task_id": result.task_id,
                    "worker_id": result.worker_id,
                    "timestamp": datetime.now().isoformat(),
                    **result.output_data,
                }
                self._crashes.append(crash_info)
                self._stats.crashes_found = len(self._crashes)

                # Trigger callbacks
                for callback in self._on_crash_callbacks:
                    try:
                        callback(crash_info)
                    except Exception as e:
                        logger.debug(f"Crash callback error: {e}")

            # Update coverage
            if result.coverage_delta > 0 and self._stats is not None:
                self._stats.coverage_percent += result.coverage_delta

        # Trigger progress callbacks
        if self._stats is not None:
            stats_dict: dict[str, Any] = {
                "campaign_id": self._stats.campaign_id,
                "start_time": self._stats.start_time.isoformat(),
                "total_tasks": self._stats.total_tasks,
                "completed_tasks": self._stats.completed_tasks,
                "crashes_found": self._stats.crashes_found,
                "coverage_percent": self._stats.coverage_percent,
                "executions_per_sec": self._stats.executions_per_sec,
                "active_workers": self._stats.active_workers,
            }
            for callback in self._on_progress_callbacks:
                try:
                    callback(stats_dict)
                except Exception as e:
                    logger.debug(f"Progress callback error: {e}")

    def _maintenance_loop(self) -> None:
        """Background thread for maintenance tasks."""
        if self._queue is None:
            logger.error("Queue not initialized")
            return

        while self._running:
            try:
                # Requeue stale tasks
                requeued = self._queue.requeue_stale_tasks()
                if requeued > 0:
                    logger.info(f"Requeued {requeued} stale tasks")

                # Check campaign duration
                if (
                    self._config is not None
                    and self._config.duration > 0
                    and self._stats is not None
                ):
                    elapsed = (datetime.now() - self._stats.start_time).total_seconds()
                    if elapsed >= self._config.duration:
                        logger.info("Campaign duration reached")
                        self._running = False
                        break

                # Remove dead workers
                self._prune_dead_workers()

                time.sleep(self.requeue_interval)

            except Exception as e:
                logger.error(f"Maintenance error: {e}")
                time.sleep(5)

    def _prune_dead_workers(self) -> None:
        """Remove workers that haven't sent heartbeat."""
        with self._lock:
            now = datetime.now()
            dead_workers = []

            for worker_id, info in self._workers.items():
                elapsed = (now - info.last_heartbeat).total_seconds()
                if elapsed > self.heartbeat_timeout:
                    dead_workers.append(worker_id)

            for worker_id in dead_workers:
                del self._workers[worker_id]
                logger.warning(f"Worker {worker_id} removed (no heartbeat)")

    def on_crash(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Register a callback for crash discoveries.

        Args:
            callback: Function to call when crash is found

        """
        self._on_crash_callbacks.append(callback)

    def on_progress(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Register a callback for progress updates.

        Args:
            callback: Function to call on progress (receives stats as dict)

        """
        self._on_progress_callbacks.append(callback)

    def worker_heartbeat(self, worker_id: str, hostname: str = "") -> None:
        """Update worker heartbeat.

        Args:
            worker_id: Worker identifier
            hostname: Worker hostname

        """
        with self._lock:
            if worker_id in self._workers:
                self._workers[worker_id].last_heartbeat = datetime.now()
            else:
                self._workers[worker_id] = WorkerInfo(
                    worker_id=worker_id,
                    hostname=hostname,
                )
