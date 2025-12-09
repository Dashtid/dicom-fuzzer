"""Distributed fuzzing support for DICOM Fuzzer.

This module provides multi-machine fuzzing capabilities using a
coordinator-worker architecture with Redis-backed task queues.

Components:
- coordinator: Master node that distributes work and aggregates results
- worker: Worker node that executes fuzzing tasks
- queue: Redis-backed task queue for job distribution

Architecture:
    Coordinator (Master)
         |
         +-- Redis Queue
         |
         +-- Worker 1
         +-- Worker 2
         +-- Worker N

Usage:
    # On coordinator machine
    coordinator = FuzzingCoordinator(redis_url="redis://localhost:6379")
    coordinator.start_campaign(target, corpus_dir, workers=4)

    # On worker machines
    worker = FuzzingWorker(redis_url="redis://localhost:6379")
    worker.start()
"""

from dicom_fuzzer.distributed.coordinator import FuzzingCoordinator
from dicom_fuzzer.distributed.queue import TaskQueue
from dicom_fuzzer.distributed.worker import FuzzingWorker

__all__ = ["FuzzingCoordinator", "FuzzingWorker", "TaskQueue"]
