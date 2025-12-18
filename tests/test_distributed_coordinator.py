"""Tests for the distributed coordinator module.

This module tests FuzzingCoordinator and related classes.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import pytest

from dicom_fuzzer.distributed.coordinator import (
    CampaignConfig,
    CampaignStats,
    FuzzingCoordinator,
    WorkerInfo,
)


class TestCampaignConfig:
    """Tests for CampaignConfig dataclass."""

    def test_required_fields(self) -> None:
        """Test config with required fields."""
        config = CampaignConfig(
            campaign_id="camp-001",
            target_executable="/path/to/target",
            corpus_dir="/path/to/corpus",
        )
        assert config.campaign_id == "camp-001"
        assert config.target_executable == "/path/to/target"
        assert config.corpus_dir == "/path/to/corpus"
        # Defaults
        assert config.output_dir == "./artifacts/fuzzed"
        assert config.timeout == 30.0
        assert config.strategy == "coverage_guided"
        assert config.max_workers == 4
        assert config.duration == 0  # Unlimited

    def test_custom_values(self) -> None:
        """Test config with custom values."""
        config = CampaignConfig(
            campaign_id="camp-002",
            target_executable="/target",
            corpus_dir="/corpus",
            output_dir="/output",
            timeout=60.0,
            strategy="mutation_based",
            max_workers=8,
            duration=3600,
        )
        assert config.output_dir == "/output"
        assert config.timeout == 60.0
        assert config.strategy == "mutation_based"
        assert config.max_workers == 8
        assert config.duration == 3600


class TestCampaignStats:
    """Tests for CampaignStats dataclass."""

    def test_default_values(self) -> None:
        """Test stats with default values."""
        stats = CampaignStats(campaign_id="camp-001")
        assert stats.campaign_id == "camp-001"
        assert stats.total_tasks == 0
        assert stats.completed_tasks == 0
        assert stats.crashes_found == 0
        assert stats.coverage_percent == 0.0
        assert stats.active_workers == 0
        assert stats.executions_per_sec == 0.0
        assert isinstance(stats.start_time, datetime)

    def test_custom_values(self) -> None:
        """Test stats with custom values."""
        now = datetime.now()
        stats = CampaignStats(
            campaign_id="camp-002",
            start_time=now,
            total_tasks=100,
            completed_tasks=50,
            crashes_found=3,
            coverage_percent=75.5,
            active_workers=4,
            executions_per_sec=25.0,
        )
        assert stats.total_tasks == 100
        assert stats.completed_tasks == 50
        assert stats.crashes_found == 3
        assert stats.coverage_percent == 75.5

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        now = datetime.now()
        stats = CampaignStats(
            campaign_id="camp-003",
            start_time=now,
            total_tasks=200,
            completed_tasks=100,
            crashes_found=5,
            coverage_percent=80.0,
            active_workers=2,
            executions_per_sec=30.0,
        )
        data = stats.to_dict()

        assert data["campaign_id"] == "camp-003"
        assert data["start_time"] == now.isoformat()
        assert data["total_tasks"] == 200
        assert data["completed_tasks"] == 100
        assert data["crashes_found"] == 5
        assert data["coverage_percent"] == 80.0
        assert data["active_workers"] == 2
        assert data["executions_per_sec"] == 30.0
        assert "runtime_seconds" in data
        assert data["runtime_seconds"] >= 0


class TestWorkerInfo:
    """Tests for WorkerInfo dataclass."""

    def test_default_values(self) -> None:
        """Test worker info with default values."""
        info = WorkerInfo(worker_id="worker-001")
        assert info.worker_id == "worker-001"
        assert info.hostname == ""
        assert isinstance(info.last_heartbeat, datetime)
        assert info.tasks_completed == 0
        assert info.crashes_found == 0

    def test_custom_values(self) -> None:
        """Test worker info with custom values."""
        now = datetime.now()
        info = WorkerInfo(
            worker_id="worker-002",
            hostname="server-01.local",
            last_heartbeat=now,
            tasks_completed=50,
            crashes_found=2,
        )
        assert info.hostname == "server-01.local"
        assert info.last_heartbeat == now
        assert info.tasks_completed == 50
        assert info.crashes_found == 2


class TestFuzzingCoordinator:
    """Tests for FuzzingCoordinator class."""

    def test_initialization_defaults(self) -> None:
        """Test coordinator initializes with defaults."""
        coordinator = FuzzingCoordinator()
        assert coordinator.redis_url is None
        assert coordinator.requeue_interval == 60
        assert coordinator.heartbeat_timeout == 120
        assert coordinator._running is False
        assert coordinator._config is None
        assert coordinator._stats is None

    def test_initialization_custom(self) -> None:
        """Test coordinator with custom values."""
        coordinator = FuzzingCoordinator(
            redis_url="redis://localhost:6379",
            requeue_interval=30,
            heartbeat_timeout=60,
        )
        assert coordinator.redis_url == "redis://localhost:6379"
        assert coordinator.requeue_interval == 30
        assert coordinator.heartbeat_timeout == 60

    def test_start_campaign(self) -> None:
        """Test starting a campaign."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="test-campaign",
            target_executable="/target",
            corpus_dir="/corpus",
        )

        coordinator.start_campaign(config)

        assert coordinator._config == config
        assert coordinator._stats is not None
        assert coordinator._stats.campaign_id == "test-campaign"
        assert coordinator._running is True

        # Cleanup
        coordinator.stop()

    def test_start_campaign_already_running(self) -> None:
        """Test starting campaign when one is already running."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="test",
            target_executable="/target",
            corpus_dir="/corpus",
        )

        coordinator.start_campaign(config)

        with pytest.raises(RuntimeError, match="already running"):
            coordinator.start_campaign(config)

        coordinator.stop()

    def test_stop(self) -> None:
        """Test stopping coordinator."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="test",
            target_executable="/target",
            corpus_dir="/corpus",
        )

        coordinator.start_campaign(config)
        assert coordinator._running is True

        coordinator.stop()
        assert coordinator._running is False

    def test_stop_not_running(self) -> None:
        """Test stopping when not running."""
        coordinator = FuzzingCoordinator()
        coordinator.stop()  # Should not raise

    def test_is_running(self) -> None:
        """Test is_running method."""
        coordinator = FuzzingCoordinator()
        assert coordinator.is_running() is False

        config = CampaignConfig(
            campaign_id="test",
            target_executable="/target",
            corpus_dir="/corpus",
        )
        coordinator.start_campaign(config)
        assert coordinator.is_running() is True

        coordinator.stop()
        assert coordinator.is_running() is False

    def test_get_stats_not_started(self) -> None:
        """Test getting stats before campaign started."""
        coordinator = FuzzingCoordinator()
        stats = coordinator.get_stats()
        assert stats is None

    def test_get_stats(self) -> None:
        """Test getting stats during campaign."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="stats-test",
            target_executable="/target",
            corpus_dir="/corpus",
        )

        coordinator.start_campaign(config)
        stats = coordinator.get_stats()

        assert stats is not None
        assert stats.campaign_id == "stats-test"

        coordinator.stop()

    def test_get_crashes_empty(self) -> None:
        """Test getting crashes when none found."""
        coordinator = FuzzingCoordinator()
        crashes = coordinator.get_crashes()
        assert crashes == []

    def test_on_crash_callback(self) -> None:
        """Test crash callback registration."""
        coordinator = FuzzingCoordinator()
        callback_data: list[dict[str, Any]] = []

        def callback(crash: dict[str, Any]) -> None:
            callback_data.append(crash)

        coordinator.on_crash(callback)
        assert len(coordinator._on_crash_callbacks) == 1

    def test_on_progress_callback(self) -> None:
        """Test progress callback registration."""
        coordinator = FuzzingCoordinator()
        callback_data: list[dict[str, Any]] = []

        def callback(progress: dict[str, Any]) -> None:
            callback_data.append(progress)

        coordinator.on_progress(callback)
        assert len(coordinator._on_progress_callbacks) == 1

    def test_worker_heartbeat_new_worker(self) -> None:
        """Test worker heartbeat creates new worker."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="test",
            target_executable="/target",
            corpus_dir="/corpus",
        )
        coordinator.start_campaign(config)

        # Heartbeat from new worker should create entry
        coordinator.worker_heartbeat("worker-001", "host-001")
        assert "worker-001" in coordinator._workers
        assert coordinator._workers["worker-001"].hostname == "host-001"

        coordinator.stop()

    def test_worker_heartbeat_existing_worker(self) -> None:
        """Test worker heartbeat updates existing worker."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="test",
            target_executable="/target",
            corpus_dir="/corpus",
        )
        coordinator.start_campaign(config)

        # First heartbeat creates worker
        coordinator.worker_heartbeat("worker-001", "host-001")
        first_heartbeat = coordinator._workers["worker-001"].last_heartbeat

        time.sleep(0.1)

        # Second heartbeat updates time
        coordinator.worker_heartbeat("worker-001")
        second_heartbeat = coordinator._workers["worker-001"].last_heartbeat

        assert second_heartbeat > first_heartbeat

        coordinator.stop()

    def test_get_workers(self) -> None:
        """Test getting workers list."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="test",
            target_executable="/target",
            corpus_dir="/corpus",
        )
        coordinator.start_campaign(config)

        coordinator.worker_heartbeat("w1", "h1")
        coordinator.worker_heartbeat("w2", "h2")

        workers = coordinator.get_workers()
        assert len(workers) == 2

        worker_ids = [w.worker_id for w in workers]
        assert "w1" in worker_ids
        assert "w2" in worker_ids

        coordinator.stop()


class TestFuzzingCoordinatorIntegration:
    """Integration tests for FuzzingCoordinator."""

    def test_full_workflow(self) -> None:
        """Test complete campaign workflow."""
        coordinator = FuzzingCoordinator()
        config = CampaignConfig(
            campaign_id="integration-test",
            target_executable="/target",
            corpus_dir="/corpus",
            max_workers=2,
        )

        # Start campaign
        coordinator.start_campaign(config)
        assert coordinator.is_running()

        # Register workers via heartbeat
        coordinator.worker_heartbeat("w1", "host1")
        coordinator.worker_heartbeat("w2", "host2")

        # Get stats
        stats = coordinator.get_stats()
        assert stats is not None
        assert stats.campaign_id == "integration-test"

        # Get workers
        workers = coordinator.get_workers()
        assert len(workers) == 2

        # Stop
        coordinator.stop()
        assert not coordinator.is_running()
