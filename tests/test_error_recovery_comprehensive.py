"""Comprehensive tests for error_recovery module.

Tests checkpoint/resume functionality, error recovery, and campaign state management.
"""

import json
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from dicom_fuzzer.core.error_recovery import (
    CampaignCheckpoint,
    CampaignRecovery,
    CampaignStatus,
)


class TestCampaignStatus:
    """Test CampaignStatus enum."""

    def test_all_statuses_defined(self):
        """Test all campaign statuses are defined."""
        assert CampaignStatus.PENDING
        assert CampaignStatus.RUNNING
        assert CampaignStatus.PAUSED
        assert CampaignStatus.COMPLETED
        assert CampaignStatus.FAILED
        assert CampaignStatus.INTERRUPTED

    def test_status_values(self):
        """Test status values are correct."""
        assert CampaignStatus.PENDING.value == "pending"
        assert CampaignStatus.RUNNING.value == "running"
        assert CampaignStatus.COMPLETED.value == "completed"


class TestCampaignCheckpoint:
    """Test CampaignCheckpoint dataclass."""

    def test_initialization(self):
        """Test checkpoint initialization."""
        checkpoint = CampaignCheckpoint(
            campaign_id="test-001",
            status=CampaignStatus.RUNNING,
            start_time=time.time(),
            last_update=time.time(),
            total_files=100,
            processed_files=50,
            successful=45,
            failed=5,
            crashes=2,
            current_file_index=50,
            test_files=["file1.dcm", "file2.dcm"],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={"target": "test"},
        )

        assert checkpoint.campaign_id == "test-001"
        assert checkpoint.status == CampaignStatus.RUNNING
        assert checkpoint.total_files == 100
        assert checkpoint.processed_files == 50

    def test_to_dict_conversion(self):
        """Test checkpoint to dictionary conversion."""
        checkpoint = CampaignCheckpoint(
            campaign_id="test-002",
            status=CampaignStatus.PAUSED,
            start_time=1000.0,
            last_update=2000.0,
            total_files=10,
            processed_files=5,
            successful=4,
            failed=1,
            crashes=0,
            current_file_index=5,
            test_files=["a.dcm"],
            output_dir="/out",
            crash_dir="/crash",
            metadata={},
        )

        data = checkpoint.to_dict()

        assert isinstance(data, dict)
        assert data["campaign_id"] == "test-002"
        assert data["status"] == "paused"
        assert data["total_files"] == 10

    def test_from_dict_creation(self):
        """Test creating checkpoint from dictionary."""
        data = {
            "campaign_id": "test-003",
            "status": "running",
            "start_time": 1000.0,
            "last_update": 1500.0,
            "total_files": 200,
            "processed_files": 100,
            "successful": 95,
            "failed": 5,
            "crashes": 3,
            "current_file_index": 100,
            "test_files": ["file1.dcm", "file2.dcm"],
            "output_dir": "/output",
            "crash_dir": "/crashes",
            "metadata": {"key": "value"},
        }

        checkpoint = CampaignCheckpoint.from_dict(data)

        assert checkpoint.campaign_id == "test-003"
        assert checkpoint.status == CampaignStatus.RUNNING
        assert checkpoint.total_files == 200
        assert checkpoint.metadata == {"key": "value"}

    def test_round_trip_serialization(self):
        """Test checkpoint serialization round-trip."""
        original = CampaignCheckpoint(
            campaign_id="test-rt",
            status=CampaignStatus.COMPLETED,
            start_time=1000.0,
            last_update=2000.0,
            total_files=50,
            processed_files=50,
            successful=48,
            failed=2,
            crashes=1,
            current_file_index=50,
            test_files=["a.dcm", "b.dcm"],
            output_dir="/out",
            crash_dir="/crash",
            metadata={"test": "data"},
        )

        data = original.to_dict()
        restored = CampaignCheckpoint.from_dict(data)

        assert restored.campaign_id == original.campaign_id
        assert restored.status == original.status
        assert restored.total_files == original.total_files
        assert restored.metadata == original.metadata


class TestCampaignRecoveryInitialization:
    """Test CampaignRecovery initialization."""

    def test_default_initialization(self):
        """Test recovery manager with defaults."""
        recovery = CampaignRecovery()

        assert recovery.checkpoint_dir == Path("./checkpoints")
        assert recovery.checkpoint_interval == 100
        assert recovery.enable_auto_resume is True

    def test_custom_initialization(self):
        """Test recovery manager with custom parameters."""
        recovery = CampaignRecovery(
            checkpoint_dir="/custom/path",
            checkpoint_interval=50,
            enable_auto_resume=False,
        )

        assert recovery.checkpoint_dir == Path("/custom/path")
        assert recovery.checkpoint_interval == 50
        assert recovery.enable_auto_resume is False

    def test_creates_checkpoint_directory(self, tmp_path):
        """Test checkpoint directory creation."""
        checkpoint_dir = tmp_path / "checkpoints"
        recovery = CampaignRecovery(checkpoint_dir=str(checkpoint_dir))

        assert checkpoint_dir.exists()
        assert checkpoint_dir.is_dir()


class TestCheckpointOperations:
    """Test checkpoint save/load operations."""

    def test_save_checkpoint(self, tmp_path):
        """Test saving checkpoint to disk."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        checkpoint = CampaignCheckpoint(
            campaign_id="save-test",
            status=CampaignStatus.RUNNING,
            start_time=time.time(),
            last_update=time.time(),
            total_files=100,
            processed_files=50,
            successful=48,
            failed=2,
            crashes=1,
            current_file_index=50,
            test_files=["file.dcm"],
            output_dir="/out",
            crash_dir="/crash",
            metadata={},
        )

        recovery.save_checkpoint(checkpoint)

        # Verify file exists
        checkpoint_file = tmp_path / f"{checkpoint.campaign_id}.json"
        assert checkpoint_file.exists()

    def test_load_checkpoint(self, tmp_path):
        """Test loading checkpoint from disk."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        # Create and save checkpoint
        original = CampaignCheckpoint(
            campaign_id="load-test",
            status=CampaignStatus.PAUSED,
            start_time=1000.0,
            last_update=2000.0,
            total_files=200,
            processed_files=100,
            successful=95,
            failed=5,
            crashes=2,
            current_file_index=100,
            test_files=["a.dcm", "b.dcm"],
            output_dir="/output",
            crash_dir="/crashes",
            metadata={"key": "value"},
        )

        recovery.save_checkpoint(original)

        # Load it back
        loaded = recovery.load_checkpoint("load-test")

        assert loaded is not None
        assert loaded.campaign_id == "load-test"
        assert loaded.status == CampaignStatus.PAUSED
        assert loaded.processed_files == 100

    def test_load_nonexistent_checkpoint(self, tmp_path):
        """Test loading checkpoint that doesn't exist."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        checkpoint = recovery.load_checkpoint("nonexistent")

        assert checkpoint is None

    def test_checkpoint_persistence(self, tmp_path):
        """Test checkpoint persists across recovery instances."""
        checkpoint = CampaignCheckpoint(
            campaign_id="persist-test",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=2000.0,
            total_files=100,
            processed_files=50,
            successful=48,
            failed=2,
            crashes=0,
            current_file_index=50,
            test_files=["file.dcm"],
            output_dir="/out",
            crash_dir="/crash",
            metadata={},
        )

        # Save with first instance
        recovery1 = CampaignRecovery(checkpoint_dir=str(tmp_path))
        recovery1.save_checkpoint(checkpoint)

        # Load with new instance
        recovery2 = CampaignRecovery(checkpoint_dir=str(tmp_path))
        loaded = recovery2.load_checkpoint("persist-test")

        assert loaded is not None
        assert loaded.campaign_id == checkpoint.campaign_id


class TestCampaignResumption:
    """Test campaign resumption logic."""

    def test_should_resume_interrupted_campaign(self, tmp_path):
        """Test detection of interrupted campaigns."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(tmp_path), enable_auto_resume=True
        )

        # Create interrupted checkpoint
        checkpoint = CampaignCheckpoint(
            campaign_id="interrupted",
            status=CampaignStatus.INTERRUPTED,
            start_time=1000.0,
            last_update=2000.0,
            total_files=100,
            processed_files=50,
            successful=45,
            failed=5,
            crashes=0,
            current_file_index=50,
            test_files=["file.dcm"],
            output_dir="/out",
            crash_dir="/crash",
            metadata={},
        )

        recovery.save_checkpoint(checkpoint)

        # Check if should resume
        should_resume = recovery.should_resume("interrupted")

        assert should_resume is True

    def test_no_resume_for_completed_campaign(self, tmp_path):
        """Test completed campaigns are not resumed."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        checkpoint = CampaignCheckpoint(
            campaign_id="completed",
            status=CampaignStatus.COMPLETED,
            start_time=1000.0,
            last_update=2000.0,
            total_files=100,
            processed_files=100,
            successful=100,
            failed=0,
            crashes=0,
            current_file_index=100,
            test_files=[],
            output_dir="/out",
            crash_dir="/crash",
            metadata={},
        )

        recovery.save_checkpoint(checkpoint)

        should_resume = recovery.should_resume("completed")

        assert should_resume is False

    def test_auto_resume_disabled(self, tmp_path):
        """Test no resume when auto_resume disabled."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(tmp_path), enable_auto_resume=False
        )

        assert recovery.enable_auto_resume is False


class TestCheckpointListing:
    """Test listing available checkpoints."""

    def test_list_checkpoints_empty(self, tmp_path):
        """Test listing when no checkpoints exist."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        checkpoints = recovery.list_checkpoints()

        assert isinstance(checkpoints, list)
        assert len(checkpoints) == 0

    def test_list_checkpoints_multiple(self, tmp_path):
        """Test listing multiple checkpoints."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        # Create multiple checkpoints
        for i in range(3):
            checkpoint = CampaignCheckpoint(
                campaign_id=f"campaign-{i}",
                status=CampaignStatus.RUNNING,
                start_time=float(i * 1000),
                last_update=float(i * 1000),
                total_files=100,
                processed_files=50,
                successful=48,
                failed=2,
                crashes=0,
                current_file_index=50,
                test_files=[],
                output_dir="/out",
                crash_dir="/crash",
                metadata={},
            )
            recovery.save_checkpoint(checkpoint)

        checkpoints = recovery.list_checkpoints()

        assert len(checkpoints) == 3
        assert all("campaign-" in cp for cp in checkpoints)


class TestIntegrationScenarios:
    """Test integration scenarios."""

    def test_complete_checkpoint_workflow(self, tmp_path):
        """Test complete checkpoint save/load workflow."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        # Create checkpoint
        checkpoint = CampaignCheckpoint(
            campaign_id="workflow-test",
            status=CampaignStatus.RUNNING,
            start_time=time.time(),
            last_update=time.time(),
            total_files=1000,
            processed_files=500,
            successful=490,
            failed=10,
            crashes=5,
            current_file_index=500,
            test_files=["a.dcm", "b.dcm"],
            output_dir="/output",
            crash_dir="/crashes",
            metadata={"target": "test.dcm"},
        )

        # Save
        recovery.save_checkpoint(checkpoint)

        # Load
        loaded = recovery.load_checkpoint("workflow-test")

        # Verify
        assert loaded is not None
        assert loaded.campaign_id == checkpoint.campaign_id
        assert loaded.processed_files == 500
        assert loaded.crashes == 5

    def test_checkpoint_update_workflow(self, tmp_path):
        """Test updating checkpoint during campaign."""
        recovery = CampaignRecovery(checkpoint_dir=str(tmp_path))

        # Initial checkpoint
        checkpoint = CampaignCheckpoint(
            campaign_id="update-test",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=1000.0,
            total_files=100,
            processed_files=0,
            successful=0,
            failed=0,
            crashes=0,
            current_file_index=0,
            test_files=["file.dcm"],
            output_dir="/out",
            crash_dir="/crash",
            metadata={},
        )

        recovery.save_checkpoint(checkpoint)

        # Update progress
        checkpoint.processed_files = 50
        checkpoint.successful = 48
        checkpoint.failed = 2
        checkpoint.current_file_index = 50
        checkpoint.last_update = 2000.0

        recovery.save_checkpoint(checkpoint)

        # Load and verify updated state
        loaded = recovery.load_checkpoint("update-test")

        assert loaded.processed_files == 50
        assert loaded.successful == 48
