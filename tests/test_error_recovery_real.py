"""Real-world tests for error_recovery module.

Tests the error recovery and checkpoint/resume functionality with realistic scenarios.
"""

import json
import time

import pytest

from dicom_fuzzer.core.error_recovery import (
    CampaignCheckpoint,
    CampaignRecovery,
    CampaignStatus,
    SignalHandler,
    with_error_recovery,
)


@pytest.fixture
def temp_checkpoint_dir(tmp_path):
    """Create temporary directory for checkpoints."""
    checkpoint_dir = tmp_path / "checkpoints"
    checkpoint_dir.mkdir()
    return checkpoint_dir


@pytest.fixture
def sample_test_files(tmp_path):
    """Create sample test files."""
    files = []
    for i in range(5):
        file_path = tmp_path / f"test_file_{i}.dcm"
        file_path.write_text(f"test content {i}")
        files.append(file_path)
    return files


class TestCampaignStatusEnum:
    """Test CampaignStatus enum."""

    def test_status_values(self):
        """Test that all expected status values exist."""
        assert CampaignStatus.PENDING.value == "pending"
        assert CampaignStatus.RUNNING.value == "running"
        assert CampaignStatus.PAUSED.value == "paused"
        assert CampaignStatus.COMPLETED.value == "completed"
        assert CampaignStatus.FAILED.value == "failed"
        assert CampaignStatus.INTERRUPTED.value == "interrupted"


class TestCampaignCheckpointDataclass:
    """Test CampaignCheckpoint dataclass."""

    def test_checkpoint_creation(self, sample_test_files):
        """Test creating checkpoint."""
        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=time.time(),
            last_update=time.time(),
            total_files=5,
            processed_files=2,
            successful=1,
            failed=0,
            crashes=1,
            current_file_index=2,
            test_files=[str(f) for f in sample_test_files],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={"version": "1.0"},
        )

        assert checkpoint.campaign_id == "test_campaign"
        assert checkpoint.total_files == 5
        assert checkpoint.processed_files == 2
        assert len(checkpoint.test_files) == 5

    def test_checkpoint_to_dict(self):
        """Test converting checkpoint to dictionary."""
        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=1100.0,
            total_files=10,
            processed_files=5,
            successful=3,
            failed=1,
            crashes=1,
            current_file_index=5,
            test_files=["file1.dcm", "file2.dcm"],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={},
        )

        data = checkpoint.to_dict()

        assert isinstance(data, dict)
        assert data["campaign_id"] == "test_campaign"
        assert data["status"] == "running"  # Converted to string
        assert data["total_files"] == 10

    def test_checkpoint_from_dict(self):
        """Test creating checkpoint from dictionary."""
        data = {
            "campaign_id": "test_campaign",
            "status": "running",
            "start_time": 1000.0,
            "last_update": 1100.0,
            "total_files": 10,
            "processed_files": 5,
            "successful": 3,
            "failed": 1,
            "crashes": 1,
            "current_file_index": 5,
            "test_files": ["file1.dcm"],
            "output_dir": "/tmp/output",
            "crash_dir": "/tmp/crashes",
            "metadata": {},
        }

        checkpoint = CampaignCheckpoint.from_dict(data)

        assert checkpoint.campaign_id == "test_campaign"
        assert checkpoint.status == CampaignStatus.RUNNING  # Converted to enum
        assert checkpoint.total_files == 10


class TestCampaignRecoveryInitialization:
    """Test CampaignRecovery initialization."""

    def test_initialization_default(self, temp_checkpoint_dir):
        """Test creating recovery manager with defaults."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir),
        )

        assert recovery.checkpoint_dir == temp_checkpoint_dir
        assert recovery.checkpoint_interval == 100
        assert recovery.enable_auto_resume is True
        assert recovery.current_checkpoint is None

    def test_initialization_custom(self, temp_checkpoint_dir):
        """Test creating recovery manager with custom settings."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir),
            checkpoint_interval=50,
            enable_auto_resume=False,
        )

        assert recovery.checkpoint_interval == 50
        assert recovery.enable_auto_resume is False

    def test_initialization_creates_directory(self, tmp_path):
        """Test that initialization creates checkpoint directory."""
        checkpoint_dir = tmp_path / "new_checkpoints"
        assert not checkpoint_dir.exists()

        CampaignRecovery(checkpoint_dir=str(checkpoint_dir))

        assert checkpoint_dir.exists()


class TestCheckpointCreation:
    """Test checkpoint creation."""

    def test_create_checkpoint(self, temp_checkpoint_dir, sample_test_files):
        """Test creating a new checkpoint."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=1,
            failed=0,
            crashes=1,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={"version": "1.0"},
        )

        assert checkpoint is not None
        assert checkpoint.campaign_id == "test_campaign"
        assert checkpoint.status == CampaignStatus.RUNNING
        assert checkpoint.total_files == 5
        assert checkpoint.processed_files == 2
        assert recovery.current_checkpoint == checkpoint

    def test_create_checkpoint_preserves_start_time(
        self, temp_checkpoint_dir, sample_test_files
    ):
        """Test that creating subsequent checkpoints preserves start time."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint1 = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=1,
            successful=1,
            failed=0,
            crashes=0,
            current_file_index=1,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        time.sleep(0.1)  # Ensure time difference

        checkpoint2 = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        assert checkpoint1.start_time == checkpoint2.start_time
        assert checkpoint2.last_update > checkpoint1.last_update


class TestCheckpointSaving:
    """Test checkpoint saving functionality."""

    def test_save_checkpoint(self, temp_checkpoint_dir, sample_test_files):
        """Test saving checkpoint to disk."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=1,
            failed=0,
            crashes=1,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        checkpoint_path = recovery.save_checkpoint(checkpoint)

        assert checkpoint_path.exists()
        assert checkpoint_path.name == "test_campaign_checkpoint.json"

    def test_save_checkpoint_atomic_write(self, temp_checkpoint_dir, sample_test_files):
        """Test that checkpoint is saved atomically."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=1,
            failed=0,
            crashes=1,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        checkpoint_path = recovery.save_checkpoint(checkpoint)

        # Verify no temp file left behind
        temp_file = checkpoint_path.with_suffix(".tmp")
        assert not temp_file.exists()

    def test_save_checkpoint_no_current(self, temp_checkpoint_dir):
        """Test saving without current checkpoint raises error."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        with pytest.raises(ValueError, match="No checkpoint to save"):
            recovery.save_checkpoint()

    def test_save_checkpoint_overwrites_existing(
        self, temp_checkpoint_dir, sample_test_files
    ):
        """Test that saving overwrites existing checkpoint."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint1 = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=1,
            successful=1,
            failed=0,
            crashes=0,
            current_file_index=1,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        recovery.save_checkpoint(checkpoint1)

        checkpoint2 = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        checkpoint_path = recovery.save_checkpoint(checkpoint2)

        # Load and verify it's the second checkpoint
        with open(checkpoint_path, "r") as f:
            data = json.load(f)

        assert data["processed_files"] == 2


class TestCheckpointLoading:
    """Test checkpoint loading functionality."""

    def test_load_checkpoint(self, temp_checkpoint_dir, sample_test_files):
        """Test loading checkpoint from disk."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        # Create and save checkpoint
        original = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=1,
            failed=0,
            crashes=1,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={"key": "value"},
        )

        recovery.save_checkpoint(original)

        # Create new recovery instance and load
        recovery2 = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))
        loaded = recovery2.load_checkpoint("test_campaign")

        assert loaded is not None
        assert loaded.campaign_id == "test_campaign"
        assert loaded.total_files == 5
        assert loaded.processed_files == 2
        assert loaded.metadata["key"] == "value"

    def test_load_checkpoint_nonexistent(self, temp_checkpoint_dir):
        """Test loading nonexistent checkpoint returns None."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        loaded = recovery.load_checkpoint("nonexistent_campaign")

        assert loaded is None

    def test_load_checkpoint_corrupted_json(self, temp_checkpoint_dir):
        """Test loading corrupted JSON returns None."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        # Create corrupted JSON file
        checkpoint_file = temp_checkpoint_dir / "corrupted_campaign_checkpoint.json"
        checkpoint_file.write_text("{ invalid json")

        loaded = recovery.load_checkpoint("corrupted_campaign")

        assert loaded is None


class TestCheckpointValidation:
    """Test checkpoint validation."""

    def test_validate_checkpoint_valid(self, temp_checkpoint_dir, sample_test_files):
        """Test validating valid checkpoint."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=1100.0,
            total_files=5,
            processed_files=2,
            successful=1,
            failed=0,
            crashes=1,
            current_file_index=2,
            test_files=[str(f) for f in sample_test_files],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={},
        )

        assert recovery._validate_checkpoint(checkpoint) is True

    def test_validate_checkpoint_processed_exceeds_total(self, temp_checkpoint_dir):
        """Test validation fails when processed > total."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=1100.0,
            total_files=5,
            processed_files=10,  # Invalid: more than total
            successful=5,
            failed=0,
            crashes=0,
            current_file_index=5,
            test_files=["file1.dcm"],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={},
        )

        assert recovery._validate_checkpoint(checkpoint) is False

    def test_validate_checkpoint_negative_counts(self, temp_checkpoint_dir):
        """Test validation fails with negative counts."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=1100.0,
            total_files=5,
            processed_files=-1,  # Invalid: negative
            successful=0,
            failed=0,
            crashes=0,
            current_file_index=0,
            test_files=["file1.dcm"],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={},
        )

        assert recovery._validate_checkpoint(checkpoint) is False

    def test_validate_checkpoint_invalid_index(self, temp_checkpoint_dir):
        """Test validation fails with invalid file index."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=1000.0,
            last_update=1100.0,
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=10,  # Invalid: exceeds test_files length
            test_files=["file1.dcm"],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={},
        )

        assert recovery._validate_checkpoint(checkpoint) is False

    def test_validate_checkpoint_invalid_timestamps(self, temp_checkpoint_dir):
        """Test validation fails with invalid timestamps."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = CampaignCheckpoint(
            campaign_id="test_campaign",
            status=CampaignStatus.RUNNING,
            start_time=2000.0,
            last_update=1000.0,  # Invalid: before start_time
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=2,
            test_files=["file1.dcm"],
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={},
        )

        assert recovery._validate_checkpoint(checkpoint) is False


class TestShouldCheckpoint:
    """Test checkpoint interval logic."""

    def test_should_checkpoint_interval_not_reached(self, temp_checkpoint_dir):
        """Test that checkpoint is not triggered before interval."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir), checkpoint_interval=10
        )

        recovery.files_since_checkpoint = 5

        assert recovery.should_checkpoint() is False

    def test_should_checkpoint_interval_reached(self, temp_checkpoint_dir):
        """Test that checkpoint is triggered at interval."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir), checkpoint_interval=10
        )

        recovery.files_since_checkpoint = 10

        assert recovery.should_checkpoint() is True

    def test_should_checkpoint_force(self, temp_checkpoint_dir):
        """Test forced checkpoint ignores interval."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir), checkpoint_interval=100
        )

        recovery.files_since_checkpoint = 0

        assert recovery.should_checkpoint(force=True) is True


class TestCampaignStatusChanges:
    """Test campaign status change methods."""

    def test_mark_completed(self, temp_checkpoint_dir, sample_test_files):
        """Test marking campaign as completed."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=5,
            successful=5,
            failed=0,
            crashes=0,
            current_file_index=5,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        recovery.mark_completed("test_campaign")

        assert checkpoint.status == CampaignStatus.COMPLETED

    def test_mark_failed(self, temp_checkpoint_dir, sample_test_files):
        """Test marking campaign as failed."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=1,
            failed=1,
            crashes=0,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        recovery.mark_failed("test_campaign", "Test failure reason")

        assert checkpoint.status == CampaignStatus.FAILED
        assert checkpoint.metadata["failure_reason"] == "Test failure reason"

    def test_mark_interrupted(self, temp_checkpoint_dir, sample_test_files):
        """Test marking campaign as interrupted."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        recovery.mark_interrupted("test_campaign")

        assert checkpoint.status == CampaignStatus.INTERRUPTED


class TestInterruptedCampaigns:
    """Test finding interrupted campaigns."""

    def test_list_interrupted_campaigns(self, temp_checkpoint_dir, sample_test_files):
        """Test listing interrupted campaigns."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        # Create running campaign
        checkpoint1 = recovery.create_checkpoint(
            campaign_id="running_campaign",
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )
        recovery.save_checkpoint(checkpoint1)

        # Create completed campaign
        recovery.current_checkpoint = None
        checkpoint2 = recovery.create_checkpoint(
            campaign_id="completed_campaign",
            total_files=5,
            processed_files=5,
            successful=5,
            failed=0,
            crashes=0,
            current_file_index=5,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )
        checkpoint2.status = CampaignStatus.COMPLETED
        recovery.save_checkpoint(checkpoint2)

        # List interrupted campaigns
        interrupted = recovery.list_interrupted_campaigns()

        assert len(interrupted) == 1
        assert interrupted[0].campaign_id == "running_campaign"

    def test_list_interrupted_campaigns_empty(self, temp_checkpoint_dir):
        """Test listing when no interrupted campaigns exist."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        interrupted = recovery.list_interrupted_campaigns()

        assert len(interrupted) == 0


class TestCheckpointCleanup:
    """Test checkpoint cleanup."""

    def test_cleanup_checkpoint(self, temp_checkpoint_dir, sample_test_files):
        """Test cleaning up checkpoint file."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=5,
            processed_files=5,
            successful=5,
            failed=0,
            crashes=0,
            current_file_index=5,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        checkpoint_path = recovery.save_checkpoint(checkpoint)
        assert checkpoint_path.exists()

        recovery.cleanup_checkpoint("test_campaign")

        assert not checkpoint_path.exists()

    def test_cleanup_checkpoint_nonexistent(self, temp_checkpoint_dir):
        """Test cleaning up nonexistent checkpoint doesn't error."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        # Should not raise error
        recovery.cleanup_checkpoint("nonexistent_campaign")


class TestUpdateProgress:
    """Test progress update functionality."""

    def test_update_progress(self, temp_checkpoint_dir, sample_test_files):
        """Test updating progress counters."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir), checkpoint_interval=10
        )

        checkpoint = recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=10,
            processed_files=0,
            successful=0,
            failed=0,
            crashes=0,
            current_file_index=0,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        recovery.update_progress(processed=5, successful=4, failed=0, crashes=1)

        assert checkpoint.processed_files == 5
        assert checkpoint.successful == 4
        assert checkpoint.crashes == 1
        assert recovery.files_since_checkpoint == 1

    def test_update_progress_triggers_checkpoint(
        self, temp_checkpoint_dir, sample_test_files
    ):
        """Test that progress update triggers checkpoint at interval."""
        recovery = CampaignRecovery(
            checkpoint_dir=str(temp_checkpoint_dir), checkpoint_interval=1
        )

        recovery.create_checkpoint(
            campaign_id="test_campaign",
            total_files=10,
            processed_files=0,
            successful=0,
            failed=0,
            crashes=0,
            current_file_index=0,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
        )

        # Verify checkpoint file doesn't exist yet
        checkpoint_file = temp_checkpoint_dir / "test_campaign_checkpoint.json"
        assert not checkpoint_file.exists()

        # First update increments counter and should trigger checkpoint save
        recovery.update_progress(processed=1, successful=1, failed=0, crashes=0)

        # Verify checkpoint was saved to disk
        assert checkpoint_file.exists()


class TestSignalHandler:
    """Test signal handler functionality."""

    def test_signal_handler_initialization(self):
        """Test creating signal handler."""
        handler = SignalHandler()

        assert handler.interrupted is False
        assert handler.recovery_manager is None

    def test_signal_handler_with_recovery(self, temp_checkpoint_dir):
        """Test creating signal handler with recovery manager."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))
        handler = SignalHandler(recovery_manager=recovery)

        assert handler.recovery_manager is recovery

    def test_check_interrupted_initially_false(self):
        """Test that interrupted is initially False."""
        handler = SignalHandler()

        assert handler.check_interrupted() is False


class TestErrorRecoveryDecorator:
    """Test error recovery decorator."""

    def test_with_error_recovery_success(self):
        """Test decorator with successful function."""
        call_count = [0]

        @with_error_recovery
        def successful_function():
            call_count[0] += 1
            return "success"

        result = successful_function()

        assert result == "success"
        assert call_count[0] == 1

    def test_with_error_recovery_retries(self):
        """Test decorator retries on failure."""
        call_count = [0]

        @with_error_recovery
        def failing_then_success():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary failure")
            return "success"

        result = failing_then_success()

        assert result == "success"
        assert call_count[0] == 3

    def test_with_error_recovery_max_retries(self):
        """Test decorator fails after max retries."""
        call_count = [0]

        @with_error_recovery
        def always_fails():
            call_count[0] += 1
            raise ValueError("Always fails")

        with pytest.raises(ValueError, match="Always fails"):
            always_fails()

        assert call_count[0] == 4  # Initial + 3 retries


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    def test_complete_checkpoint_resume_workflow(
        self, temp_checkpoint_dir, sample_test_files
    ):
        """Test complete checkpoint and resume workflow."""
        # Create initial campaign and save checkpoint
        recovery1 = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        checkpoint = recovery1.create_checkpoint(
            campaign_id="long_campaign",
            total_files=10,
            processed_files=5,
            successful=4,
            failed=0,
            crashes=1,
            current_file_index=5,
            test_files=sample_test_files,
            output_dir="/tmp/output",
            crash_dir="/tmp/crashes",
            metadata={"started_by": "test"},
        )

        recovery1.save_checkpoint(checkpoint)

        # Simulate restart - create new recovery instance
        recovery2 = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        # Load the checkpoint
        loaded = recovery2.load_checkpoint("long_campaign")

        assert loaded is not None
        assert loaded.campaign_id == "long_campaign"
        assert loaded.processed_files == 5
        assert loaded.current_file_index == 5
        assert loaded.metadata["started_by"] == "test"

        # Continue from checkpoint
        recovery2.update_progress(processed=6, successful=5, failed=0, crashes=1)

        assert loaded.processed_files == 6

    def test_multiple_campaigns(self, temp_checkpoint_dir, sample_test_files):
        """Test managing multiple campaigns simultaneously."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_checkpoint_dir))

        # Create first campaign
        checkpoint1 = recovery.create_checkpoint(
            campaign_id="campaign1",
            total_files=5,
            processed_files=2,
            successful=2,
            failed=0,
            crashes=0,
            current_file_index=2,
            test_files=sample_test_files,
            output_dir="/tmp/output1",
            crash_dir="/tmp/crashes1",
        )
        recovery.save_checkpoint(checkpoint1)

        # Create second campaign
        recovery.current_checkpoint = None
        checkpoint2 = recovery.create_checkpoint(
            campaign_id="campaign2",
            total_files=3,
            processed_files=1,
            successful=1,
            failed=0,
            crashes=0,
            current_file_index=1,
            test_files=sample_test_files[:3],
            output_dir="/tmp/output2",
            crash_dir="/tmp/crashes2",
        )
        recovery.save_checkpoint(checkpoint2)

        # Load both campaigns
        loaded1 = recovery.load_checkpoint("campaign1")
        loaded2 = recovery.load_checkpoint("campaign2")

        assert loaded1.total_files == 5
        assert loaded2.total_files == 3
        assert loaded1.output_dir == "/tmp/output1"
        assert loaded2.output_dir == "/tmp/output2"
