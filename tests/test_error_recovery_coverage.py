"""Tests for error_recovery module to improve code coverage.

These tests exercise the error recovery and campaign resumption code paths.
"""

import json
import signal
import time
from unittest.mock import patch

import pytest

from dicom_fuzzer.core.error_recovery import (
    CampaignCheckpoint,
    CampaignRecovery,
    CampaignStatus,
    SignalHandler,
    with_error_recovery,
)


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def recovery_manager(temp_dir):
    """Create CampaignRecovery instance."""
    return CampaignRecovery(
        checkpoint_dir=str(temp_dir / "checkpoints"),
        checkpoint_interval=10,
        enable_auto_resume=True,
    )


@pytest.fixture
def sample_checkpoint():
    """Create sample checkpoint data."""
    return CampaignCheckpoint(
        campaign_id="test-campaign-001",
        status=CampaignStatus.RUNNING,
        start_time=time.time() - 100,
        last_update=time.time(),
        total_files=100,
        processed_files=50,
        successful=45,
        failed=3,
        crashes=2,
        current_file_index=50,
        test_files=[f"/path/to/file{i}.dcm" for i in range(100)],
        output_dir="/output",
        crash_dir="/crashes",
        metadata={"strategy": "random"},
    )


class TestCampaignStatus:
    """Test CampaignStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert CampaignStatus.PENDING.value == "pending"
        assert CampaignStatus.RUNNING.value == "running"
        assert CampaignStatus.PAUSED.value == "paused"
        assert CampaignStatus.COMPLETED.value == "completed"
        assert CampaignStatus.FAILED.value == "failed"
        assert CampaignStatus.INTERRUPTED.value == "interrupted"


class TestCampaignCheckpoint:
    """Test CampaignCheckpoint dataclass."""

    def test_create_checkpoint(self, sample_checkpoint):
        """Test creating a checkpoint."""
        assert sample_checkpoint.campaign_id == "test-campaign-001"
        assert sample_checkpoint.status == CampaignStatus.RUNNING
        assert sample_checkpoint.total_files == 100
        assert sample_checkpoint.processed_files == 50

    def test_from_dict(self):
        """Test creating checkpoint from dict."""
        data = {
            "campaign_id": "test-001",
            "status": "running",
            "start_time": 1000.0,
            "last_update": 1100.0,
            "total_files": 50,
            "processed_files": 25,
            "successful": 20,
            "failed": 3,
            "crashes": 2,
            "current_file_index": 25,
            "test_files": ["/file1.dcm", "/file2.dcm"],
            "output_dir": "/output",
            "crash_dir": "/crashes",
            "metadata": {},
        }

        checkpoint = CampaignCheckpoint.from_dict(data)

        assert checkpoint.campaign_id == "test-001"
        assert checkpoint.status == CampaignStatus.RUNNING
        assert checkpoint.total_files == 50


class TestCampaignRecoveryInit:
    """Test CampaignRecovery initialization."""

    def test_init_creates_directory(self, temp_dir):
        """Test that init creates checkpoint directory."""
        checkpoint_dir = temp_dir / "checkpoints"
        recovery = CampaignRecovery(checkpoint_dir=str(checkpoint_dir))

        assert checkpoint_dir.exists()

    def test_init_with_defaults(self, temp_dir):
        """Test initialization with default values."""
        recovery = CampaignRecovery(checkpoint_dir=str(temp_dir))

        assert recovery.checkpoint_interval == 100
        assert recovery.enable_auto_resume is True
        assert recovery.current_checkpoint is None
        assert recovery.files_since_checkpoint == 0


class TestCreateCheckpoint:
    """Test create_checkpoint method."""

    def test_create_checkpoint(self, recovery_manager, temp_dir):
        """Test creating a new checkpoint."""
        test_files = [temp_dir / f"file{i}.dcm" for i in range(10)]

        checkpoint = recovery_manager.create_checkpoint(
            campaign_id="test-001",
            total_files=10,
            processed_files=5,
            successful=4,
            failed=1,
            crashes=0,
            current_file_index=5,
            test_files=test_files,
            output_dir=str(temp_dir / "output"),
            crash_dir=str(temp_dir / "crashes"),
        )

        assert checkpoint.campaign_id == "test-001"
        assert checkpoint.total_files == 10
        assert checkpoint.processed_files == 5
        assert recovery_manager.current_checkpoint == checkpoint
        assert recovery_manager.files_since_checkpoint == 0

    def test_create_checkpoint_preserves_start_time(self, recovery_manager, temp_dir):
        """Test that start_time is preserved on update."""
        test_files = [temp_dir / f"file{i}.dcm" for i in range(10)]

        # Create first checkpoint
        first_checkpoint = recovery_manager.create_checkpoint(
            campaign_id="test-001",
            total_files=10,
            processed_files=0,
            successful=0,
            failed=0,
            crashes=0,
            current_file_index=0,
            test_files=test_files,
            output_dir=str(temp_dir / "output"),
            crash_dir=str(temp_dir / "crashes"),
        )

        original_start_time = first_checkpoint.start_time
        time.sleep(0.01)

        # Create second checkpoint
        second_checkpoint = recovery_manager.create_checkpoint(
            campaign_id="test-001",
            total_files=10,
            processed_files=5,
            successful=4,
            failed=1,
            crashes=0,
            current_file_index=5,
            test_files=test_files,
            output_dir=str(temp_dir / "output"),
            crash_dir=str(temp_dir / "crashes"),
        )

        # Start time should be preserved
        assert second_checkpoint.start_time == original_start_time

    def test_create_checkpoint_with_metadata(self, recovery_manager, temp_dir):
        """Test creating checkpoint with metadata."""
        test_files = [temp_dir / "file.dcm"]

        checkpoint = recovery_manager.create_checkpoint(
            campaign_id="test-001",
            total_files=1,
            processed_files=0,
            successful=0,
            failed=0,
            crashes=0,
            current_file_index=0,
            test_files=test_files,
            output_dir=str(temp_dir),
            crash_dir=str(temp_dir),
            metadata={"strategy": "mutation", "seed": 12345},
        )

        assert checkpoint.metadata["strategy"] == "mutation"
        assert checkpoint.metadata["seed"] == 12345


class TestShouldCheckpoint:
    """Test should_checkpoint method."""

    def test_should_checkpoint_force(self, recovery_manager):
        """Test force checkpoint."""
        assert recovery_manager.should_checkpoint(force=True) is True

    def test_should_checkpoint_interval_not_reached(self, recovery_manager):
        """Test checkpoint not needed."""
        recovery_manager.files_since_checkpoint = 5
        assert recovery_manager.should_checkpoint() is False

    def test_should_checkpoint_interval_reached(self, recovery_manager):
        """Test checkpoint needed when interval reached."""
        recovery_manager.files_since_checkpoint = 10
        assert recovery_manager.should_checkpoint() is True


class TestSaveCheckpoint:
    """Test save_checkpoint method."""

    def test_save_checkpoint(self, recovery_manager, sample_checkpoint, temp_dir):
        """Test saving checkpoint to disk."""
        recovery_manager.current_checkpoint = sample_checkpoint

        path = recovery_manager.save_checkpoint()

        assert path.exists()
        assert path.name == f"{sample_checkpoint.campaign_id}_checkpoint.json"

    def test_save_checkpoint_explicit(self, recovery_manager, sample_checkpoint):
        """Test saving explicit checkpoint."""
        path = recovery_manager.save_checkpoint(sample_checkpoint)

        assert path.exists()

        # Verify content
        with open(path) as f:
            data = json.load(f)

        assert data["campaign_id"] == sample_checkpoint.campaign_id

    def test_save_checkpoint_no_checkpoint_raises(self, recovery_manager):
        """Test saving when no checkpoint available."""
        with pytest.raises(ValueError, match="No checkpoint to save"):
            recovery_manager.save_checkpoint()

    def test_save_checkpoint_overwrites_existing(
        self, recovery_manager, sample_checkpoint
    ):
        """Test that save overwrites existing checkpoint."""
        # Save first time
        recovery_manager.save_checkpoint(sample_checkpoint)

        # Modify and save again
        sample_checkpoint.processed_files = 75
        path = recovery_manager.save_checkpoint(sample_checkpoint)

        with open(path) as f:
            data = json.load(f)

        assert data["processed_files"] == 75


class TestLoadCheckpoint:
    """Test load_checkpoint method."""

    def test_load_checkpoint(self, recovery_manager, sample_checkpoint):
        """Test loading checkpoint from disk."""
        # Save checkpoint first
        recovery_manager.save_checkpoint(sample_checkpoint)

        # Load it back
        loaded = recovery_manager.load_checkpoint(sample_checkpoint.campaign_id)

        assert loaded is not None
        assert loaded.campaign_id == sample_checkpoint.campaign_id
        assert loaded.total_files == sample_checkpoint.total_files

    def test_load_checkpoint_not_found(self, recovery_manager):
        """Test loading non-existent checkpoint."""
        result = recovery_manager.load_checkpoint("nonexistent-campaign")

        assert result is None

    def test_load_checkpoint_corrupted_json(self, recovery_manager, temp_dir):
        """Test loading corrupted JSON file."""
        checkpoint_file = recovery_manager.checkpoint_dir / "corrupted_checkpoint.json"
        checkpoint_file.write_text("{ invalid json }")

        result = recovery_manager.load_checkpoint("corrupted")

        assert result is None

    def test_load_checkpoint_invalid_data(self, recovery_manager, temp_dir):
        """Test loading checkpoint with missing fields."""
        checkpoint_file = recovery_manager.checkpoint_dir / "invalid_checkpoint.json"
        with open(checkpoint_file, "w") as f:
            json.dump({"campaign_id": "test"}, f)  # Missing required fields

        result = recovery_manager.load_checkpoint("invalid")

        assert result is None


class TestValidateCheckpoint:
    """Test _validate_checkpoint method."""

    def test_validate_valid_checkpoint(self, recovery_manager, sample_checkpoint):
        """Test validation of valid checkpoint."""
        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is True

    def test_validate_processed_greater_than_total(
        self, recovery_manager, sample_checkpoint
    ):
        """Test validation fails when processed > total."""
        sample_checkpoint.processed_files = 150  # Greater than total_files=100

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is False

    def test_validate_negative_file_counts(self, recovery_manager, sample_checkpoint):
        """Test validation fails with negative counts."""
        sample_checkpoint.processed_files = -1

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is False

    def test_validate_negative_total_files(self, recovery_manager, sample_checkpoint):
        """Test validation fails with negative total."""
        sample_checkpoint.total_files = -5

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is False

    def test_validate_negative_file_index(self, recovery_manager, sample_checkpoint):
        """Test validation fails with negative index."""
        sample_checkpoint.current_file_index = -1

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is False

    def test_validate_index_exceeds_files(self, recovery_manager, sample_checkpoint):
        """Test validation fails when index > file count."""
        sample_checkpoint.current_file_index = 200  # Greater than len(test_files)

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is False

    def test_validate_timestamps(self, recovery_manager, sample_checkpoint):
        """Test validation fails when last_update < start_time."""
        sample_checkpoint.last_update = sample_checkpoint.start_time - 100

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        assert result is False

    def test_validate_stats_mismatch_accepted(
        self, recovery_manager, sample_checkpoint
    ):
        """Test that stats mismatch is accepted (warning only)."""
        # Set results to exceed processed (should warn but accept)
        sample_checkpoint.successful = 100
        sample_checkpoint.failed = 100
        sample_checkpoint.crashes = 100
        # Total = 300, but processed_files = 50

        result = recovery_manager._validate_checkpoint(sample_checkpoint)

        # Should still pass (warning only)
        assert result is True


class TestListInterruptedCampaigns:
    """Test list_interrupted_campaigns method."""

    def test_list_empty(self, recovery_manager):
        """Test listing when no campaigns."""
        result = recovery_manager.list_interrupted_campaigns()

        assert result == []

    def test_list_interrupted_campaigns(self, recovery_manager, sample_checkpoint):
        """Test listing interrupted campaigns."""
        # Save running checkpoint
        sample_checkpoint.status = CampaignStatus.RUNNING
        recovery_manager.save_checkpoint(sample_checkpoint)

        result = recovery_manager.list_interrupted_campaigns()

        assert len(result) == 1
        assert result[0].campaign_id == sample_checkpoint.campaign_id

    def test_list_excludes_completed(self, recovery_manager, sample_checkpoint):
        """Test that completed campaigns are excluded."""
        sample_checkpoint.status = CampaignStatus.COMPLETED
        recovery_manager.save_checkpoint(sample_checkpoint)

        result = recovery_manager.list_interrupted_campaigns()

        assert len(result) == 0

    def test_list_includes_paused_and_interrupted(self, recovery_manager, temp_dir):
        """Test that paused and interrupted campaigns are included."""
        for i, status in enumerate(
            [CampaignStatus.PAUSED, CampaignStatus.INTERRUPTED, CampaignStatus.FAILED]
        ):
            checkpoint = CampaignCheckpoint(
                campaign_id=f"campaign-{i}",
                status=status,
                start_time=time.time(),
                last_update=time.time(),
                total_files=10,
                processed_files=5,
                successful=4,
                failed=1,
                crashes=0,
                current_file_index=5,
                test_files=["/file.dcm"],
                output_dir="/output",
                crash_dir="/crashes",
                metadata={},
            )
            recovery_manager.save_checkpoint(checkpoint)

        result = recovery_manager.list_interrupted_campaigns()

        # PAUSED and INTERRUPTED should be included, FAILED should not
        assert len(result) == 2


class TestMarkMethods:
    """Test mark_completed, mark_failed, mark_interrupted methods."""

    def test_mark_completed(self, recovery_manager, sample_checkpoint):
        """Test marking campaign as completed."""
        recovery_manager.current_checkpoint = sample_checkpoint

        recovery_manager.mark_completed(sample_checkpoint.campaign_id)

        assert sample_checkpoint.status == CampaignStatus.COMPLETED

    def test_mark_completed_wrong_campaign(self, recovery_manager, sample_checkpoint):
        """Test marking wrong campaign does nothing."""
        recovery_manager.current_checkpoint = sample_checkpoint

        recovery_manager.mark_completed("different-campaign")

        # Status should be unchanged
        assert sample_checkpoint.status == CampaignStatus.RUNNING

    def test_mark_failed(self, recovery_manager, sample_checkpoint):
        """Test marking campaign as failed."""
        recovery_manager.current_checkpoint = sample_checkpoint

        recovery_manager.mark_failed(sample_checkpoint.campaign_id, "Test failure")

        assert sample_checkpoint.status == CampaignStatus.FAILED
        assert sample_checkpoint.metadata["failure_reason"] == "Test failure"

    def test_mark_interrupted(self, recovery_manager, sample_checkpoint):
        """Test marking campaign as interrupted."""
        recovery_manager.current_checkpoint = sample_checkpoint

        recovery_manager.mark_interrupted(sample_checkpoint.campaign_id)

        assert sample_checkpoint.status == CampaignStatus.INTERRUPTED


class TestCleanupCheckpoint:
    """Test cleanup_checkpoint method."""

    def test_cleanup_existing(self, recovery_manager, sample_checkpoint):
        """Test cleaning up existing checkpoint."""
        path = recovery_manager.save_checkpoint(sample_checkpoint)
        assert path.exists()

        recovery_manager.cleanup_checkpoint(sample_checkpoint.campaign_id)

        assert not path.exists()

    def test_cleanup_nonexistent(self, recovery_manager):
        """Test cleaning up non-existent checkpoint."""
        # Should not raise
        recovery_manager.cleanup_checkpoint("nonexistent")


class TestUpdateProgress:
    """Test update_progress method."""

    def test_update_progress(self, recovery_manager, sample_checkpoint):
        """Test updating progress."""
        recovery_manager.current_checkpoint = sample_checkpoint

        recovery_manager.update_progress(
            processed=60, successful=55, failed=3, crashes=2
        )

        assert sample_checkpoint.processed_files == 60
        assert sample_checkpoint.successful == 55
        assert recovery_manager.files_since_checkpoint == 1

    def test_update_progress_triggers_checkpoint(
        self, recovery_manager, sample_checkpoint
    ):
        """Test that progress update triggers checkpoint."""
        recovery_manager.current_checkpoint = sample_checkpoint
        recovery_manager.checkpoint_interval = 5
        recovery_manager.files_since_checkpoint = 0

        # Update 5 times to trigger checkpoint (files_since reaches interval)
        for i in range(5):
            recovery_manager.update_progress(
                processed=50 + i, successful=45 + i, failed=3, crashes=2
            )

        # After 5 updates: files_since = 5 >= interval, checkpoint saved, reset to 0
        # But the save happens at the END of the 5th update, which increments first
        # So after save, it's 0. Let's verify save occurred by checking file exists.
        checkpoint_file = (
            recovery_manager.checkpoint_dir
            / f"{sample_checkpoint.campaign_id}_checkpoint.json"
        )
        assert checkpoint_file.exists()

    def test_update_progress_no_checkpoint(self, recovery_manager):
        """Test update when no current checkpoint."""
        # Should not raise
        recovery_manager.update_progress(
            processed=10, successful=8, failed=2, crashes=0
        )


class TestSignalHandler:
    """Test SignalHandler class."""

    def test_init(self, recovery_manager):
        """Test signal handler initialization."""
        handler = SignalHandler(recovery_manager)

        assert handler.recovery_manager == recovery_manager
        assert handler.interrupted is False

    def test_init_no_recovery_manager(self):
        """Test signal handler without recovery manager."""
        handler = SignalHandler()

        assert handler.recovery_manager is None

    def test_install_uninstall(self):
        """Test installing and uninstalling signal handlers."""
        handler = SignalHandler()

        handler.install()
        handler.uninstall()

        # Should complete without error

    def test_check_interrupted_false(self):
        """Test check_interrupted returns False initially."""
        handler = SignalHandler()

        assert handler.check_interrupted() is False

    def test_check_interrupted_after_signal(self, recovery_manager, sample_checkpoint):
        """Test check_interrupted after signal."""
        recovery_manager.current_checkpoint = sample_checkpoint
        handler = SignalHandler(recovery_manager)

        # Simulate signal
        handler._handle_signal(signal.SIGINT, None)

        assert handler.check_interrupted() is True

    def test_handle_signal_saves_checkpoint(self, recovery_manager, sample_checkpoint):
        """Test that signal handler saves checkpoint."""
        recovery_manager.current_checkpoint = sample_checkpoint
        handler = SignalHandler(recovery_manager)
        handler.install()

        try:
            handler._handle_signal(signal.SIGINT, None)

            # Checkpoint should be marked as interrupted
            assert sample_checkpoint.status == CampaignStatus.INTERRUPTED
        finally:
            handler.uninstall()


class TestWithErrorRecovery:
    """Test with_error_recovery decorator."""

    def test_success_no_retry(self):
        """Test successful function doesn't retry."""
        call_count = 0

        def success_func():
            nonlocal call_count
            call_count += 1
            return "success"

        wrapped = with_error_recovery(success_func, max_retries=3)
        result = wrapped()

        assert result == "success"
        assert call_count == 1

    def test_retry_then_success(self):
        """Test function retries then succeeds."""
        call_count = 0

        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"

        wrapped = with_error_recovery(
            flaky_func, max_retries=3, retry_delay=0.01, backoff_factor=1.0
        )
        result = wrapped()

        assert result == "success"
        assert call_count == 3

    def test_max_retries_exceeded(self):
        """Test error when max retries exceeded."""

        def always_fails():
            raise ValueError("Always fails")

        wrapped = with_error_recovery(
            always_fails, max_retries=2, retry_delay=0.01, backoff_factor=1.0
        )

        with pytest.raises(ValueError, match="Always fails"):
            wrapped()

    def test_backoff_factor(self):
        """Test exponential backoff."""
        call_times = []

        def timing_func():
            call_times.append(time.time())
            if len(call_times) < 3:
                raise ValueError("Error")
            return "success"

        wrapped = with_error_recovery(
            timing_func, max_retries=3, retry_delay=0.05, backoff_factor=2.0
        )
        result = wrapped()

        assert result == "success"
        assert len(call_times) == 3

        # Check delays increased
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]

        # Second delay should be roughly double the first
        assert delay2 > delay1 * 1.5


class TestEdgeCases:
    """Test edge cases."""

    def test_save_checkpoint_handles_write_error(
        self, recovery_manager, sample_checkpoint
    ):
        """Test save_checkpoint handles write errors."""
        recovery_manager.current_checkpoint = sample_checkpoint

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            with pytest.raises(PermissionError):
                recovery_manager.save_checkpoint()

    def test_load_checkpoint_handles_generic_error(self, recovery_manager, temp_dir):
        """Test load_checkpoint handles generic errors."""
        checkpoint_file = recovery_manager.checkpoint_dir / "error_checkpoint.json"
        checkpoint_file.write_text("{}")

        # Patch from_dict to raise unexpected error
        with patch.object(
            CampaignCheckpoint, "from_dict", side_effect=RuntimeError("Unexpected")
        ):
            result = recovery_manager.load_checkpoint("error")

        assert result is None

    def test_validate_checkpoint_exception(self, recovery_manager):
        """Test validation handles exceptions during validation."""
        # Create a checkpoint that will cause exception in validation
        checkpoint = CampaignCheckpoint(
            campaign_id="test",
            status=CampaignStatus.RUNNING,
            start_time=time.time(),
            last_update=time.time(),
            total_files=10,
            processed_files=5,
            successful=4,
            failed=1,
            crashes=0,
            current_file_index=5,
            test_files=["/file.dcm"],
            output_dir="/output",
            crash_dir="/crashes",
            metadata={},
        )

        # Patch the checkpoint's test_files to raise when accessed during len()
        original_test_files = checkpoint.test_files

        class BadList(list):
            def __len__(self):
                raise RuntimeError("Test exception")

        checkpoint.test_files = BadList(original_test_files)

        result = recovery_manager._validate_checkpoint(checkpoint)

        assert result is False
