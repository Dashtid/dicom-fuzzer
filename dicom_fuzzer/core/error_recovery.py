"""
Error Recovery and Campaign Resumption

CONCEPT: Provides robust error recovery, checkpoint/resume functionality,
and graceful shutdown handling for long-running fuzzing campaigns.

STABILITY FEATURES:
- Checkpoint state periodically during campaigns
- Resume interrupted campaigns from last checkpoint
- Handle signals (SIGINT/SIGTERM) gracefully
- Automatic cleanup on failure
- Progress persistence across restarts
"""

import json
import logging
import signal
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CampaignStatus(Enum):
    """Status of a fuzzing campaign."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass
class CampaignCheckpoint:
    """
    Checkpoint state for resumable fuzzing campaigns.

    CONCEPT: Captures enough state to resume a campaign after interruption
    or failure without losing progress.
    """

    campaign_id: str
    status: CampaignStatus
    start_time: float
    last_update: float
    total_files: int
    processed_files: int
    successful: int
    failed: int
    crashes: int
    current_file_index: int
    test_files: List[str]  # File paths as strings
    output_dir: str
    crash_dir: str
    metadata: Dict[str, Any]  # Additional campaign-specific data

    def to_dict(self) -> Dict[str, Any]:
        """Convert checkpoint to dictionary for serialization."""
        data = asdict(self)
        data["status"] = self.status.value  # Convert enum to string
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CampaignCheckpoint":
        """Create checkpoint from dictionary."""
        # Convert status string to enum
        data["status"] = CampaignStatus(data["status"])
        return cls(**data)


class CampaignRecovery:
    """
    Manages checkpoint/resume functionality for fuzzing campaigns.

    CONCEPT: Enables long-running campaigns to survive interruptions by:
    1. Periodically saving progress to disk
    2. Detecting interrupted campaigns on startup
    3. Resuming from last checkpoint
    4. Cleaning up temporary state
    """

    def __init__(
        self,
        checkpoint_dir: str = "./checkpoints",
        checkpoint_interval: int = 100,  # Files between checkpoints
        enable_auto_resume: bool = True,
    ):
        """
        Initialize campaign recovery manager.

        Args:
            checkpoint_dir: Directory to store checkpoint files
            checkpoint_interval: Number of files processed between checkpoints
            enable_auto_resume: Automatically resume interrupted campaigns
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_interval = checkpoint_interval
        self.enable_auto_resume = enable_auto_resume

        self.current_checkpoint: Optional[CampaignCheckpoint] = None
        self.files_since_checkpoint = 0

        logger.info(
            f"CampaignRecovery initialized: dir={checkpoint_dir}, "
            f"interval={checkpoint_interval} files"
        )

    def create_checkpoint(
        self,
        campaign_id: str,
        total_files: int,
        processed_files: int,
        successful: int,
        failed: int,
        crashes: int,
        current_file_index: int,
        test_files: List[Path],
        output_dir: str,
        crash_dir: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CampaignCheckpoint:
        """
        Create a new campaign checkpoint.

        Args:
            campaign_id: Unique identifier for this campaign
            total_files: Total number of files in campaign
            processed_files: Number of files processed so far
            successful: Number of successful test cases
            failed: Number of failed test cases
            crashes: Number of crashes detected
            current_file_index: Index of current file being processed
            test_files: List of all test files
            output_dir: Output directory for campaign
            crash_dir: Crash report directory
            metadata: Additional campaign-specific data

        Returns:
            CampaignCheckpoint object
        """
        checkpoint = CampaignCheckpoint(
            campaign_id=campaign_id,
            status=CampaignStatus.RUNNING,
            start_time=time.time()
            if not self.current_checkpoint
            else self.current_checkpoint.start_time,
            last_update=time.time(),
            total_files=total_files,
            processed_files=processed_files,
            successful=successful,
            failed=failed,
            crashes=crashes,
            current_file_index=current_file_index,
            test_files=[str(f) for f in test_files],
            output_dir=output_dir,
            crash_dir=crash_dir,
            metadata=metadata or {},
        )

        self.current_checkpoint = checkpoint
        self.files_since_checkpoint = 0

        return checkpoint

    def should_checkpoint(self, force: bool = False) -> bool:
        """
        Check if checkpoint should be saved now.

        Args:
            force: Force checkpoint regardless of interval

        Returns:
            True if checkpoint should be saved
        """
        if force:
            return True

        return self.files_since_checkpoint >= self.checkpoint_interval

    def save_checkpoint(self, checkpoint: Optional[CampaignCheckpoint] = None) -> Path:
        """
        Save checkpoint to disk.

        Args:
            checkpoint: Checkpoint to save (uses current if None)

        Returns:
            Path to saved checkpoint file

        Raises:
            ValueError: If no checkpoint to save
        """
        if checkpoint is None:
            checkpoint = self.current_checkpoint

        if checkpoint is None:
            raise ValueError("No checkpoint to save")

        # Generate checkpoint filename
        checkpoint_file = (
            self.checkpoint_dir / f"{checkpoint.campaign_id}_checkpoint.json"
        )

        # Save as JSON for human readability
        try:
            with open(checkpoint_file, "w") as f:
                json.dump(checkpoint.to_dict(), f, indent=2)

            logger.info(
                f"Checkpoint saved: {checkpoint_file} "
                f"({checkpoint.processed_files}/{checkpoint.total_files} files)"
            )

            return checkpoint_file

        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            raise

    def load_checkpoint(self, campaign_id: str) -> Optional[CampaignCheckpoint]:
        """
        Load checkpoint from disk.

        Args:
            campaign_id: Campaign identifier

        Returns:
            CampaignCheckpoint if found, None otherwise
        """
        checkpoint_file = self.checkpoint_dir / f"{campaign_id}_checkpoint.json"

        if not checkpoint_file.exists():
            logger.debug(f"No checkpoint found for campaign: {campaign_id}")
            return None

        try:
            with open(checkpoint_file, "r") as f:
                data = json.load(f)

            checkpoint = CampaignCheckpoint.from_dict(data)
            logger.info(
                f"Checkpoint loaded: {checkpoint_file} "
                f"({checkpoint.processed_files}/{checkpoint.total_files} files)"
            )

            self.current_checkpoint = checkpoint
            return checkpoint

        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None

    def list_interrupted_campaigns(self) -> List[CampaignCheckpoint]:
        """
        Find all interrupted campaigns that can be resumed.

        Returns:
            List of interrupted CampaignCheckpoint objects
        """
        interrupted = []

        for checkpoint_file in self.checkpoint_dir.glob("*_checkpoint.json"):
            try:
                with open(checkpoint_file, "r") as f:
                    data = json.load(f)

                checkpoint = CampaignCheckpoint.from_dict(data)

                # Check if campaign was interrupted
                if checkpoint.status in [
                    CampaignStatus.RUNNING,
                    CampaignStatus.PAUSED,
                    CampaignStatus.INTERRUPTED,
                ]:
                    interrupted.append(checkpoint)

            except Exception as e:
                logger.warning(f"Failed to load checkpoint {checkpoint_file}: {e}")

        return interrupted

    def mark_completed(self, campaign_id: str):
        """
        Mark campaign as completed and clean up checkpoint.

        Args:
            campaign_id: Campaign identifier
        """
        if (
            self.current_checkpoint
            and self.current_checkpoint.campaign_id == campaign_id
        ):
            self.current_checkpoint.status = CampaignStatus.COMPLETED
            self.current_checkpoint.last_update = time.time()
            self.save_checkpoint()

        # Optional: Remove completed checkpoint after a delay
        # (keep it for audit trail in production)

        logger.info(f"Campaign marked as completed: {campaign_id}")

    def mark_failed(self, campaign_id: str, reason: str):
        """
        Mark campaign as failed.

        Args:
            campaign_id: Campaign identifier
            reason: Reason for failure
        """
        if (
            self.current_checkpoint
            and self.current_checkpoint.campaign_id == campaign_id
        ):
            self.current_checkpoint.status = CampaignStatus.FAILED
            self.current_checkpoint.last_update = time.time()
            self.current_checkpoint.metadata["failure_reason"] = reason
            self.save_checkpoint()

        logger.error(f"Campaign marked as failed: {campaign_id} - {reason}")

    def mark_interrupted(self, campaign_id: str):
        """
        Mark campaign as interrupted (for graceful shutdown).

        Args:
            campaign_id: Campaign identifier
        """
        if (
            self.current_checkpoint
            and self.current_checkpoint.campaign_id == campaign_id
        ):
            self.current_checkpoint.status = CampaignStatus.INTERRUPTED
            self.current_checkpoint.last_update = time.time()
            self.save_checkpoint()

        logger.warning(f"Campaign marked as interrupted: {campaign_id}")

    def cleanup_checkpoint(self, campaign_id: str):
        """
        Remove checkpoint file for completed/failed campaign.

        Args:
            campaign_id: Campaign identifier
        """
        checkpoint_file = self.checkpoint_dir / f"{campaign_id}_checkpoint.json"

        if checkpoint_file.exists():
            try:
                checkpoint_file.unlink()
                logger.info(f"Checkpoint cleaned up: {checkpoint_file}")
            except Exception as e:
                logger.warning(f"Failed to cleanup checkpoint: {e}")

    def update_progress(
        self, processed: int, successful: int, failed: int, crashes: int
    ):
        """
        Update progress counters and trigger checkpoint if needed.

        Args:
            processed: Number of files processed
            successful: Number of successful tests
            failed: Number of failed tests
            crashes: Number of crashes
        """
        if self.current_checkpoint:
            self.current_checkpoint.processed_files = processed
            self.current_checkpoint.successful = successful
            self.current_checkpoint.failed = failed
            self.current_checkpoint.crashes = crashes
            self.current_checkpoint.last_update = time.time()

            self.files_since_checkpoint += 1

            # Auto-save if interval reached
            if self.should_checkpoint():
                self.save_checkpoint()


class SignalHandler:
    """
    Handles graceful shutdown on SIGINT/SIGTERM.

    CONCEPT: Intercepts interrupt signals to allow campaign to save state
    before exiting, enabling resume later.
    """

    def __init__(self, recovery_manager: Optional[CampaignRecovery] = None):
        """
        Initialize signal handler.

        Args:
            recovery_manager: CampaignRecovery instance to save state on interrupt
        """
        self.recovery_manager = recovery_manager
        self.interrupted = False
        self.original_sigint = None
        self.original_sigterm = None

        logger.debug("SignalHandler initialized")

    def install(self):
        """Install signal handlers."""
        self.original_sigint = signal.signal(signal.SIGINT, self._handle_signal)

        # SIGTERM not available on Windows
        if hasattr(signal, "SIGTERM"):
            self.original_sigterm = signal.signal(signal.SIGTERM, self._handle_signal)

        logger.info("Signal handlers installed (SIGINT/SIGTERM)")

    def uninstall(self):
        """Restore original signal handlers."""
        if self.original_sigint:
            signal.signal(signal.SIGINT, self.original_sigint)

        if self.original_sigterm and hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.original_sigterm)

        logger.debug("Signal handlers uninstalled")

    def _handle_signal(self, signum, frame):
        """
        Handle interrupt signal.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        signal_name = signal.Signals(signum).name
        logger.warning(f"Received {signal_name} - initiating graceful shutdown")

        self.interrupted = True

        # Save checkpoint if recovery manager available
        if self.recovery_manager and self.recovery_manager.current_checkpoint:
            campaign_id = self.recovery_manager.current_checkpoint.campaign_id
            logger.info(f"Saving checkpoint for campaign: {campaign_id}")
            self.recovery_manager.mark_interrupted(campaign_id)

        # Allow one more interrupt to force exit
        if self.original_sigint:
            signal.signal(signal.SIGINT, self.original_sigint)

        logger.info("Checkpoint saved. Press Ctrl+C again to force exit.")

    def check_interrupted(self) -> bool:
        """
        Check if interrupt signal was received.

        Returns:
            True if interrupted
        """
        return self.interrupted


# Convenience function for handling errors with recovery
def with_error_recovery(
    func,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    backoff_factor: float = 2.0,
):
    """
    Decorator for adding error recovery with exponential backoff.

    Args:
        func: Function to wrap
        max_retries: Maximum number of retries
        retry_delay: Initial delay between retries (seconds)
        backoff_factor: Multiplier for delay on each retry

    Returns:
        Wrapped function with error recovery
    """

    def wrapper(*args, **kwargs):
        delay = retry_delay
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    logger.warning(
                        f"Error in {func.__name__} (attempt {attempt + 1}/{max_retries}): {e}"
                    )
                    logger.info(f"Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    delay *= backoff_factor
                else:
                    logger.error(
                        f"Failed after {max_retries} retries in {func.__name__}: {e}"
                    )
                    raise last_exception

    return wrapper
