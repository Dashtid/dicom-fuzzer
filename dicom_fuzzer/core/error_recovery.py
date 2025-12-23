"""Error Recovery and Campaign Resumption

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
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import FrameType
from typing import Any, TypeVar

from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

# Type variable for generic function wrapper
F = TypeVar("F", bound=Callable[..., Any])

logger = get_logger(__name__)


class CampaignStatus(Enum):
    """Status of a fuzzing campaign."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass
class CampaignCheckpoint(SerializableMixin):
    """Checkpoint state for resumable fuzzing campaigns.

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
    test_files: list[str]  # File paths as strings
    output_dir: str
    crash_dir: str
    metadata: dict[str, Any]  # Additional campaign-specific data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CampaignCheckpoint":
        """Create checkpoint from dictionary.

        Args:
            data: Dictionary representation of checkpoint

        Returns:
            CampaignCheckpoint instance

        Raises:
            KeyError: If required fields are missing

        """
        # Validate required fields
        required_fields = [
            "campaign_id",
            "status",
            "start_time",
            "last_update",
            "total_files",
            "processed_files",
            "successful",
            "failed",
            "crashes",
            "current_file_index",
            "test_files",
            "output_dir",
            "crash_dir",
            "metadata",
        ]
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise KeyError(f"Missing required fields in checkpoint data: {missing}")

        # Convert status string to enum
        data["status"] = CampaignStatus(data["status"])
        return cls(**data)


class CampaignRecovery:
    """Manages checkpoint/resume functionality for fuzzing campaigns.

    CONCEPT: Enables long-running campaigns to survive interruptions by:
    1. Periodically saving progress to disk
    2. Detecting interrupted campaigns on startup
    3. Resuming from last checkpoint
    4. Cleaning up temporary state
    """

    def __init__(
        self,
        checkpoint_dir: str = "./artifacts/checkpoints",
        checkpoint_interval: int = 100,  # Files between checkpoints
        enable_auto_resume: bool = True,
    ):
        """Initialize campaign recovery manager.

        Args:
            checkpoint_dir: Directory to store checkpoint files
            checkpoint_interval: Number of files processed between checkpoints
            enable_auto_resume: Automatically resume interrupted campaigns

        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_interval = checkpoint_interval
        self.enable_auto_resume = enable_auto_resume

        self.current_checkpoint: CampaignCheckpoint | None = None
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
        test_files: list[Path],
        output_dir: str,
        crash_dir: str,
        metadata: dict[str, Any] | None = None,
    ) -> CampaignCheckpoint:
        """Create a new campaign checkpoint.

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
        """Check if checkpoint should be saved now.

        Args:
            force: Force checkpoint regardless of interval

        Returns:
            True if checkpoint should be saved

        """
        if force:
            return True

        return self.files_since_checkpoint >= self.checkpoint_interval

    def save_checkpoint(self, checkpoint: CampaignCheckpoint | None = None) -> Path:
        """Save checkpoint to disk atomically to prevent corruption.

        STABILITY: Uses atomic write pattern (write to temp, then rename) to ensure
        checkpoint file is never in corrupted/partial state.

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
        temp_file = checkpoint_file.with_suffix(".tmp")

        # Save as JSON for human readability with atomic write
        try:
            # Write to temporary file first
            with open(temp_file, "w") as f:
                json.dump(checkpoint.to_dict(), f, indent=2)

            # Atomic rename (prevents corruption on crash during write)
            # On Windows, need to remove destination first
            if checkpoint_file.exists():
                checkpoint_file.unlink()
            temp_file.rename(checkpoint_file)

            logger.info(
                f"Checkpoint saved: {checkpoint_file} "
                f"({checkpoint.processed_files}/{checkpoint.total_files} files)"
            )

            return checkpoint_file

        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            # Cleanup temp file if it exists
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception as cleanup_err:
                    logger.debug(
                        f"Failed to cleanup temp file {temp_file}: {cleanup_err}"
                    )
            raise

    def load_checkpoint(self, campaign_id: str) -> CampaignCheckpoint | None:
        """Load and validate checkpoint from disk.

        STABILITY: Validates checkpoint data integrity to detect corruption.

        Args:
            campaign_id: Campaign identifier

        Returns:
            CampaignCheckpoint if found and valid, None otherwise

        """
        checkpoint_file = self.checkpoint_dir / f"{campaign_id}_checkpoint.json"

        if not checkpoint_file.exists():
            logger.debug(f"No checkpoint found for campaign: {campaign_id}")
            return None

        try:
            with open(checkpoint_file) as f:
                data = json.load(f)

            checkpoint = CampaignCheckpoint.from_dict(data)

            # VALIDATION: Verify checkpoint data is consistent
            if not self._validate_checkpoint(checkpoint):
                logger.error(
                    "Checkpoint validation failed - checkpoint may be corrupted"
                )
                return None

            logger.info(
                f"Checkpoint loaded: {checkpoint_file} "
                f"({checkpoint.processed_files}/{checkpoint.total_files} files)"
            )

            self.current_checkpoint = checkpoint
            return checkpoint

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Failed to load checkpoint (corrupted or invalid): {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None

    def _validate_checkpoint(self, checkpoint: CampaignCheckpoint) -> bool:
        """Validate checkpoint data integrity.

        CONCEPT: Detect corrupted or inconsistent checkpoint data before use.

        Args:
            checkpoint: Checkpoint to validate

        Returns:
            True if valid, False otherwise

        """
        try:
            # Check basic sanity of counters
            if checkpoint.processed_files > checkpoint.total_files:
                logger.error(
                    f"Checkpoint corruption: processed ({checkpoint.processed_files}) "
                    f"> total ({checkpoint.total_files})"
                )
                return False

            if checkpoint.processed_files < 0 or checkpoint.total_files < 0:
                logger.error("Checkpoint corruption: negative file counts")
                return False

            # Check that result counts add up
            total_results = (
                checkpoint.successful + checkpoint.failed + checkpoint.crashes
            )
            if total_results > checkpoint.processed_files:
                logger.warning(
                    f"Checkpoint stats mismatch: results ({total_results}) "
                    f"> processed ({checkpoint.processed_files}). Accepting anyway."
                )
                # Don't reject - this might happen with concurrent updates

            # Check current_file_index is reasonable
            if checkpoint.current_file_index < 0:
                logger.error("Checkpoint corruption: negative file index")
                return False

            if checkpoint.current_file_index > len(checkpoint.test_files):
                logger.error(
                    f"Checkpoint corruption: file index ({checkpoint.current_file_index}) "
                    f"> test files ({len(checkpoint.test_files)})"
                )
                return False

            # Check timestamps are reasonable
            if checkpoint.last_update < checkpoint.start_time:
                logger.error("Checkpoint corruption: last_update < start_time")
                return False

            # All checks passed
            return True

        except Exception as e:
            logger.error(f"Exception during checkpoint validation: {e}")
            return False

    def list_interrupted_campaigns(self) -> list[CampaignCheckpoint]:
        """Find all interrupted campaigns that can be resumed.

        Returns:
            List of interrupted CampaignCheckpoint objects

        """
        interrupted = []

        for checkpoint_file in self.checkpoint_dir.glob("*_checkpoint.json"):
            try:
                with open(checkpoint_file) as f:
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

    def mark_completed(self, campaign_id: str) -> None:
        """Mark campaign as completed and clean up checkpoint.

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

    def mark_failed(self, campaign_id: str, reason: str) -> None:
        """Mark campaign as failed.

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

    def mark_interrupted(self, campaign_id: str) -> None:
        """Mark campaign as interrupted (for graceful shutdown).

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

    def cleanup_checkpoint(self, campaign_id: str) -> None:
        """Remove checkpoint file for completed/failed campaign.

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
    ) -> None:
        """Update progress counters and trigger checkpoint if needed.

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
    """Handles graceful shutdown on SIGINT/SIGTERM.

    CONCEPT: Intercepts interrupt signals to allow campaign to save state
    before exiting, enabling resume later.
    """

    def __init__(self, recovery_manager: CampaignRecovery | None = None):
        """Initialize signal handler.

        Args:
            recovery_manager: CampaignRecovery instance to save state on interrupt

        """
        self.recovery_manager = recovery_manager
        self.interrupted = False
        # Signal handlers can be callable, int (SIG_DFL/SIG_IGN), or None
        self.original_sigint: Callable[[int, FrameType | None], Any] | int | None = None
        self.original_sigterm: Callable[[int, FrameType | None], Any] | int | None = (
            None
        )

        logger.debug("SignalHandler initialized")

    def install(self) -> None:
        """Install signal handlers."""
        self.original_sigint = signal.signal(signal.SIGINT, self._handle_signal)

        # SIGTERM not available on Windows
        if hasattr(signal, "SIGTERM"):
            self.original_sigterm = signal.signal(signal.SIGTERM, self._handle_signal)

        logger.info("Signal handlers installed (SIGINT/SIGTERM)")

    def uninstall(self) -> None:
        """Restore original signal handlers."""
        if self.original_sigint is not None:
            signal.signal(signal.SIGINT, self.original_sigint)

        if self.original_sigterm is not None and hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.original_sigterm)

        logger.debug("Signal handlers uninstalled")

    def _handle_signal(self, signum: int, frame: FrameType | None) -> None:
        """Handle interrupt signal.

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
        """Check if interrupt signal was received.

        Returns:
            True if interrupted

        """
        return self.interrupted


# Convenience function for handling errors with recovery
def with_error_recovery(
    func: F,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    backoff_factor: float = 2.0,
) -> F:
    """Decorator for adding error recovery with exponential backoff.

    Args:
        func: Function to wrap
        max_retries: Maximum number of retries
        retry_delay: Initial delay between retries (seconds)
        backoff_factor: Multiplier for delay on each retry

    Returns:
        Wrapped function with error recovery

    """

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        delay = retry_delay
        last_exception: Exception | None = None

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
                    raise last_exception from e
        return None  # Unreachable but satisfies type checker

    return wrapper  # type: ignore[return-value]
