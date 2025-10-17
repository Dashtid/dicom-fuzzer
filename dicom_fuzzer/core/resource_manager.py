"""
Resource Management for DICOM Fuzzer

CONCEPT: Manages system resources (memory, CPU, disk) to prevent resource
exhaustion during fuzzing campaigns. Provides safe execution contexts with
configurable limits.

SECURITY: Prevents denial-of-service through resource exhaustion by enforcing
hard limits on memory, CPU time, and disk usage.
"""

import logging
import os
import platform
import shutil
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# resource module is Unix-only
try:
    import resource as sys_resource

    HAS_RESOURCE_MODULE = True
except ImportError:
    HAS_RESOURCE_MODULE = False
    sys_resource = None

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimits:
    """
    Resource limits for fuzzing operations.

    Attributes:
        max_memory_mb: Maximum memory in megabytes (soft limit)
        max_memory_mb_hard: Hard memory limit in megabytes
        max_cpu_seconds: Maximum CPU time per operation in seconds
        min_disk_space_mb: Minimum free disk space required in megabytes
        max_open_files: Maximum number of open file descriptors
    """

    max_memory_mb: int = 1024  # 1GB soft limit
    max_memory_mb_hard: int = 2048  # 2GB hard limit
    max_cpu_seconds: int = 30  # 30 seconds per operation
    min_disk_space_mb: int = 1024  # Require 1GB free space
    max_open_files: int = 1000  # Max file descriptors


@dataclass
class ResourceUsage:
    """
    Current resource usage snapshot.

    Attributes:
        memory_mb: Current memory usage in megabytes
        cpu_seconds: CPU time used in seconds
        disk_free_mb: Free disk space in megabytes
        open_files: Number of open file descriptors
        timestamp: Time of measurement
    """

    memory_mb: float
    cpu_seconds: float
    disk_free_mb: float
    open_files: int
    timestamp: float


class ResourceExhaustedError(Exception):
    """Raised when resource limits are exceeded."""

    pass


class ResourceManager:
    """
    Manages and enforces resource limits during fuzzing operations.

    CONCEPT: Provides context managers and utilities to:
    1. Set resource limits before operations
    2. Monitor resource usage during execution
    3. Prevent resource exhaustion
    4. Provide graceful degradation

    PLATFORM SUPPORT:
    - Linux/Unix: Full support via resource module
    - Windows: Limited support (disk checks only, no RLIMIT support)
    """

    def __init__(self, limits: Optional[ResourceLimits] = None):
        """
        Initialize resource manager.

        Args:
            limits: Resource limits to enforce (uses defaults if None)
        """
        self.limits = limits or ResourceLimits()
        self.is_windows = platform.system() == "Windows"

        if self.is_windows:
            logger.warning(
                "Running on Windows - resource limits (memory/CPU) not supported. "
                "Only disk space checks will be enforced."
            )

        logger.info(
            f"Resource limits: memory={self.limits.max_memory_mb}MB, "
            f"cpu={self.limits.max_cpu_seconds}s, "
            f"disk={self.limits.min_disk_space_mb}MB"
        )

    def check_available_resources(self, output_dir: Optional[Path] = None) -> bool:
        """
        Check if sufficient resources are available.

        Args:
            output_dir: Directory to check for disk space (defaults to current dir)

        Returns:
            True if resources are sufficient

        Raises:
            ResourceExhaustedError: If resources are insufficient
        """
        # Check disk space
        check_path = output_dir or Path.cwd()
        disk_free_mb = self._get_disk_space_mb(check_path)

        if disk_free_mb < self.limits.min_disk_space_mb:
            raise ResourceExhaustedError(
                f"Insufficient disk space: {disk_free_mb:.0f}MB free, "
                f"need {self.limits.min_disk_space_mb}MB"
            )

        logger.debug(f"Disk space check passed: {disk_free_mb:.0f}MB available")
        return True

    def get_current_usage(self, output_dir: Optional[Path] = None) -> ResourceUsage:
        """
        Get current resource usage snapshot.

        Args:
            output_dir: Directory to check disk space for

        Returns:
            ResourceUsage snapshot
        """
        check_path = output_dir or Path.cwd()

        # Get memory usage (works on Unix-like systems)
        try:
            if not self.is_windows:
                import psutil

                process = psutil.Process(os.getpid())
                memory_mb = process.memory_info().rss / (1024 * 1024)
            else:
                memory_mb = 0.0  # Not available on Windows without psutil
        except ImportError:
            memory_mb = 0.0

        # Get CPU time (works on Unix-like systems)
        try:
            if not self.is_windows:
                usage = sys_resource.getrusage(sys_resource.RUSAGE_SELF)
                cpu_seconds = usage.ru_utime + usage.ru_stime
            else:
                cpu_seconds = 0.0
        except Exception:
            cpu_seconds = 0.0

        # Get disk space
        disk_free_mb = self._get_disk_space_mb(check_path)

        # Get open file count (Unix only)
        try:
            if not self.is_windows:
                import psutil

                process = psutil.Process(os.getpid())
                open_files = len(process.open_files())
            else:
                open_files = 0
        except ImportError:
            open_files = 0

        return ResourceUsage(
            memory_mb=memory_mb,
            cpu_seconds=cpu_seconds,
            disk_free_mb=disk_free_mb,
            open_files=open_files,
            timestamp=time.time(),
        )

    @contextmanager
    def limited_execution(self):
        """
        Context manager for resource-limited execution.

        Sets resource limits before entering context and restores them on exit.
        Only works on Unix-like systems.

        Example:
            >>> manager = ResourceManager()
            >>> with manager.limited_execution():
            ...     # Code runs with resource limits enforced
            ...     run_fuzzing_campaign()

        Raises:
            ResourceExhaustedError: If pre-flight resource checks fail
        """
        # Pre-flight check
        self.check_available_resources()

        if self.is_windows:
            # Windows doesn't support resource limits via resource module
            logger.debug("Skipping resource limits on Windows")
            yield
            return

        # Save current limits
        saved_limits = {}

        try:
            # Set memory limit (RLIMIT_AS - virtual memory)
            try:
                soft_bytes = self.limits.max_memory_mb * 1024 * 1024
                hard_bytes = self.limits.max_memory_mb_hard * 1024 * 1024

                saved_limits["as"] = sys_resource.getrlimit(sys_resource.RLIMIT_AS)
                sys_resource.setrlimit(
                    sys_resource.RLIMIT_AS, (soft_bytes, hard_bytes)
                )
                logger.debug(
                    f"Set memory limit: soft={self.limits.max_memory_mb}MB, "
                    f"hard={self.limits.max_memory_mb_hard}MB"
                )
            except (ValueError, OSError) as e:
                logger.warning(f"Could not set memory limit: {e}")

            # Set CPU time limit
            try:
                saved_limits["cpu"] = sys_resource.getrlimit(sys_resource.RLIMIT_CPU)
                sys_resource.setrlimit(
                    sys_resource.RLIMIT_CPU,
                    (self.limits.max_cpu_seconds, self.limits.max_cpu_seconds + 5),
                )
                logger.debug(f"Set CPU limit: {self.limits.max_cpu_seconds}s")
            except (ValueError, OSError) as e:
                logger.warning(f"Could not set CPU limit: {e}")

            # Set file descriptor limit
            try:
                saved_limits["nofile"] = sys_resource.getrlimit(
                    sys_resource.RLIMIT_NOFILE
                )
                sys_resource.setrlimit(
                    sys_resource.RLIMIT_NOFILE,
                    (self.limits.max_open_files, self.limits.max_open_files + 100),
                )
                logger.debug(f"Set file descriptor limit: {self.limits.max_open_files}")
            except (ValueError, OSError) as e:
                logger.warning(f"Could not set file descriptor limit: {e}")

            yield

        finally:
            # Restore original limits
            for resource_type, (soft, hard) in saved_limits.items():
                try:
                    if resource_type == "as":
                        sys_resource.setrlimit(sys_resource.RLIMIT_AS, (soft, hard))
                    elif resource_type == "cpu":
                        sys_resource.setrlimit(sys_resource.RLIMIT_CPU, (soft, hard))
                    elif resource_type == "nofile":
                        sys_resource.setrlimit(sys_resource.RLIMIT_NOFILE, (soft, hard))
                except (ValueError, OSError) as e:
                    logger.warning(f"Could not restore {resource_type} limit: {e}")

    def _get_disk_space_mb(self, path: Path) -> float:
        """
        Get free disk space in megabytes for given path.

        Args:
            path: Path to check (file or directory)

        Returns:
            Free disk space in megabytes
        """
        try:
            # Ensure path exists
            if not path.exists():
                path = path.parent

            stat = shutil.disk_usage(str(path))
            return stat.free / (1024 * 1024)
        except Exception as e:
            logger.warning(f"Could not get disk space for {path}: {e}")
            return float("inf")  # Assume infinite if we can't check

    def estimate_required_disk_space(
        self, num_files: int, avg_file_size_mb: float = 1.0
    ) -> float:
        """
        Estimate required disk space for fuzzing campaign.

        Args:
            num_files: Number of files to generate
            avg_file_size_mb: Average file size in megabytes

        Returns:
            Estimated disk space needed in megabytes
        """
        # Add 20% overhead for reports, logs, etc.
        return num_files * avg_file_size_mb * 1.2

    def can_accommodate_campaign(
        self,
        num_files: int,
        avg_file_size_mb: float,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Check if system has resources for planned fuzzing campaign.

        Args:
            num_files: Number of files to generate
            avg_file_size_mb: Average file size in megabytes
            output_dir: Output directory for campaign

        Returns:
            True if campaign can proceed

        Raises:
            ResourceExhaustedError: If resources are insufficient
        """
        required_mb = self.estimate_required_disk_space(num_files, avg_file_size_mb)
        check_path = output_dir or Path.cwd()
        available_mb = self._get_disk_space_mb(check_path)

        if available_mb < required_mb:
            raise ResourceExhaustedError(
                f"Insufficient disk space for campaign: "
                f"{available_mb:.0f}MB available, {required_mb:.0f}MB required"
            )

        logger.info(
            f"Campaign resource check passed: {required_mb:.0f}MB required, "
            f"{available_mb:.0f}MB available"
        )
        return True


# Convenience function for simple resource-limited execution
@contextmanager
def resource_limited(
    max_memory_mb: int = 1024,
    max_cpu_seconds: int = 30,
    min_disk_space_mb: int = 1024,
):
    """
    Convenience context manager for resource-limited execution.

    Args:
        max_memory_mb: Maximum memory in megabytes
        max_cpu_seconds: Maximum CPU time in seconds
        min_disk_space_mb: Minimum free disk space in megabytes

    Example:
        >>> with resource_limited(max_memory_mb=512, max_cpu_seconds=10):
        ...     # Code runs with resource limits
        ...     run_expensive_operation()
    """
    limits = ResourceLimits(
        max_memory_mb=max_memory_mb,
        max_cpu_seconds=max_cpu_seconds,
        min_disk_space_mb=min_disk_space_mb,
    )
    manager = ResourceManager(limits)

    with manager.limited_execution():
        yield manager
