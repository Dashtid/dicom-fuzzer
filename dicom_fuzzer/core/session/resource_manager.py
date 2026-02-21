"""Resource Management for DICOM Fuzzer.

Manages system resources (memory, CPU, disk) with configurable limits
to prevent resource exhaustion during fuzzing campaigns.
"""

import os
import shutil
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dicom_fuzzer.core.exceptions import ResourceExhaustedError
from dicom_fuzzer.utils.logger import get_logger

# resource module is Unix-only
IS_WINDOWS = sys.platform == "win32"
HAS_RESOURCE_MODULE = False
sys_resource: Any = None

if not IS_WINDOWS:
    try:
        import resource as sys_resource

        HAS_RESOURCE_MODULE = True
    except ImportError as _import_err:
        # resource module not available (unusual for non-Windows systems)
        del _import_err  # Avoid unused variable warning

logger = get_logger(__name__)

# Re-export for backwards compatibility
__all__ = [
    "ResourceManager",
    "ResourceLimits",
    "ResourceUsage",
    "ResourceExhaustedError",
]


@dataclass
class ResourceLimits:
    """Resource limits for fuzzing operations.

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
    """Current resource usage snapshot.

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


class ResourceManager:
    """Manages and enforces resource limits during fuzzing operations.

    Provides context managers and utilities to set resource limits before
    operations, monitor resource usage during execution, prevent resource
    exhaustion, and provide graceful degradation.

    PLATFORM SUPPORT:
    - Linux/Unix: Full support via resource module
    - Windows: Limited support (disk checks only, no RLIMIT support)
    """

    def __init__(self, limits: ResourceLimits | None = None):
        """Initialize resource manager.

        Args:
            limits: Resource limits to enforce (uses defaults if None)

        """
        self.limits = limits or ResourceLimits()
        self.is_windows = IS_WINDOWS

        if self.is_windows:
            logger.warning(
                "Running on Windows - resource limits (memory/CPU) not supported. "
                "Only disk space checks will be enforced."
            )

        logger.info(
            "Resource limits configured",
            memory_mb=self.limits.max_memory_mb,
            cpu_seconds=self.limits.max_cpu_seconds,
            disk_mb=self.limits.min_disk_space_mb,
        )

    def check_available_resources(self, output_dir: Path | None = None) -> bool:
        """Check if sufficient resources are available.

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

        logger.debug("Disk space check passed", available_mb=f"{disk_free_mb:.0f}")
        return True

    def get_current_usage(self, output_dir: Path | None = None) -> ResourceUsage:
        """Get current resource usage snapshot.

        Args:
            output_dir: Directory to check disk space for

        Returns:
            ResourceUsage snapshot

        """
        check_path = output_dir or Path.cwd()

        # Get memory usage
        try:
            import psutil

            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / (1024 * 1024)
        except ImportError:
            memory_mb = 0.0

        # Get CPU time (works on Unix-like systems)
        try:
            if HAS_RESOURCE_MODULE and sys_resource is not None:
                usage = sys_resource.getrusage(sys_resource.RUSAGE_SELF)
                cpu_seconds = usage.ru_utime + usage.ru_stime
            else:
                cpu_seconds = 0.0
        except Exception:
            cpu_seconds = 0.0

        # Get disk space
        disk_free_mb = self._get_disk_space_mb(check_path)

        # Get open file count
        try:
            import psutil

            process = psutil.Process(os.getpid())
            open_files = len(process.open_files())
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
    def limited_execution(self) -> Generator[None, None, None]:
        """Context manager for resource-limited execution.

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

        if not HAS_RESOURCE_MODULE or sys_resource is None:
            # Windows doesn't support resource limits via resource module
            logger.debug("Skipping resource limits (resource module not available)")
            yield
            return

        # Save current limits
        saved_limits: dict[str, tuple[int, int]] = {}

        try:
            # Set memory limit (RLIMIT_AS - virtual memory)
            try:
                soft_bytes = self.limits.max_memory_mb * 1024 * 1024
                hard_bytes = self.limits.max_memory_mb_hard * 1024 * 1024

                saved_limits["as"] = sys_resource.getrlimit(sys_resource.RLIMIT_AS)
                sys_resource.setrlimit(sys_resource.RLIMIT_AS, (soft_bytes, hard_bytes))
                logger.debug(
                    "Set memory limit",
                    soft_mb=self.limits.max_memory_mb,
                    hard_mb=self.limits.max_memory_mb_hard,
                )
            except (ValueError, OSError) as e:
                logger.warning("Could not set memory limit", error=str(e))

            # Set CPU time limit
            try:
                saved_limits["cpu"] = sys_resource.getrlimit(sys_resource.RLIMIT_CPU)
                sys_resource.setrlimit(
                    sys_resource.RLIMIT_CPU,
                    (self.limits.max_cpu_seconds, self.limits.max_cpu_seconds + 5),
                )
                logger.debug("Set CPU limit", cpu_seconds=self.limits.max_cpu_seconds)
            except (ValueError, OSError) as e:
                logger.warning("Could not set CPU limit", error=str(e))

            # Set file descriptor limit
            try:
                saved_limits["nofile"] = sys_resource.getrlimit(
                    sys_resource.RLIMIT_NOFILE
                )
                sys_resource.setrlimit(
                    sys_resource.RLIMIT_NOFILE,
                    (self.limits.max_open_files, self.limits.max_open_files + 100),
                )
                logger.debug(
                    "Set file descriptor limit",
                    max_open_files=self.limits.max_open_files,
                )
            except (ValueError, OSError) as e:
                logger.warning("Could not set file descriptor limit", error=str(e))

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
                    logger.warning(
                        "Could not restore resource limit",
                        resource_type=resource_type,
                        error=str(e),
                    )

    def _get_disk_space_mb(self, path: Path) -> float:
        """Get free disk space in megabytes for given path.

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
            logger.warning("Could not get disk space", path=str(path), error=str(e))
            return float("inf")  # Assume infinite if we can't check

    def estimate_required_disk_space(
        self, num_files: int, avg_file_size_mb: float = 1.0
    ) -> float:
        """Estimate required disk space for fuzzing campaign.

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
        output_dir: Path | None = None,
    ) -> bool:
        """Check if system has resources for planned fuzzing campaign.

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
            "Campaign resource check passed",
            required_mb=f"{required_mb:.0f}",
            available_mb=f"{available_mb:.0f}",
        )
        return True


# Convenience function for simple resource-limited execution
@contextmanager
def resource_limited(
    max_memory_mb: int = 1024,
    max_cpu_seconds: int = 30,
    min_disk_space_mb: int = 1024,
) -> Generator[ResourceManager, None, None]:
    """Convenience context manager for resource-limited execution.

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
