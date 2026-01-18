"""3D DICOM Viewer Launcher and Harness

This module provides ViewerLauncher3D for testing DICOM viewers with complete 3D series
(multi-slice volumes). It extends the existing TargetRunner patterns to support folder-based
loading, crash correlation, and resource monitoring during 3D rendering operations.

KEY FEATURES:
- Folder-based series loading (not individual files)
- Generic viewer support via command-line templates
- Crash correlation (identify which slice triggered crash)
- Memory monitoring during 3D load/render
- Configurable timeouts per series (not per slice)

SECURITY RESEARCH (2025 CVEs):
- CVE-2025-35975: MicroDicom out-of-bounds write (CVSS 8.8)
- CVE-2025-36521: MicroDicom out-of-bounds read (CVSS 8.8)
- CVE-2025-5943: MicroDicom out-of-bounds write (CVSS 8.6)
- CVE-2025-1001: RadiAnt certificate validation (CVSS 5.7)
- CVE-2025-1002: MicroDicom certificate validation (CVSS 5.7)

USAGE:
    launcher = ViewerLauncher3D(viewer_path="/path/to/viewer", timeout=60)
    result = launcher.launch_with_series(series_dir)

    if result.crashed:
        print(f"Crash detected! Likely slice: {result.crash_slice_index}")
"""

import os
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import psutil

from dicom_fuzzer.core.target_runner import ExecutionStatus
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class ViewerType(Enum):
    """Supported DICOM viewer types."""

    GENERIC = "generic"  # Generic viewer with folder argument
    MICRODICOM = "microdicom"  # MicroDicom DICOM Viewer
    RADIANT = "radiant"  # RadiAnt DICOM Viewer
    RUBO = "rubo"  # Rubo DICOM Viewer
    CUSTOM = "custom"  # User-defined custom viewer


@dataclass
class ViewerConfig:
    """Configuration for a DICOM viewer application.

    This dataclass defines how to launch a specific DICOM viewer with a series folder.
    """

    viewer_type: ViewerType
    executable_path: Path
    command_template: str  # Template with {folder_path} placeholder
    timeout_seconds: int = 60  # Default timeout for 3D series load
    memory_limit_mb: int | None = None  # Max memory (None = no limit)
    expected_window_title: str | None = None  # For window detection
    requires_folder_scan: bool = True  # Whether viewer scans folder for DICOM
    additional_args: list[str] = field(default_factory=list)

    def format_command(self, series_folder: Path) -> list[str]:
        """Format the command line for launching the viewer.

        Args:
            series_folder: Path to folder containing DICOM series

        Returns:
            List of command arguments

        """
        # Replace {folder_path} with actual folder
        cmd_str = self.command_template.format(folder_path=str(series_folder))

        # Split into arguments
        args = [str(self.executable_path)] + cmd_str.split()

        # Add any additional arguments
        args.extend(self.additional_args)

        return args


@dataclass
class SeriesTestResult:
    """Result of testing a DICOM viewer with a 3D series.

    Extends ExecutionStatus with series-specific information.
    """

    status: ExecutionStatus
    series_folder: Path
    slice_count: int
    execution_time: float  # Seconds
    peak_memory_mb: float  # Peak memory usage in MB
    crashed: bool = False
    timed_out: bool = False
    exit_code: int | None = None
    crash_slice_index: int | None = None  # Best-effort guess
    stderr: str = ""
    stdout: str = ""
    error_message: str | None = None


class ViewerLauncher3D:
    """Launcher and harness for testing DICOM viewers with 3D series.

    This class extends TargetRunner patterns to support folder-based DICOM series testing.
    It can detect crashes, monitor memory usage, and attempt to correlate crashes to
    specific slices within the series.
    """

    def __init__(
        self,
        config: ViewerConfig,
        monitor_memory: bool = True,
        kill_on_timeout: bool = True,
    ):
        """Initialize ViewerLauncher3D.

        Args:
            config: ViewerConfig for the target viewer
            monitor_memory: Enable memory monitoring during execution
            kill_on_timeout: Kill process if it exceeds timeout

        """
        self.config = config
        self.monitor_memory = monitor_memory
        self.kill_on_timeout = kill_on_timeout

        # Validate executable exists
        if not self.config.executable_path.exists():
            raise FileNotFoundError(
                f"Viewer executable not found: {self.config.executable_path}"
            )

        logger.info(
            f"ViewerLauncher3D initialized for {self.config.viewer_type.value} "
            f"(timeout={self.config.timeout_seconds}s)"
        )

    def launch_with_series(self, series_folder: Path) -> SeriesTestResult:
        """Launch viewer with a DICOM series folder and monitor for crashes.

        Args:
            series_folder: Path to folder containing DICOM series

        Returns:
            SeriesTestResult with execution details

        Raises:
            FileNotFoundError: If series_folder doesn't exist

        """
        if not series_folder.exists():
            raise FileNotFoundError(f"Series folder not found: {series_folder}")

        # Count slices in series
        slice_count = self._count_dicom_files(series_folder)
        logger.info(
            f"Launching viewer with series: {series_folder.name} ({slice_count} slices)"
        )

        # Build command
        cmd_args = self.config.format_command(series_folder)
        logger.debug(f"Command: {' '.join(cmd_args)}")

        # Execute and monitor
        start_time = time.time()
        process = None
        peak_memory = 0.0
        crashed = False
        timed_out = False
        exit_code = None
        stdout_data = ""
        stderr_data = ""

        try:
            # Launch process
            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if os.name == "nt"
                    else 0
                ),
            )

            # Monitor process
            if self.monitor_memory:
                peak_memory = self._monitor_process(
                    process, self.config.timeout_seconds
                )
            else:
                # Just wait for timeout
                try:
                    stdout_bytes, stderr_bytes = process.communicate(
                        timeout=self.config.timeout_seconds
                    )
                    stdout_data = stdout_bytes.decode("utf-8", errors="replace")
                    stderr_data = stderr_bytes.decode("utf-8", errors="replace")
                except subprocess.TimeoutExpired:
                    timed_out = True
                    if self.kill_on_timeout:
                        self._kill_process_tree(process)

            exit_code = process.returncode

            # Determine if crashed (non-zero exit or timeout)
            crashed = exit_code not in [0, None] if not timed_out else False

        except Exception as e:
            logger.error(f"Failed to launch viewer: {e}")
            crashed = True
            stderr_data = str(e)

        finally:
            execution_time = time.time() - start_time

            # Ensure process is terminated
            if process and process.poll() is None:
                self._kill_process_tree(process)

        # Determine status
        if timed_out:
            status = ExecutionStatus.HANG
        elif crashed:
            status = ExecutionStatus.CRASH
        else:
            status = ExecutionStatus.SUCCESS

        # Attempt crash correlation (best-effort)
        crash_slice_index = None
        if crashed or timed_out:
            crash_slice_index = self._correlate_crash_to_slice(
                series_folder, stderr_data, stdout_data
            )

        result = SeriesTestResult(
            status=status,
            series_folder=series_folder,
            slice_count=slice_count,
            execution_time=execution_time,
            peak_memory_mb=peak_memory,
            crashed=crashed,
            timed_out=timed_out,
            exit_code=exit_code,
            crash_slice_index=crash_slice_index,
            stderr=stderr_data,
            stdout=stdout_data,
            error_message=stderr_data if crashed else None,
        )

        logger.info(
            f"Test complete: {status.value} "
            f"(time={execution_time:.2f}s, memory={peak_memory:.1f}MB)"
        )

        return result

    def _count_dicom_files(self, folder: Path) -> int:
        """Count DICOM files in folder.

        Args:
            folder: Folder to scan

        Returns:
            Number of DICOM files found

        """
        extensions = [".dcm", ".DCM", ".dicom", ".DICOM"]
        count = 0

        for ext in extensions:
            count += len(list(folder.glob(f"*{ext}")))

        # Also check for extensionless DICOM files (common in some systems)
        for file_path in folder.iterdir():
            if file_path.is_file() and not file_path.suffix:
                # Simple heuristic: check if file starts with DICOM magic bytes
                try:
                    with open(file_path, "rb") as f:
                        f.seek(128)
                        if f.read(4) == b"DICM":
                            count += 1
                except Exception as read_err:
                    # Skip unreadable files without breaking enumeration
                    logger.debug(f"Could not read {file_path}: {read_err}")

        return count

    def _monitor_process(self, process: subprocess.Popen[bytes], timeout: int) -> float:
        """Monitor process for memory usage and timeout.

        Args:
            process: Process to monitor
            timeout: Timeout in seconds

        Returns:
            Peak memory usage in MB

        """
        peak_memory = 0.0
        start_time = time.time()
        poll_interval = 0.1  # 100ms

        try:
            ps_process = psutil.Process(process.pid)

            while process.poll() is None:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.warning(f"Process exceeded timeout ({timeout}s)")
                    break

                # Monitor memory
                try:
                    mem_info = ps_process.memory_info()
                    mem_mb = mem_info.rss / (1024 * 1024)  # RSS in MB
                    peak_memory = max(peak_memory, mem_mb)

                    # Check memory limit
                    if (
                        self.config.memory_limit_mb
                        and mem_mb > self.config.memory_limit_mb
                    ):
                        logger.warning(
                            f"Process exceeded memory limit ({self.config.memory_limit_mb}MB)"
                        )
                        break
                except psutil.NoSuchProcess:
                    # Process terminated
                    break

                time.sleep(poll_interval)

        except psutil.NoSuchProcess:
            # Process exited during monitoring - expected race condition
            logger.debug("Process exited during memory monitoring")

        return peak_memory

    def _kill_process_tree(self, process: subprocess.Popen[bytes]) -> None:
        """Kill process and all its children.

        Args:
            process: Process to kill

        """
        try:
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)

            # Kill children first
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    # Child already terminated - continue with others
                    continue

            # Kill parent
            try:
                parent.kill()
            except psutil.NoSuchProcess:
                # Parent already terminated - expected in race conditions
                logger.debug("Parent process already terminated")

            # Wait for termination (result discarded - we just need to wait)
            psutil.wait_procs([parent] + children, timeout=3)

            logger.debug(f"Killed process tree (parent PID={process.pid})")

        except psutil.NoSuchProcess:
            # Process already terminated before we could kill it
            logger.debug("Process tree already terminated")
        except Exception as e:
            logger.warning(f"Failed to kill process tree: {e}")

    def _correlate_crash_to_slice(
        self, series_folder: Path, stderr: str, stdout: str
    ) -> int | None:
        """Attempt to correlate crash to specific slice (best-effort).

        This is a heuristic approach that looks for patterns in error output
        that might indicate which slice caused the crash.

        Args:
            series_folder: Folder containing series
            stderr: Standard error output
            stdout: Standard output

        Returns:
            Slice index (0-based) or None if cannot determine

        """
        # Look for patterns like "slice_001.dcm", "001.dcm", "slice 5", etc.
        import re

        combined_output = stderr + "\n" + stdout

        # Pattern 1: "slice_NNN.dcm" or "NNN.dcm"
        pattern1 = r"(?:slice_)?(\d+)\.dcm"
        matches = re.findall(pattern1, combined_output, re.IGNORECASE)
        if matches:
            # Return first match (convert to 0-based index)
            return int(matches[0]) - 1

        # Pattern 2: "slice N" or "image N"
        pattern2 = r"(?:slice|image)\s+(\d+)"
        matches = re.findall(pattern2, combined_output, re.IGNORECASE)
        if matches:
            return int(matches[0]) - 1

        # Pattern 3: "instance N" or "file N"
        pattern3 = r"(?:instance|file)\s+(\d+)"
        matches = re.findall(pattern3, combined_output, re.IGNORECASE)
        if matches:
            return int(matches[0]) - 1

        # Could not determine - return None
        return None


def create_generic_config(
    viewer_path: Path, timeout: int = 60, memory_limit_mb: int | None = None
) -> ViewerConfig:
    """Create a generic viewer configuration.

    This is a helper function for creating ViewerConfig for viewers not explicitly
    supported. The generic configuration assumes the viewer accepts a folder path
    as the first command-line argument.

    Args:
        viewer_path: Path to viewer executable
        timeout: Timeout in seconds (default: 60)
        memory_limit_mb: Memory limit in MB (default: None)

    Returns:
        ViewerConfig configured for generic viewer

    Example:
        config = create_generic_config(Path("C:/MyViewer/viewer.exe"))
        launcher = ViewerLauncher3D(config)

    """
    return ViewerConfig(
        viewer_type=ViewerType.GENERIC,
        executable_path=viewer_path,
        command_template="{folder_path}",  # Just pass folder as argument
        timeout_seconds=timeout,
        memory_limit_mb=memory_limit_mb,
        requires_folder_scan=True,
    )
