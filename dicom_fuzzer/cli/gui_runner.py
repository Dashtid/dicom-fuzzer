"""GUI Target Runner for DICOM Fuzzer.

This module provides a specialized runner for GUI applications that don't exit
after processing files, such as DICOM viewers (Hermes Affinity, MicroDicom, etc.).
"""

import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from dicom_fuzzer.core.target_runner import ExecutionStatus

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger(__name__)


@dataclass
class GUIExecutionResult:
    """Result from executing a GUI application with a test file.

    For GUI applications that don't exit naturally, we track:
    - Whether it crashed before timeout (actual crash)
    - Memory usage during execution
    - Whether it was killed due to timeout (expected for GUI apps)
    """

    test_file: Path
    status: ExecutionStatus
    exit_code: int | None
    execution_time: float
    peak_memory_mb: float
    crashed: bool  # True only if app crashed BEFORE timeout
    timed_out: bool  # True if we killed it after timeout (normal for GUI)
    stdout: str = ""
    stderr: str = ""

    def __bool__(self) -> bool:
        """Test succeeded if app didn't crash (timeout is OK for GUI apps)."""
        return not self.crashed


class GUITargetRunner:
    """Runner for GUI applications that don't exit after processing files.

    Unlike TargetRunner which expects apps to exit with a return code,
    GUITargetRunner:
    - Launches the app with a test file
    - Monitors memory usage
    - Kills the app after timeout
    - Reports SUCCESS if app didn't crash before timeout
    - Reports CRASH only if app crashed before timeout

    This is appropriate for DICOM viewers like Hermes Affinity, MicroDicom,
    RadiAnt, etc. that open a window and wait for user interaction.
    """

    def __init__(
        self,
        target_executable: str,
        timeout: float = 10.0,
        crash_dir: str = "./artifacts/crashes",
        memory_limit_mb: int | None = None,
        startup_delay: float = 0.0,
    ):
        """Initialize GUI target runner.

        Args:
            target_executable: Path to GUI application
            timeout: Seconds to wait before killing the app
            crash_dir: Directory to save crash reports
            memory_limit_mb: Optional memory limit (kills if exceeded)
            startup_delay: Seconds to wait after launch before monitoring starts

        Raises:
            FileNotFoundError: If target executable doesn't exist
            ImportError: If psutil is not installed

        """
        if not HAS_PSUTIL:
            raise ImportError(
                "GUI mode requires psutil. Install with: pip install psutil"
            )

        self.target_executable = Path(target_executable)
        if not self.target_executable.exists():
            raise FileNotFoundError(f"Target executable not found: {target_executable}")

        self.timeout = timeout
        self.crash_dir = Path(crash_dir)
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        self.memory_limit_mb = memory_limit_mb
        self.startup_delay = startup_delay

        # Statistics
        self.total_tests = 0
        self.crashes = 0
        self.timeouts = 0  # Normal for GUI apps
        self.memory_exceeded = 0

        logger.info(
            f"GUITargetRunner initialized: target={target_executable}, "
            f"timeout={timeout}s, memory_limit={memory_limit_mb}MB, "
            f"startup_delay={startup_delay}s"
        )

    def execute_test(self, test_file: Path | str) -> GUIExecutionResult:
        """Execute GUI application with a test file.

        Args:
            test_file: Path to DICOM file to test

        Returns:
            GUIExecutionResult with execution details

        """
        test_file_path = Path(test_file) if isinstance(test_file, str) else test_file
        logger.debug(f"Testing file: {test_file_path.name}")

        self.total_tests += 1
        start_time = time.time()
        peak_memory = 0.0
        crashed = False
        timed_out = False
        exit_code = None
        stdout_data = ""
        stderr_data = ""

        process = None
        try:
            # Launch GUI application with test file
            process = subprocess.Popen(
                [str(self.target_executable), str(test_file_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if sys.platform == "win32"
                    else 0
                ),
            )

            # Wait for startup delay if specified
            if self.startup_delay > 0:
                logger.debug(f"Waiting {self.startup_delay}s for app to start...")
                time.sleep(self.startup_delay)
                start_time = time.time()

            # Monitor process until timeout or crash
            poll_interval = 0.1
            while True:
                elapsed = time.time() - start_time

                # Check if process exited (crash or normal exit)
                exit_code = process.poll()
                if exit_code is not None:
                    if exit_code != 0:
                        crashed = True
                        self.crashes += 1
                        logger.warning(
                            f"GUI app crashed: {test_file_path.name} "
                            f"(exit_code={exit_code})"
                        )
                    break

                # Check timeout
                if elapsed >= self.timeout:
                    timed_out = True
                    self.timeouts += 1
                    break

                # Monitor memory
                try:
                    ps_process = psutil.Process(process.pid)
                    mem_info = ps_process.memory_info()
                    mem_mb = mem_info.rss / (1024 * 1024)
                    peak_memory = max(peak_memory, mem_mb)

                    # Check memory limit
                    if self.memory_limit_mb and mem_mb > self.memory_limit_mb:
                        logger.warning(
                            f"Memory limit exceeded: {mem_mb:.1f}MB > "
                            f"{self.memory_limit_mb}MB"
                        )
                        self.memory_exceeded += 1
                        crashed = True
                        break
                except psutil.NoSuchProcess:
                    crashed = True
                    self.crashes += 1
                    break

                time.sleep(poll_interval)

        except Exception as e:
            logger.error(f"Error testing {test_file_path.name}: {e}")
            crashed = True
            stderr_data = str(e)

        finally:
            execution_time = time.time() - start_time

            # Kill process if still running
            if process and process.poll() is None:
                self._kill_process_tree(process)

            # Capture any output
            if process:
                try:
                    raw_stdout, raw_stderr = process.communicate(timeout=1)
                    if isinstance(raw_stdout, bytes):
                        stdout_data = raw_stdout.decode("utf-8", errors="replace")
                    if isinstance(raw_stderr, bytes):
                        stderr_data = raw_stderr.decode("utf-8", errors="replace")
                except Exception as comm_err:
                    logger.debug(f"Failed to capture process output: {comm_err}")

        # Determine status
        if crashed:
            status = ExecutionStatus.CRASH
        elif timed_out:
            status = ExecutionStatus.SUCCESS  # Timeout is SUCCESS for GUI apps
        else:
            status = ExecutionStatus.SUCCESS

        return GUIExecutionResult(
            test_file=test_file_path,
            status=status,
            exit_code=exit_code,
            execution_time=execution_time,
            peak_memory_mb=peak_memory,
            crashed=crashed,
            timed_out=timed_out,
            stdout=stdout_data,
            stderr=stderr_data,
        )

    def _kill_process_tree(self, process: subprocess.Popen) -> None:
        """Kill process and all its children."""
        try:
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)

            # Kill children first
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    continue

            # Kill parent
            try:
                parent.kill()
            except psutil.NoSuchProcess:
                logger.debug("Parent process already terminated")

            # Wait for termination
            psutil.wait_procs([parent] + children, timeout=3)

        except psutil.NoSuchProcess:
            logger.debug("Process tree already terminated")
        except Exception as e:
            logger.warning(f"Failed to kill process tree: {e}")

    def run_campaign(
        self, test_files: list[Path], stop_on_crash: bool = False
    ) -> dict[ExecutionStatus, list[GUIExecutionResult]]:
        """Run fuzzing campaign against GUI target.

        Args:
            test_files: List of DICOM files to test
            stop_on_crash: Stop on first crash

        Returns:
            Dictionary mapping status to results

        """
        results: dict[ExecutionStatus, list[GUIExecutionResult]] = {
            status: [] for status in ExecutionStatus
        }

        logger.info(f"Starting GUI fuzzing campaign with {len(test_files)} files")

        for i, test_file in enumerate(test_files, 1):
            logger.debug(f"[{i}/{len(test_files)}] Testing {test_file.name}")

            result = self.execute_test(test_file)
            results[result.status].append(result)

            if result.crashed:
                logger.warning(
                    f"[{i}/{len(test_files)}] CRASH: {test_file.name} "
                    f"(exit={result.exit_code}, mem={result.peak_memory_mb:.1f}MB)"
                )
                if stop_on_crash:
                    logger.info("Stopping on first crash")
                    break

        return results

    def get_summary(
        self, results: dict[ExecutionStatus, list[GUIExecutionResult]]
    ) -> str:
        """Generate summary of campaign results."""
        total = sum(len(r) for r in results.values())
        crashes = len(results[ExecutionStatus.CRASH])
        success = len(results[ExecutionStatus.SUCCESS])

        # Calculate average memory
        all_results = [r for rs in results.values() for r in rs]
        avg_memory = (
            sum(r.peak_memory_mb for r in all_results) / len(all_results)
            if all_results
            else 0
        )
        max_memory = max((r.peak_memory_mb for r in all_results), default=0)

        lines = [
            "=" * 70,
            "  GUI Fuzzing Campaign Summary",
            "=" * 70,
            f"  Total tests:     {total}",
            f"  Successful:      {success} (app ran without crashing)",
            f"  Crashes:         {crashes} (app crashed before timeout)",
            f"  Memory exceeded: {self.memory_exceeded}",
            "",
            f"  Avg memory:      {avg_memory:.1f} MB",
            f"  Peak memory:     {max_memory:.1f} MB",
            "=" * 70,
        ]

        if crashes > 0:
            lines.append("\n  CRASHES DETECTED:")
            crash_results = results[ExecutionStatus.CRASH]
            for result in crash_results[:10]:
                lines.append(
                    f"    - {result.test_file.name} "
                    f"(exit={result.exit_code}, mem={result.peak_memory_mb:.1f}MB)"
                )
            if len(crash_results) > 10:
                lines.append(f"    ... and {len(crash_results) - 10} more")

        lines.append("")
        return "\n".join(lines)
