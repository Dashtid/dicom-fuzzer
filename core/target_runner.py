"""
Target Application Runner

CONCEPT: This module interfaces with target applications to feed them
fuzzed DICOM files and detect crashes, hangs, and other anomalies.

SECURITY TESTING WORKFLOW:
1. Generate fuzzed DICOM files
2. Feed files to target application (viewer, PACS, etc.)
3. Monitor application behavior (crashes, hangs, errors)
4. Collect crash reports and analyze vulnerabilities

This implements file-based fuzzing testing (Option 1).
"""

import logging
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from core.crash_analyzer import CrashAnalyzer

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Result of a single test case execution."""

    SUCCESS = "success"  # Application handled file successfully
    CRASH = "crash"  # Application crashed/terminated abnormally
    HANG = "hang"  # Application hung/timed out
    ERROR = "error"  # Application returned error code
    SKIPPED = "skipped"  # Test was skipped


@dataclass
class ExecutionResult:
    """
    Results from executing target application with a test file.

    CONCEPT: Captures all relevant information about how the target
    application behaved when processing a fuzzed DICOM file.
    """

    test_file: Path
    result: ExecutionStatus
    exit_code: Optional[int]
    execution_time: float
    stdout: str
    stderr: str
    exception: Optional[Exception] = None
    crash_hash: Optional[str] = None

    def __bool__(self) -> bool:
        """Test succeeded if result is SUCCESS."""
        return self.result == ExecutionStatus.SUCCESS


class TargetRunner:
    """
    Runs target application with fuzzed files and detects anomalies.

    CONCEPT: This class acts as the bridge between the fuzzer and the
    target application being tested. It handles:
    - Launching the target application
    - Feeding it test files
    - Monitoring for crashes/hangs
    - Collecting diagnostic information

    SECURITY: Runs target in isolated process to contain potential exploits.
    """

    def __init__(
        self,
        target_executable: str,
        timeout: float = 5.0,
        crash_dir: str = "./crashes",
        collect_stdout: bool = True,
        collect_stderr: bool = True,
    ):
        """
        Initialize target runner.

        Args:
            target_executable: Path to application to test
            timeout: Max seconds to wait for execution
            crash_dir: Directory to save crash reports
            collect_stdout: Whether to capture stdout
            collect_stderr: Whether to capture stderr

        Raises:
            FileNotFoundError: If target executable doesn't exist
        """
        self.target_executable = Path(target_executable)
        if not self.target_executable.exists():
            raise FileNotFoundError(f"Target executable not found: {target_executable}")

        self.timeout = timeout
        self.crash_dir = Path(crash_dir)
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        self.collect_stdout = collect_stdout
        self.collect_stderr = collect_stderr

        # Initialize crash analyzer for crash reporting
        self.crash_analyzer = CrashAnalyzer(crash_dir=str(self.crash_dir))

        logger.info(
            f"Initialized TargetRunner: target={target_executable}, "
            f"timeout={timeout}s"
        )

    def execute_test(self, test_file: Path) -> ExecutionResult:
        """
        Execute target application with a test file.

        Args:
            test_file: Path to DICOM file to test

        Returns:
            ExecutionResult with test outcome

        CONCEPT: This is the core method that:
        1. Launches the target app with the test file
        2. Monitors execution with timeout
        3. Captures output and exit code
        4. Classifies the result (success/crash/hang/error)
        """
        start_time = time.time()

        logger.debug(f"Testing file: {test_file.name}")

        try:
            # Launch target application with test file
            # SECURITY: Use subprocess for isolation
            result = subprocess.run(
                [str(self.target_executable), str(test_file)],
                timeout=self.timeout,
                capture_output=True,
                text=True,
                check=False,  # Don't raise on non-zero exit
            )

            execution_time = time.time() - start_time

            # Classify result based on exit code
            if result.returncode == 0:
                test_result = ExecutionStatus.SUCCESS
            elif result.returncode < 0:
                # Negative return code indicates signal termination (crash)
                test_result = ExecutionStatus.CRASH
            else:
                # Positive non-zero indicates error
                test_result = ExecutionStatus.ERROR

            return ExecutionResult(
                test_file=test_file,
                result=test_result,
                exit_code=result.returncode,
                execution_time=execution_time,
                stdout=result.stdout if self.collect_stdout else "",
                stderr=result.stderr if self.collect_stderr else "",
            )

        except subprocess.TimeoutExpired as e:
            # Application hung - didn't complete within timeout
            execution_time = time.time() - start_time

            # Record hang as potential DoS vulnerability
            crash_report = self.crash_analyzer.analyze_exception(
                Exception(f"Timeout after {self.timeout}s"),
                test_case_path=str(test_file),
            )

            return ExecutionResult(
                test_file=test_file,
                result=ExecutionStatus.HANG,
                exit_code=None,
                execution_time=execution_time,
                stdout=e.stdout.decode() if e.stdout and self.collect_stdout else "",
                stderr=e.stderr.decode() if e.stderr and self.collect_stderr else "",
                exception=e,
                crash_hash=crash_report.crash_hash if crash_report else None,
            )

        except Exception as e:
            # Unexpected error during test execution
            execution_time = time.time() - start_time

            logger.error(f"Unexpected error testing {test_file.name}: {e}")

            return ExecutionResult(
                test_file=test_file,
                result=ExecutionStatus.ERROR,
                exit_code=None,
                execution_time=execution_time,
                stdout="",
                stderr=str(e),
                exception=e,
            )

    def run_campaign(
        self, test_files: List[Path], stop_on_crash: bool = False
    ) -> Dict[ExecutionStatus, List[ExecutionResult]]:
        """
        Run fuzzing campaign against target with multiple test files.

        Args:
            test_files: List of fuzzed DICOM files to test
            stop_on_crash: If True, stop testing on first crash

        Returns:
            Dictionary mapping ExecutionStatus to list of ExecutionResults

        CONCEPT: Batch testing mode - feed all fuzzed files to target
        and collect comprehensive results for analysis.
        """
        results: Dict[ExecutionStatus, List[ExecutionResult]] = {
            result_type: [] for result_type in ExecutionStatus
        }

        total = len(test_files)
        logger.info(f"Starting fuzzing campaign with {total} test files")

        for i, test_file in enumerate(test_files, 1):
            logger.debug(f"[{i}/{total}] Testing {test_file.name}")

            exec_result = self.execute_test(test_file)
            results[exec_result.result].append(exec_result)

            # Log crashes and hangs as they occur
            if exec_result.result in (ExecutionStatus.CRASH, ExecutionStatus.HANG):
                logger.warning(
                    f"[{i}/{total}] {exec_result.result.value.upper()}: "
                    f"{test_file.name} (exit_code={exec_result.exit_code})"
                )

                if stop_on_crash:
                    logger.info("Stopping campaign on first crash (stop_on_crash=True)")
                    break

        # Print summary
        logger.info("Campaign complete. Results:")
        for result_type, exec_results in results.items():
            if exec_results:
                logger.info(f"  {result_type.value}: {len(exec_results)}")

        return results

    def get_summary(self, results: Dict[ExecutionStatus, List[ExecutionResult]]) -> str:
        """
        Generate human-readable summary of campaign results.

        Args:
            results: Campaign results from run_campaign()

        Returns:
            Formatted summary string
        """
        total = sum(len(r) for r in results.values())
        crashes = len(results[ExecutionStatus.CRASH])
        hangs = len(results[ExecutionStatus.HANG])
        errors = len(results[ExecutionStatus.ERROR])
        success = len(results[ExecutionStatus.SUCCESS])

        summary = [
            "=" * 70,
            "  Fuzzing Campaign Summary",
            "=" * 70,
            f"  Total test cases: {total}",
            f"  Successful:       {success}",
            f"  Crashes:          {crashes}",
            f"  Hangs/Timeouts:   {hangs}",
            f"  Errors:           {errors}",
            "=" * 70,
        ]

        if crashes > 0:
            summary.append("\n  CRASHES DETECTED:")
            # Show first 10 crashes
            for exec_result in results[ExecutionStatus.CRASH][:10]:
                crash_line = (
                    f"    - {exec_result.test_file.name} "
                    f"(exit_code={exec_result.exit_code})"
                )
                summary.append(crash_line)
            if len(results[ExecutionStatus.CRASH]) > 10:
                remaining = len(results[ExecutionStatus.CRASH]) - 10
                summary.append(f"    ... and {remaining} more")

        if hangs > 0:
            summary.append("\n  HANGS DETECTED:")
            for exec_result in results[ExecutionStatus.HANG][:10]:
                summary.append(f"    - {exec_result.test_file.name}")
            if len(results[ExecutionStatus.HANG]) > 10:
                summary.append(
                    f"    ... and {len(results[ExecutionStatus.HANG]) - 10} more"
                )

        summary.append("")
        return "\n".join(summary)
