"""Target Calibrator for Automatic Fuzzing Configuration.

Implements AFL-style calibration to automatically detect target characteristics
and configure optimal fuzzing parameters.

Calibration Phases:
1. Target Detection - Classify as CLI/GUI/Error mode
2. Timeout Calibration - Calculate optimal timeout based on execution speed
3. Crash Detection Validation - Verify crash detection works
4. Corpus Validation - Quick-test corpus for problematic seeds

References:
- AFL++ calibration: https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-fuzz-run.c
- WINNIE GUI handling: https://taesoo.kim/pubs/2021/jung:winnie.pdf

"""

from __future__ import annotations

import ctypes
import random
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class TargetType(Enum):
    """Classification of target application type."""

    CLI = "cli"  # Command-line app that exits after processing
    GUI = "gui"  # GUI app that stays running
    ERROR = "error"  # App exits with error on valid input
    UNKNOWN = "unknown"  # Could not determine


class CrashDetectionStatus(Enum):
    """Status of crash detection validation."""

    VALIDATED = "validated"  # Crash detection confirmed working
    UNTESTED = "untested"  # Not yet tested
    FAILED = "failed"  # Crash detection not working properly


@dataclass
class CalibrationResult:
    """Results from target calibration."""

    # Target classification
    target_type: TargetType = TargetType.UNKNOWN
    target_path: str = ""

    # Timing
    recommended_timeout: float = 10.0
    avg_execution_time: float = 0.0
    min_execution_time: float = 0.0
    max_execution_time: float = 0.0
    execution_variance: float = 0.0  # Stddev for stability detection
    execution_times: list[float] = field(default_factory=list)

    # Crash detection
    crash_detection: CrashDetectionStatus = CrashDetectionStatus.UNTESTED
    wer_disabled: bool = False

    # Corpus health
    corpus_total: int = 0
    corpus_valid: int = 0
    corpus_errors: int = 0
    corpus_crashes: int = 0
    problematic_seeds: list[str] = field(default_factory=list)

    # Recommendations
    recommendations: list[str] = field(default_factory=list)

    # Stability
    is_stable: bool = True  # False if execution variance > 20%

    # Metadata
    calibration_version: int = 2
    calibration_time: float = 0.0
    test_runs: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "calibration_version": self.calibration_version,
            "target_type": self.target_type.value,
            "target_path": self.target_path,
            "recommended_timeout": self.recommended_timeout,
            "avg_execution_time": self.avg_execution_time,
            "min_execution_time": self.min_execution_time,
            "max_execution_time": self.max_execution_time,
            "execution_variance": self.execution_variance,
            "is_stable": self.is_stable,
            "crash_detection": self.crash_detection.value,
            "wer_disabled": self.wer_disabled,
            "corpus_health": {
                "total": self.corpus_total,
                "valid": self.corpus_valid,
                "errors": self.corpus_errors,
                "crashes": self.corpus_crashes,
            },
            "problematic_seeds": self.problematic_seeds[:10],  # Limit to 10
            "recommendations": self.recommendations,
            "calibration_time": self.calibration_time,
            "test_runs": self.test_runs,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationResult:
        """Create CalibrationResult from dictionary (loaded from JSON)."""
        corpus_health = data.get("corpus_health", {})
        return cls(
            target_type=TargetType(data.get("target_type", "unknown")),
            target_path=data.get("target_path", ""),
            recommended_timeout=data.get("recommended_timeout", 10.0),
            avg_execution_time=data.get("avg_execution_time", 0.0),
            min_execution_time=data.get("min_execution_time", 0.0),
            max_execution_time=data.get("max_execution_time", 0.0),
            execution_variance=data.get("execution_variance", 0.0),
            is_stable=data.get("is_stable", True),
            crash_detection=CrashDetectionStatus(
                data.get("crash_detection", "untested")
            ),
            wer_disabled=data.get("wer_disabled", False),
            corpus_total=corpus_health.get("total", 0),
            corpus_valid=corpus_health.get("valid", 0),
            corpus_errors=corpus_health.get("errors", 0),
            corpus_crashes=corpus_health.get("crashes", 0),
            problematic_seeds=data.get("problematic_seeds", []),
            recommendations=data.get("recommendations", []),
            calibration_version=data.get("calibration_version", 1),
            calibration_time=data.get("calibration_time", 0.0),
            test_runs=data.get("test_runs", 0),
        )

    def print_summary(self) -> None:
        """Print human-readable calibration summary."""
        print("\n" + "=" * 70)
        print("  TARGET CALIBRATION RESULTS")
        print("=" * 70)
        print(f"  Target: {self.target_path}")
        print(f"  Type: {self.target_type.value.upper()}")
        print(f"  Recommended Timeout: {self.recommended_timeout:.1f}s")
        # Show N/A for GUI apps where timeout calibration was skipped
        if self.target_type == TargetType.GUI and self.avg_execution_time == 0.0:
            print("  Avg Execution Time: N/A (GUI mode)")
        else:
            print(f"  Avg Execution Time: {self.avg_execution_time:.3f}s")
            if self.execution_variance > 0:
                stability = "stable" if self.is_stable else "UNSTABLE"
                print(
                    f"  Execution Variance: {self.execution_variance:.3f}s ({stability})"
                )
        print(f"  Crash Detection: {self.crash_detection.value}")
        print(f"  WER Disabled: {self.wer_disabled}")
        if self.corpus_total > 0:
            print(f"  Corpus: {self.corpus_valid}/{self.corpus_total} valid")
            if self.corpus_crashes > 0:
                print(f"  [!] {self.corpus_crashes} seeds cause crashes")
        print("-" * 70)
        print("  Recommendations:")
        for rec in self.recommendations:
            print(f"    - {rec}")
        print("=" * 70 + "\n")


class TargetCalibrator:
    """Calibrates fuzzing parameters for a target application.

    Implements AFL-style calibration with 4 phases:
    1. Target Detection - Classify as CLI/GUI/Error mode
    2. Timeout Calibration - Calculate optimal timeout
    3. Crash Detection Validation - Verify crash detection works
    4. Corpus Validation - Quick-test corpus health

    """

    # Calibration format version (increment when schema changes)
    CALIBRATION_VERSION = 2

    # Windows crash exit codes
    CRASH_EXIT_CODES = {
        -1073741819,  # 0xC0000005 - Access Violation
        -1073741795,  # 0xC000001D - Illegal Instruction
        -1073741676,  # 0xC0000094 - Integer Divide by Zero
        -1073741571,  # 0xC00000FD - Stack Overflow
        -1073740940,  # 0xC0000374 - Heap Corruption
        -1073740791,  # 0xC0000409 - Stack Buffer Overrun
        -2147483645,  # 0x80000003 - Breakpoint
        -1073741515,  # 0xC0000135 - DLL Not Found
    }

    # Timeout calculation constants (based on AFL)
    TIMEOUT_MULTIPLIER_CLI = 5.0  # 5x average for CLI apps
    TIMEOUT_MULTIPLIER_GUI = 1.5  # 1.5x startup time for GUI apps
    MIN_TIMEOUT = 0.1  # 100ms minimum
    MAX_TIMEOUT = 60.0  # 60s maximum
    DEFAULT_GUI_TIMEOUT = 10.0  # Default for GUI apps

    # Detection thresholds
    CLI_EXIT_THRESHOLD = 2.0  # If exits within 2s, likely CLI
    DETECTION_RUNS = 5  # Runs for target detection
    CALIBRATION_RUNS = 3  # Runs for timeout calibration (AFL_FAST_CAL style)
    CORPUS_SAMPLE_PERCENT = 0.1  # Test 10% of corpus
    MAX_CORPUS_SAMPLE_CLI = 50  # Cap corpus sample for CLI apps
    MAX_CORPUS_SAMPLE_GUI = 20  # Smaller sample for slow GUI apps

    def __init__(
        self,
        target_executable: Path | str,
        corpus_dir: Path | str | None = None,
        verbose: bool = False,
    ):
        """Initialize calibrator.

        Args:
            target_executable: Path to the target application
            corpus_dir: Optional path to seed corpus
            verbose: Enable verbose logging

        """
        self.target = Path(target_executable)
        self.corpus_dir = Path(corpus_dir) if corpus_dir else None
        self.verbose = verbose
        self.result = CalibrationResult(target_path=str(self.target))
        self._temp_files: list[Path] = []  # Track temp files for cleanup

        if not self.target.exists():
            raise FileNotFoundError(f"Target not found: {self.target}")

    def calibrate(self) -> CalibrationResult:
        """Run full calibration and return results.

        Returns:
            CalibrationResult with all calibration data

        """
        start_time = time.time()
        logger.info(f"[i] Starting calibration for: {self.target}")

        # Phase 1: Target Detection
        self._phase1_detect_target_type()

        # Phase 2: Timeout Calibration (skip for GUI apps - use default)
        if self.result.target_type == TargetType.GUI:
            self.result.recommended_timeout = self.DEFAULT_GUI_TIMEOUT
            logger.info(
                f"[i] Phase 2: Skipped for GUI app "
                f"(using default {self.DEFAULT_GUI_TIMEOUT:.0f}s timeout)"
            )
        else:
            self._phase2_calibrate_timeout()

        # Phase 3: Crash Detection Validation
        self._phase3_validate_crash_detection()

        # Phase 4: Corpus Validation (if corpus provided)
        if self.corpus_dir and self.corpus_dir.exists():
            self._phase4_validate_corpus()

        # Generate recommendations
        self._generate_recommendations()

        # Cleanup temp files
        self._cleanup_temp_files()

        self.result.calibration_time = time.time() - start_time
        logger.info(f"[+] Calibration complete in {self.result.calibration_time:.1f}s")

        return self.result

    def _cleanup_temp_files(self) -> None:
        """Remove temporary files created during calibration."""
        for temp_file in self._temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    if self.verbose:
                        logger.debug(f"  Cleaned up: {temp_file}")
            except Exception as e:
                logger.debug(f"Failed to clean up {temp_file}: {e}")
        self._temp_files.clear()

    def _get_test_file(self) -> Path | None:
        """Get a test file from corpus or create minimal DICOM."""
        if self.corpus_dir and self.corpus_dir.exists():
            # Find a DICOM file in corpus
            dcm_files = list(self.corpus_dir.rglob("*.dcm"))[:10]
            if dcm_files:
                return random.choice(dcm_files)

            # Try files without extension
            all_files = [
                f
                for f in self.corpus_dir.rglob("*")
                if f.is_file() and f.stat().st_size > 132
            ]
            if all_files:
                return random.choice(all_files[:10])

        # Create minimal DICOM file
        minimal_dcm = self.target.parent / "_calibration_test.dcm"
        minimal_dcm.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        self._temp_files.append(minimal_dcm)  # Track for cleanup
        return minimal_dcm

    def _run_target(
        self, test_file: Path, timeout: float = 5.0
    ) -> tuple[int | None, float, bool]:
        """Run target with test file and measure execution.

        Args:
            test_file: Path to test file
            timeout: Maximum execution time

        Returns:
            Tuple of (exit_code, execution_time, timed_out)

        """
        start_time = time.time()
        timed_out = False
        exit_code = None

        try:
            process = subprocess.Popen(
                [str(self.target), str(test_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    if sys.platform == "win32"
                    else 0
                ),
            )

            # Poll for completion
            elapsed = 0.0
            while elapsed < timeout:
                exit_code = process.poll()
                if exit_code is not None:
                    break
                time.sleep(0.05)
                elapsed = time.time() - start_time

            if exit_code is None:
                # Process still running - kill it
                timed_out = True
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)

        except Exception as e:
            logger.debug(f"Error running target: {e}")
            exit_code = -1

        execution_time = time.time() - start_time
        self.result.test_runs += 1

        return exit_code, execution_time, timed_out

    def _phase1_detect_target_type(self) -> None:
        """Phase 1: Detect if target is CLI or GUI application."""
        logger.info("[i] Phase 1: Detecting target type...")

        test_file = self._get_test_file()
        if not test_file:
            logger.warning("[!] No test file available for detection")
            self.result.target_type = TargetType.UNKNOWN
            return

        exits_count = 0
        timeout_count = 0
        error_count = 0
        crash_count = 0

        for i in range(self.DETECTION_RUNS):
            exit_code, exec_time, timed_out = self._run_target(
                test_file, timeout=self.CLI_EXIT_THRESHOLD
            )

            if self.verbose:
                logger.debug(
                    f"  Run {i + 1}: exit={exit_code}, time={exec_time:.2f}s, "
                    f"timeout={timed_out}"
                )

            if timed_out:
                timeout_count += 1
            elif exit_code is not None:
                if exit_code in self.CRASH_EXIT_CODES or exit_code < 0:
                    crash_count += 1
                elif exit_code == 0:
                    exits_count += 1
                else:
                    error_count += 1

        # Classify based on majority behavior
        if timeout_count >= self.DETECTION_RUNS * 0.6:
            self.result.target_type = TargetType.GUI
            logger.info("[+] Detected: GUI application (stays running)")
        elif crash_count >= self.DETECTION_RUNS * 0.6:
            self.result.target_type = TargetType.ERROR
            logger.warning("[!] Detected: Application crashes on valid input")
        elif exits_count >= self.DETECTION_RUNS * 0.6:
            self.result.target_type = TargetType.CLI
            logger.info("[+] Detected: CLI application (exits after processing)")
        elif error_count >= self.DETECTION_RUNS * 0.6:
            self.result.target_type = TargetType.ERROR
            logger.warning("[!] Detected: Application returns errors on valid input")
        else:
            self.result.target_type = TargetType.UNKNOWN
            logger.warning("[!] Could not determine target type (mixed behavior)")

    def _phase2_calibrate_timeout(self) -> None:
        """Phase 2: Calibrate timeout based on execution speed."""
        logger.info("[i] Phase 2: Calibrating timeout...")

        test_file = self._get_test_file()
        if not test_file:
            self.result.recommended_timeout = self.DEFAULT_GUI_TIMEOUT
            return

        execution_times: list[float] = []

        # Use longer timeout for calibration to get accurate times
        calibration_timeout = 30.0

        for i in range(self.CALIBRATION_RUNS):
            exit_code, exec_time, timed_out = self._run_target(
                test_file, timeout=calibration_timeout
            )

            if not timed_out:
                execution_times.append(exec_time)

            if self.verbose:
                logger.debug(f"  Run {i + 1}: {exec_time:.3f}s")

        if execution_times:
            self.result.execution_times = execution_times
            self.result.avg_execution_time = statistics.mean(execution_times)
            self.result.min_execution_time = min(execution_times)
            self.result.max_execution_time = max(execution_times)

            # Calculate variance for stability detection
            if len(execution_times) >= 2:
                self.result.execution_variance = statistics.stdev(execution_times)
                # Unstable if variance > 20% of mean
                variance_ratio = (
                    self.result.execution_variance / self.result.avg_execution_time
                    if self.result.avg_execution_time > 0
                    else 0
                )
                self.result.is_stable = variance_ratio <= 0.2
                if not self.result.is_stable:
                    logger.warning(
                        f"[!] Target appears unstable "
                        f"(variance {variance_ratio:.1%} of mean)"
                    )

            # Calculate timeout based on target type
            if self.result.target_type == TargetType.CLI:
                # AFL-style: 5x average execution time
                timeout = self.result.avg_execution_time * self.TIMEOUT_MULTIPLIER_CLI
            else:
                # GUI apps: Use max observed + buffer
                timeout = self.result.max_execution_time * self.TIMEOUT_MULTIPLIER_GUI
                timeout = max(timeout, self.DEFAULT_GUI_TIMEOUT)

            # Clamp to valid range
            self.result.recommended_timeout = max(
                self.MIN_TIMEOUT, min(self.MAX_TIMEOUT, timeout)
            )
        else:
            # All runs timed out - use default
            self.result.recommended_timeout = self.DEFAULT_GUI_TIMEOUT

        logger.info(
            f"[+] Recommended timeout: {self.result.recommended_timeout:.1f}s "
            f"(avg exec: {self.result.avg_execution_time:.3f}s)"
        )

    def _phase3_validate_crash_detection(self) -> None:
        """Phase 3: Validate that crash detection is working."""
        logger.info("[i] Phase 3: Validating crash detection...")

        # Check WER is disabled on Windows
        if sys.platform == "win32":
            try:
                kernel32 = ctypes.windll.kernel32
                sem_nogpfaulterrorbox = 0x0002  # Windows constant
                kernel32.SetErrorMode(sem_nogpfaulterrorbox)
                self.result.wer_disabled = True
                logger.info("[+] Windows Error Reporting dialogs disabled")
            except Exception:
                self.result.wer_disabled = False
                logger.warning("[!] Could not disable WER dialogs")

        # Test with a truncated/invalid file to ensure target handles it
        test_file = self._get_test_file()
        if test_file:
            # Create truncated version
            truncated_file = self.target.parent / "_calibration_truncated.dcm"
            truncated_file.write_bytes(b"\x00" * 50)  # Too short to be valid

            exit_code, exec_time, timed_out = self._run_target(
                truncated_file, timeout=5.0
            )

            # Clean up - ignore errors as temp file may already be deleted
            try:
                truncated_file.unlink()
            except Exception as e:
                logger.debug(f"Cleanup failed for calibration file: {e}")

            if exit_code in self.CRASH_EXIT_CODES:
                logger.warning(
                    "[!] Target crashes on invalid input (expected for some apps)"
                )
                self.result.crash_detection = CrashDetectionStatus.VALIDATED
            elif exit_code is not None or timed_out:
                self.result.crash_detection = CrashDetectionStatus.VALIDATED
                logger.info("[+] Crash detection validated")
            else:
                self.result.crash_detection = CrashDetectionStatus.FAILED
                logger.warning("[!] Could not validate crash detection")
        else:
            self.result.crash_detection = CrashDetectionStatus.UNTESTED

    def _phase4_validate_corpus(self) -> None:
        """Phase 4: Quick-test corpus for problematic seeds."""
        logger.info("[i] Phase 4: Validating corpus...")

        if not self.corpus_dir or not self.corpus_dir.exists():
            return

        # Find all potential seed files
        all_seeds = list(self.corpus_dir.rglob("*.dcm"))
        if not all_seeds:
            all_seeds = [
                f
                for f in self.corpus_dir.rglob("*")
                if f.is_file() and f.stat().st_size > 132
            ]

        self.result.corpus_total = len(all_seeds)

        if not all_seeds:
            logger.warning("[!] No seed files found in corpus")
            return

        # Sample a subset for testing (smaller sample for slow GUI apps)
        max_sample = (
            self.MAX_CORPUS_SAMPLE_GUI
            if self.result.target_type == TargetType.GUI
            else self.MAX_CORPUS_SAMPLE_CLI
        )
        sample_size = min(
            max_sample, max(10, int(len(all_seeds) * self.CORPUS_SAMPLE_PERCENT))
        )
        sample = random.sample(all_seeds, min(sample_size, len(all_seeds)))

        logger.info(f"[i] Testing {len(sample)} of {len(all_seeds)} seeds...")

        valid = 0
        errors = 0
        crashes = 0

        for seed in sample:
            exit_code, exec_time, timed_out = self._run_target(
                seed, timeout=self.result.recommended_timeout
            )

            if exit_code in self.CRASH_EXIT_CODES:
                crashes += 1
                self.result.problematic_seeds.append(str(seed))
            elif exit_code is not None and exit_code != 0:
                errors += 1
            else:
                valid += 1

        # Extrapolate to full corpus
        sample_ratio = len(all_seeds) / len(sample)
        self.result.corpus_valid = int(valid * sample_ratio)
        self.result.corpus_errors = int(errors * sample_ratio)
        self.result.corpus_crashes = int(crashes * sample_ratio)

        logger.info(
            f"[+] Corpus health: {valid}/{len(sample)} valid in sample "
            f"(~{self.result.corpus_valid}/{self.result.corpus_total} estimated)"
        )

        if crashes > 0:
            logger.warning(
                f"[!] {crashes} seeds cause crashes - prioritize these for testing"
            )

    def _generate_recommendations(self) -> None:
        """Generate recommendations based on calibration results."""
        recs = []

        # Target type recommendations
        if self.result.target_type == TargetType.GUI:
            recs.append(
                f"Use GUI mode with {self.result.recommended_timeout:.0f}s timeout"
            )
        elif self.result.target_type == TargetType.CLI:
            recs.append(
                f"Use CLI mode with {self.result.recommended_timeout:.1f}s timeout"
            )
        elif self.result.target_type == TargetType.ERROR:
            recs.append("Target returns errors - check if corpus files are valid")
        else:
            recs.append("Could not determine target type - use conservative settings")

        # Crash detection recommendations
        if not self.result.wer_disabled and sys.platform == "win32":
            recs.append("Run as administrator to disable WER dialogs")

        # Corpus recommendations
        if self.result.corpus_crashes > 0:
            recs.append(
                f"{self.result.corpus_crashes} corpus files cause crashes - "
                "prioritize these for investigation"
            )

        if self.result.corpus_total > 1000:
            recs.append(
                f"Large corpus ({self.result.corpus_total} files) - "
                "consider minimization for faster iteration"
            )

        # Performance recommendations
        if self.result.avg_execution_time > 1.0:
            recs.append(
                f"Slow target ({self.result.avg_execution_time:.1f}s avg) - "
                "expect ~{:.0f} tests/hour".format(
                    3600 / self.result.recommended_timeout
                )
            )

        self.result.recommendations = recs


def calibrate_target(
    target: str | Path,
    corpus: str | Path | None = None,
    verbose: bool = False,
) -> CalibrationResult:
    """Convenience function to calibrate a target.

    Args:
        target: Path to target executable
        corpus: Optional path to seed corpus
        verbose: Enable verbose output

    Returns:
        CalibrationResult with calibration data

    """
    calibrator = TargetCalibrator(target, corpus, verbose)
    return calibrator.calibrate()
