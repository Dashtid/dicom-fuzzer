#!/usr/bin/env python3
"""Overnight Fuzzing Campaign for Hermes.exe

Automated fuzzing campaign with crash detection, memory monitoring, and reporting.
Supports GUI applications with crash monitoring.

Usage:
    python scripts/overnight_campaign.py --help
    python scripts/overnight_campaign.py --duration 8  # 8-hour campaign
    python scripts/overnight_campaign.py --dry-run     # Test without fuzzing

"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import random
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dicom_fuzzer.core.byte_mutator import ByteMutator, DICOMByteMutator  # noqa: E402

# Note: CVE-specific mutations have been removed from fuzzing.
# For CVE replication, use: dicom-fuzzer cve --help


class GUIExecutionStatus(Enum):
    """Result of GUI application execution."""

    SUCCESS = "success"  # App ran and was killed normally
    CRASH = "crash"  # App crashed before timeout
    HANG = "hang"  # App became unresponsive
    ERROR = "error"  # Other error


@dataclass
class GUIExecutionResult:
    """Result from executing a GUI application."""

    status: GUIExecutionStatus
    exit_code: int | None
    execution_time: float
    crashed_early: bool = False


class GUITargetRunner:
    """Runner for GUI applications with crash monitoring.

    For GUI apps that don't exit after loading a file, this runner:
    1. Launches the application with the test file
    2. Monitors for early termination (crash indicator)
    3. Kills the process after a timeout
    4. Detects crashes vs normal operation
    """

    # Exit codes that indicate crashes on Windows
    CRASH_EXIT_CODES = {
        -1073741819,  # 0xC0000005 - Access Violation
        -1073741795,  # 0xC000001D - Illegal Instruction
        -1073741676,  # 0xC0000094 - Integer Divide by Zero
        -1073741571,  # 0xC00000FD - Stack Overflow
        -1073740940,  # 0xC0000374 - Heap Corruption
        -1073740791,  # 0xC0000409 - Stack Buffer Overrun
        -2147483645,  # 0x80000003 - Breakpoint (crash trap)
    }

    def __init__(
        self,
        target_executable: Path,
        timeout: float = 10.0,
        poll_interval: float = 0.1,
    ):
        """Initialize GUI target runner.

        Args:
            target_executable: Path to the GUI application
            timeout: Seconds to wait before killing (normal operation)
            poll_interval: How often to check if process crashed

        """
        self.target = target_executable
        self.timeout = timeout
        self.poll_interval = poll_interval

        if not self.target.exists():
            raise FileNotFoundError(f"Target not found: {target_executable}")

    def execute(self, test_file: Path) -> GUIExecutionResult:
        """Execute the GUI application with a test file.

        Args:
            test_file: DICOM file to test

        Returns:
            GUIExecutionResult with execution details

        """
        start_time = time.time()

        try:
            # Launch the GUI application
            process = subprocess.Popen(
                [str(self.target), str(test_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
                if sys.platform == "win32"
                else 0,
            )

            # Monitor for early termination (crash indicator)
            elapsed = 0.0
            while elapsed < self.timeout:
                # Check if process terminated
                exit_code = process.poll()
                if exit_code is not None:
                    # Process terminated before timeout
                    execution_time = time.time() - start_time

                    # Check if it's a crash
                    if exit_code in self.CRASH_EXIT_CODES or exit_code < 0:
                        return GUIExecutionResult(
                            status=GUIExecutionStatus.CRASH,
                            exit_code=exit_code,
                            execution_time=execution_time,
                            crashed_early=True,
                        )
                    else:
                        # Normal exit (unusual for GUI app, might be error)
                        return GUIExecutionResult(
                            status=GUIExecutionStatus.SUCCESS,
                            exit_code=exit_code,
                            execution_time=execution_time,
                            crashed_early=False,
                        )

                time.sleep(self.poll_interval)
                elapsed = time.time() - start_time

            # Timeout reached - kill the process (normal for GUI apps)
            execution_time = time.time() - start_time

            # Try graceful termination first
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                # Force kill if still running
                process.kill()
                process.wait(timeout=1.0)

            return GUIExecutionResult(
                status=GUIExecutionStatus.SUCCESS,
                exit_code=None,
                execution_time=execution_time,
                crashed_early=False,
            )

        except Exception:
            execution_time = time.time() - start_time
            return GUIExecutionResult(
                status=GUIExecutionStatus.ERROR,
                exit_code=None,
                execution_time=execution_time,
                crashed_early=False,
            )


@dataclass
class CampaignConfig:
    """Configuration for overnight fuzzing campaign."""

    # Target
    target_executable: Path = Path(r"C:\Hermes\Affinity\Hermes.exe")
    corpus_dir: Path = Path(r"C:\Data\test-automation\Kiwi - Example Data - 20210423")
    output_dir: Path = PROJECT_ROOT / "artifacts" / "hermes-campaign"

    # Timing
    duration_hours: float = 8.0
    timeout_per_execution: float = 10.0  # seconds (short for GUI apps)
    stats_interval: float = 300.0  # 5 minutes
    gui_mode: bool = True  # Use GUI-aware crash monitoring
    auto_calibrate: bool = True  # Run calibration before campaign

    # Resources
    max_workers: int = 0  # 0 = auto (CPU count - 2)
    memory_limit_mb: int = 4096
    max_corpus_size: int = 1000  # Max seeds after minimization

    # Mutation
    mutation_strategies: list[str] = field(
        default_factory=lambda: ["byte_havoc", "dicom_aware", "cve_patterns"]
    )
    mutations_per_seed: int = 100

    # Crash handling
    max_crashes_before_pause: int = 100
    dedupe_crashes: bool = True


@dataclass
class CampaignStats:
    """Statistics for fuzzing campaign."""

    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    total_executions: int = 0
    crashes: int = 0
    hangs: int = 0
    errors: int = 0
    unique_crashes: int = 0
    seeds_tested: int = 0
    mutations_generated: int = 0
    peak_memory_mb: float = 0.0
    crash_hashes: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert stats to dictionary."""
        runtime = (self.end_time or datetime.now()) - self.start_time
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": (self.end_time or datetime.now()).isoformat(),
            "runtime_seconds": runtime.total_seconds(),
            "total_executions": self.total_executions,
            "executions_per_second": (
                self.total_executions / max(1, runtime.total_seconds())
            ),
            "crashes": self.crashes,
            "hangs": self.hangs,
            "errors": self.errors,
            "unique_crashes": self.unique_crashes,
            "seeds_tested": self.seeds_tested,
            "mutations_generated": self.mutations_generated,
            "peak_memory_mb": self.peak_memory_mb,
        }


class OvernightCampaign:
    """Manages overnight fuzzing campaign."""

    def __init__(self, config: CampaignConfig):
        self.config = config
        self.stats = CampaignStats()
        self.logger = self._setup_logging()
        self.running = False
        self.stop_event = threading.Event()

        # Mutators
        self.byte_mutator = ByteMutator()
        self.dicom_mutator = DICOMByteMutator()
        # CVE mutations removed - use dicom-fuzzer cve command for CVE replication
        self.cve_funcs: list = []

        # Seeds
        self.seeds: list[Path] = []
        self.current_seed_idx = 0

    def _setup_logging(self) -> logging.Logger:
        """Set up campaign logging."""
        log_dir = self.config.output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        logger = logging.getLogger("overnight_campaign")
        logger.setLevel(logging.DEBUG)

        # File handler - detailed logs
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fh = logging.FileHandler(log_dir / f"campaign_{timestamp}.log")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(fh)

        # Console handler - summary only
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(ch)

        return logger

    def _setup_directories(self) -> None:
        """Create output directory structure."""
        dirs = [
            self.config.output_dir / "crashes",
            self.config.output_dir / "hangs",
            self.config.output_dir / "queue",
            self.config.output_dir / "logs",
            self.config.output_dir / "reports",
            self.config.output_dir / "corpus",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"[+] Output directory: {self.config.output_dir}")

    def _disable_wer(self) -> bool:
        """Disable Windows Error Reporting dialogs.

        Returns:
            True if successful, False otherwise.

        """
        if sys.platform != "win32":
            return True

        try:
            # Method 1: Set error mode to prevent dialogs
            kernel32 = ctypes.windll.kernel32
            sem_nogpfaulterrorbox = 0x0002  # Windows constants
            sem_failcriticalerrors = 0x0001
            sem_noopenfileerrorbox = 0x8000
            kernel32.SetErrorMode(
                sem_nogpfaulterrorbox | sem_failcriticalerrors | sem_noopenfileerrorbox
            )
            self.logger.info("[+] Disabled Windows Error Reporting dialogs")
            return True
        except Exception as e:
            self.logger.warning(f"[!] Could not disable WER: {e}")
            return False

    def _load_corpus(self) -> None:
        """Load and optionally minimize seed corpus."""
        self.logger.info(f"[i] Scanning corpus: {self.config.corpus_dir}")

        # Find all DICOM files
        all_seeds = list(self.config.corpus_dir.rglob("*.dcm"))
        self.logger.info(f"[i] Found {len(all_seeds)} DICOM files")

        if len(all_seeds) == 0:
            # Try without .dcm extension (some DICOM files have no extension)
            all_seeds = [
                f
                for f in self.config.corpus_dir.rglob("*")
                if f.is_file() and f.stat().st_size > 132
            ]
            self.logger.info(f"[i] Found {len(all_seeds)} potential DICOM files")

        # Minimize corpus if too large
        if len(all_seeds) > self.config.max_corpus_size:
            self.logger.info(
                f"[i] Minimizing corpus from {len(all_seeds)} to "
                f"{self.config.max_corpus_size} seeds..."
            )
            # Sample diverse seeds (by size and directory)
            self.seeds = self._sample_diverse_seeds(
                all_seeds, self.config.max_corpus_size
            )
        else:
            self.seeds = all_seeds

        # Copy seeds to campaign corpus dir
        corpus_dir = self.config.output_dir / "corpus"
        for i, seed in enumerate(self.seeds):
            dest = corpus_dir / f"seed_{i:04d}{seed.suffix}"
            if not dest.exists():
                shutil.copy2(seed, dest)

        self.logger.info(f"[+] Loaded {len(self.seeds)} seeds")

    def _sample_diverse_seeds(self, seeds: list[Path], max_count: int) -> list[Path]:
        """Sample diverse seeds from corpus."""
        if len(seeds) <= max_count:
            return seeds

        # Group by parent directory (preserves modality diversity)
        by_dir: dict[Path, list[Path]] = {}
        for seed in seeds:
            parent = seed.parent
            if parent not in by_dir:
                by_dir[parent] = []
            by_dir[parent].append(seed)

        # Sample proportionally from each directory
        result: list[Path] = []
        per_dir = max(1, max_count // len(by_dir))

        for dir_seeds in by_dir.values():
            sample_count = min(per_dir, len(dir_seeds))
            result.extend(random.sample(dir_seeds, sample_count))

        # If we still need more, sample randomly
        remaining = max_count - len(result)
        if remaining > 0:
            available = [s for s in seeds if s not in result]
            result.extend(random.sample(available, min(remaining, len(available))))

        return result[:max_count]

    def _mutate_seed(self, seed_data: bytes) -> bytes:
        """Apply random mutation strategy to seed."""
        strategy = random.choice(self.config.mutation_strategies)
        self.stats.mutations_generated += 1

        if strategy == "byte_havoc":
            return self.byte_mutator.mutate(
                seed_data, num_mutations=random.randint(1, 10)
            )
        elif strategy == "dicom_aware":
            return self.dicom_mutator.mutate_dicom(seed_data, preserve_magic=True)
        elif strategy == "cve_patterns":
            # Apply random CVE-inspired mutation
            try:
                cve_func = random.choice(self.cve_funcs)
                return cve_func(seed_data)
            except Exception:
                return self.byte_mutator.mutate(seed_data)
        else:
            return self.byte_mutator.mutate(seed_data)

    def _save_crash(
        self, input_data: bytes, seed_path: Path, exit_code: int | None, stderr: str
    ) -> str:
        """Save crash-inducing input."""
        import hashlib

        crash_hash = hashlib.sha256(input_data).hexdigest()[:16]

        # Check for duplicate
        if self.config.dedupe_crashes and crash_hash in self.stats.crash_hashes:
            return crash_hash

        self.stats.crash_hashes.add(crash_hash)
        self.stats.unique_crashes += 1

        # Save crash input
        crash_dir = self.config.output_dir / "crashes"
        crash_file = crash_dir / f"crash_{crash_hash}.dcm"
        crash_file.write_bytes(input_data)

        # Save crash metadata
        meta = {
            "crash_hash": crash_hash,
            "timestamp": datetime.now().isoformat(),
            "original_seed": str(seed_path),
            "exit_code": exit_code,
            "stderr": stderr[:2000] if stderr else "",
        }
        meta_file = crash_dir / f"crash_{crash_hash}.json"
        meta_file.write_text(json.dumps(meta, indent=2))

        self.logger.info(f"[!] CRASH saved: {crash_file.name} (exit={exit_code})")
        return crash_hash

    def _save_hang(self, input_data: bytes, seed_path: Path) -> None:
        """Save hang-inducing input."""
        import hashlib

        hang_hash = hashlib.sha256(input_data).hexdigest()[:16]
        hang_dir = self.config.output_dir / "hangs"
        hang_file = hang_dir / f"hang_{hang_hash}.dcm"

        if not hang_file.exists():
            hang_file.write_bytes(input_data)
            self.logger.info(f"[!] HANG saved: {hang_file.name}")

    def _print_stats(self) -> None:
        """Print current campaign statistics."""
        runtime = datetime.now() - self.stats.start_time
        exec_rate = self.stats.total_executions / max(1, runtime.total_seconds())

        print("\n" + "=" * 70)
        print(f"  Runtime: {str(runtime).split('.')[0]}")
        print(f"  Executions: {self.stats.total_executions:,} ({exec_rate:.1f}/sec)")
        print(f"  Crashes: {self.stats.crashes} ({self.stats.unique_crashes} unique)")
        print(f"  Hangs: {self.stats.hangs}")
        print(f"  Seeds tested: {self.stats.seeds_tested}/{len(self.seeds)}")
        print("=" * 70 + "\n")

    def _generate_report(self) -> None:
        """Generate final campaign report."""
        self.stats.end_time = datetime.now()
        report_dir = self.config.output_dir / "reports"

        # JSON report
        report = {
            "campaign": {
                "target": str(self.config.target_executable),
                "corpus": str(self.config.corpus_dir),
                "duration_hours": self.config.duration_hours,
            },
            "stats": self.stats.to_dict(),
            "crashes": [
                str(f) for f in (self.config.output_dir / "crashes").glob("*.dcm")
            ],
            "hangs": [str(f) for f in (self.config.output_dir / "hangs").glob("*.dcm")],
        }

        json_path = report_dir / "campaign_report.json"
        json_path.write_text(json.dumps(report, indent=2))
        self.logger.info(f"[+] Report saved: {json_path}")

        # Text summary
        summary_path = report_dir / "summary.txt"
        with open(summary_path, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("  OVERNIGHT FUZZING CAMPAIGN SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Target: {self.config.target_executable}\n")
            f.write(f"Duration: {self.config.duration_hours} hours\n")
            f.write(f"Start: {self.stats.start_time}\n")
            f.write(f"End: {self.stats.end_time}\n\n")
            f.write(f"Total Executions: {self.stats.total_executions:,}\n")
            f.write(f"Crashes Found: {self.stats.crashes}\n")
            f.write(f"Unique Crashes: {self.stats.unique_crashes}\n")
            f.write(f"Hangs Found: {self.stats.hangs}\n")
            f.write("=" * 70 + "\n")

        self.logger.info(f"[+] Summary saved: {summary_path}")

    def _run_calibration(self, force_recalibrate: bool = False) -> Any:
        """Run target calibration and return results.

        Checks for existing calibration.json first to skip re-calibration.
        Validates target path and version before using cached calibration.

        Args:
            force_recalibrate: If True, skip cache and run fresh calibration.

        Returns:
            CalibrationResult or None if calibration fails.

        """
        from dicom_fuzzer.core.target_calibrator import (
            CalibrationResult,
            TargetCalibrator,
        )

        # Check for existing calibration (unless forced)
        report_dir = self.config.output_dir / "reports"
        calib_file = report_dir / "calibration.json"

        if calib_file.exists() and not force_recalibrate:
            try:
                data = json.loads(calib_file.read_text())

                # Validate version compatibility
                cached_version = data.get("calibration_version", 1)
                current_version = TargetCalibrator.CALIBRATION_VERSION
                if cached_version < current_version:
                    self.logger.warning(
                        f"[!] Cached calibration is outdated "
                        f"(v{cached_version} < v{current_version})"
                    )
                    self.logger.info("[i] Running fresh calibration...")
                else:
                    # Validate target path matches
                    cached_target = Path(data.get("target_path", ""))
                    current_target = self.config.target_executable.resolve()
                    if cached_target.resolve() != current_target:
                        self.logger.warning(
                            "[!] Cached calibration is for different target"
                        )
                        self.logger.info(f"    Cached: {cached_target}")
                        self.logger.info(f"    Current: {current_target}")
                        self.logger.info("[i] Running fresh calibration...")
                    else:
                        result = CalibrationResult.from_dict(data)
                        self.logger.info(
                            f"[+] Loaded existing calibration from {calib_file}"
                        )
                        result.print_summary()
                        return result
            except Exception as e:
                self.logger.warning(f"[!] Failed to load calibration: {e}")
                self.logger.info("[i] Running fresh calibration...")

        # Run fresh calibration
        self.logger.info("[i] Running target calibration...")

        try:
            calibrator = TargetCalibrator(
                target_executable=self.config.target_executable,
                corpus_dir=self.config.corpus_dir,
                verbose=False,
            )

            result = calibrator.calibrate()
            result.print_summary()

            # Save calibration report
            report_dir.mkdir(parents=True, exist_ok=True)
            calib_file.write_text(json.dumps(result.to_dict(), indent=2))
            self.logger.info(f"[+] Calibration saved: {calib_file}")

            return result

        except Exception as e:
            self.logger.warning(f"[!] Calibration failed: {e}")
            self.logger.info("[i] Using default settings")
            return None

    def run(self, dry_run: bool = False, force_recalibrate: bool = False) -> int:
        """Run the fuzzing campaign.

        Args:
            dry_run: If True, just validate setup without fuzzing.
            force_recalibrate: If True, ignore cached calibration.

        Returns:
            Exit code (0 = success).

        """
        self.running = True

        print("\n" + "=" * 70)
        print("  DICOM Fuzzer - Overnight Campaign")
        print("=" * 70)
        print(f"  Target:   {self.config.target_executable}")
        print(f"  Corpus:   {self.config.corpus_dir}")
        print(f"  Duration: {self.config.duration_hours} hours")
        print(f"  Output:   {self.config.output_dir}")
        print("=" * 70 + "\n")

        # Setup
        self._setup_directories()
        self._disable_wer()
        self._load_corpus()

        if len(self.seeds) == 0:
            self.logger.error("[-] No seeds found in corpus!")
            return 1

        if dry_run:
            self.logger.info("[+] Dry run complete - setup validated")
            return 0

        # Auto-calibrate target if enabled
        if self.config.auto_calibrate:
            calibration_result = self._run_calibration(
                force_recalibrate=force_recalibrate
            )
            if calibration_result:
                # Apply calibrated settings
                self.config.timeout_per_execution = (
                    calibration_result.recommended_timeout
                )
                self.logger.info(
                    f"[+] Auto-calibrated: timeout={calibration_result.recommended_timeout:.1f}s, "
                    f"type={calibration_result.target_type.value}"
                )

        # Initialize target runner (GUI-aware for Hermes.exe)
        try:
            runner = GUITargetRunner(
                target_executable=self.config.target_executable,
                timeout=self.config.timeout_per_execution,
            )
            self.logger.info(
                f"[+] GUI runner initialized (timeout={self.config.timeout_per_execution}s)"
            )
        except FileNotFoundError as e:
            self.logger.error(f"[-] Target not found: {e}")
            return 1

        # Calculate end time
        end_time = datetime.now() + timedelta(hours=self.config.duration_hours)
        self.logger.info(f"[+] Campaign will run until: {end_time}")

        # Stats printer thread
        last_stats_time = time.time()

        # Signal handler for graceful shutdown
        def signal_handler(sig: int, frame: Any) -> None:
            self.logger.info("\n[i] Shutdown requested...")
            self.stop_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, signal_handler)

        # Main fuzzing loop
        try:
            while datetime.now() < end_time and not self.stop_event.is_set():
                # Get next seed
                seed_path = self.seeds[self.current_seed_idx]
                self.current_seed_idx = (self.current_seed_idx + 1) % len(self.seeds)

                try:
                    seed_data = seed_path.read_bytes()
                except Exception as e:
                    self.logger.debug(f"Could not read seed {seed_path}: {e}")
                    continue

                # Apply mutations
                for _ in range(self.config.mutations_per_seed):
                    if self.stop_event.is_set():
                        break

                    try:
                        mutated = self._mutate_seed(seed_data)
                    except Exception as e:
                        self.logger.debug(f"Mutation failed: {e}")
                        continue

                    # Write mutated input to temp file
                    temp_file = self.config.output_dir / "queue" / "current.dcm"
                    temp_file.write_bytes(mutated)

                    # Execute target with GUI-aware monitoring
                    result = runner.execute(temp_file)
                    self.stats.total_executions += 1

                    # Handle result
                    if result.status == GUIExecutionStatus.CRASH:
                        self.stats.crashes += 1
                        self._save_crash(mutated, seed_path, result.exit_code, "")
                    elif result.status == GUIExecutionStatus.ERROR:
                        self.stats.errors += 1
                    # Note: SUCCESS means app was killed after timeout (normal for GUI)

                self.stats.seeds_tested += 1

                # Print periodic stats
                if time.time() - last_stats_time > self.config.stats_interval:
                    self._print_stats()
                    last_stats_time = time.time()

        except Exception as e:
            self.logger.error(f"[-] Campaign error: {e}")
            import traceback

            traceback.print_exc()

        # Cleanup
        self.running = False
        self._print_stats()
        self._generate_report()

        self.logger.info("[+] Campaign complete!")
        return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Overnight DICOM fuzzing campaign for Hermes.exe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--target",
        type=str,
        default=r"C:\Hermes\Affinity\Hermes.exe",
        help="Target executable path",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=r"C:\Data\test-automation\Kiwi - Example Data - 20210423",
        help="Seed corpus directory",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(PROJECT_ROOT / "artifacts" / "hermes-campaign"),
        help="Output directory",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=8.0,
        help="Campaign duration in hours (default: 8)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout per execution in seconds (default: 10, for GUI apps)",
    )
    parser.add_argument(
        "--max-seeds",
        type=int,
        default=1000,
        help="Maximum seeds to use from corpus (default: 1000)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate setup without fuzzing",
    )
    parser.add_argument(
        "--recalibrate",
        action="store_true",
        help="Force fresh calibration (ignore cached calibration.json)",
    )
    parser.add_argument(
        "--no-calibrate",
        action="store_true",
        help="Skip auto-calibration entirely",
    )

    args = parser.parse_args()

    config = CampaignConfig(
        target_executable=Path(args.target),
        corpus_dir=Path(args.corpus),
        output_dir=Path(args.output),
        duration_hours=args.duration,
        timeout_per_execution=args.timeout,
        max_corpus_size=args.max_seeds,
        auto_calibrate=not args.no_calibrate,
    )

    campaign = OvernightCampaign(config)
    return campaign.run(
        dry_run=args.dry_run,
        force_recalibrate=args.recalibrate,
    )


if __name__ == "__main__":
    sys.exit(main())
