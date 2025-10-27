"""Coverage-Guided Fuzzer for DICOM

Main fuzzing engine that integrates coverage tracking, corpus management,
and adaptive mutations to maximize code coverage and bug discovery.
"""

import asyncio
import hashlib
import json
import logging
import signal
import time
from collections.abc import Callable
from concurrent.futures import BrokenExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pydicom

from .corpus_manager import CorpusManager, HistoricalCorpusManager
from .coverage_guided_mutator import CoverageGuidedMutator, MutationType
from .coverage_instrumentation import CoverageInfo, CoverageTracker
from .crash_analyzer import CrashAnalyzer
from .reporter import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class FuzzingConfig:
    """Configuration for coverage-guided fuzzing."""

    # Target configuration
    target_function: Callable | None = None
    target_binary: str | None = None
    target_modules: list[str] = field(default_factory=list)

    # Fuzzing parameters
    max_iterations: int = 10000
    timeout_per_run: float = 1.0
    max_input_size: int = 10 * 1024 * 1024  # 10MB
    num_workers: int = 1

    # Coverage parameters
    coverage_guided: bool = True
    track_branches: bool = True
    minimize_corpus: bool = True

    # Corpus parameters
    corpus_dir: Path | None = None
    seed_dir: Path | None = None
    max_corpus_size: int = 1000

    # Mutation parameters
    max_mutations: int = 10
    adaptive_mutations: bool = True
    dicom_aware: bool = True

    # Output configuration
    output_dir: Path = Path("fuzzing_output")
    crash_dir: Path = Path("crashes")
    save_all_inputs: bool = False
    save_interesting: bool = True

    # Reporting
    report_interval: int = 100
    verbose: bool = False


@dataclass
class FuzzingStats:
    """Statistics for fuzzing campaign."""

    start_time: float = field(default_factory=time.time)
    total_executions: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    coverage_increases: int = 0
    current_coverage: int = 0
    max_coverage: int = 0
    mutations_performed: int = 0
    corpus_size: int = 0
    exec_per_sec: float = 0.0
    time_since_last_coverage: float = 0.0
    mutation_stats: dict[str, Any] = field(default_factory=dict)


class CoverageGuidedFuzzer:
    """Main coverage-guided fuzzing engine for DICOM files."""

    def __init__(self, config: FuzzingConfig):
        """Initialize the coverage-guided fuzzer.

        Args:
            config: Fuzzing configuration

        """
        self.config = config
        self.stats = FuzzingStats()

        # Initialize components
        self.coverage_tracker = CoverageTracker(
            target_modules=set(config.target_modules) if config.target_modules else None
        )

        # Use historical corpus manager if history exists
        history_dir = config.corpus_dir / "history" if config.corpus_dir else None
        if history_dir and history_dir.exists():
            self.corpus_manager = HistoricalCorpusManager(
                history_dir=history_dir, max_corpus_size=config.max_corpus_size
            )
        else:
            self.corpus_manager = CorpusManager(max_corpus_size=config.max_corpus_size)

        self.mutator = CoverageGuidedMutator(
            max_mutations=config.max_mutations,
            adaptive_mode=config.adaptive_mutations,
            dicom_aware=config.dicom_aware,
        )

        self.crash_analyzer = CrashAnalyzer(crash_dir=str(config.crash_dir))
        self.reporter = ReportGenerator()

        # Setup directories
        self._setup_directories()

        # Control flags
        self.should_stop = False
        self.is_running = False

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _setup_directories(self) -> None:
        """Create necessary directories."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.config.crash_dir.mkdir(parents=True, exist_ok=True)

        if self.config.corpus_dir:
            self.config.corpus_dir.mkdir(parents=True, exist_ok=True)

    def _signal_handler(self, signum, frame) -> None:
        """Handle interrupt signals gracefully."""
        logger.info(f"Received signal {signum}, stopping fuzzer...")
        self.should_stop = True

    async def run(self) -> FuzzingStats:
        """Run the fuzzing campaign.

        Returns:
            Final fuzzing statistics

        """
        logger.info("Starting coverage-guided fuzzing campaign")
        self.is_running = True

        try:
            # Load initial seeds
            await self._load_initial_seeds()

            # Main fuzzing loop
            if self.config.num_workers > 1:
                await self._run_parallel()
            else:
                await self._run_single()

        finally:
            self.is_running = False
            await self._finalize()

        return self.stats

    async def _load_initial_seeds(self) -> None:
        """Load initial seed corpus."""
        # Load from corpus directory
        if self.config.corpus_dir and self.config.corpus_dir.exists():
            self.corpus_manager.load_corpus(self.config.corpus_dir)
            logger.info(f"Loaded {len(self.corpus_manager.seeds)} seeds from corpus")

        # Load from seed directory
        if self.config.seed_dir and self.config.seed_dir.exists():
            for seed_file in self.config.seed_dir.glob("*.dcm"):
                try:
                    with open(seed_file, "rb") as f:
                        data = f.read()

                    # Get initial coverage
                    with self.coverage_tracker.track_coverage(data) as coverage:
                        self._execute_target(data)

                    self.corpus_manager.add_seed(data, coverage)
                except Exception as e:
                    logger.warning(f"Failed to load seed {seed_file}: {e}")

        # If no seeds, create minimal seed
        if not self.corpus_manager.seeds:
            logger.info("No seeds found, creating minimal DICOM seed")
            minimal_seed = self._create_minimal_dicom()

            with self.coverage_tracker.track_coverage(minimal_seed) as coverage:
                self._execute_target(minimal_seed)

            self.corpus_manager.add_seed(minimal_seed, coverage)

        self.stats.corpus_size = len(self.corpus_manager.seeds)

    def _create_minimal_dicom(self) -> bytes:
        """Create a minimal valid DICOM file."""
        try:
            # Create minimal dataset
            ds = pydicom.Dataset()
            ds.PatientName = "Test"
            ds.PatientID = "123"
            ds.file_meta = pydicom.Dataset()
            ds.file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian

            # Convert to bytes
            from io import BytesIO

            buffer = BytesIO()
            pydicom.dcmwrite(buffer, ds, write_like_original=False)
            return buffer.getvalue()
        except Exception:
            # Fallback to minimal DICOM header
            return b"DICM" + b"\x00" * 128

    async def _run_single(self) -> None:
        """Run single-threaded fuzzing loop."""
        iteration = 0

        while not self.should_stop and iteration < self.config.max_iterations:
            # Get next seed
            seed = self.corpus_manager.get_next_seed()
            if not seed:
                logger.warning("No seeds available")
                break

            # Mutate seed
            mutations = self.mutator.mutate(seed)

            for mutated_data, mutation_type in mutations:
                if self.should_stop:
                    break

                # Execute with coverage tracking
                coverage, crashed = await self._execute_with_coverage(mutated_data)

                # Update statistics
                self.stats.total_executions += 1
                self.stats.mutations_performed += 1

                # Handle results
                await self._process_result(
                    mutated_data, coverage, crashed, seed.id, mutation_type
                )

                # Report progress
                if self.stats.total_executions % self.config.report_interval == 0:
                    self._report_progress()

            iteration += 1

    async def _run_parallel(self) -> None:
        """Run parallel fuzzing with multiple workers.

        STABILITY: Uses ThreadPoolExecutor with proper error handling.
        For CPU-intensive tasks, consider ProcessPoolExecutor with BrokenProcessPool handling.
        """
        try:
            with ThreadPoolExecutor(max_workers=self.config.num_workers) as executor:
                tasks = []

                for _ in range(self.config.num_workers):
                    task = executor.submit(self._worker_loop)
                    tasks.append(task)

                # Wait for all workers
                for task in tasks:
                    try:
                        task.result()
                    except Exception as e:
                        logger.error(f"Worker thread crashed: {e}", exc_info=True)
                        # Continue with other workers

        except BrokenExecutor as e:
            logger.error(f"Executor failed catastrophically: {e}")
            raise

    def _worker_loop(self) -> None:
        """Worker loop for parallel fuzzing."""
        while not self.should_stop:
            # Get next seed
            seed = self.corpus_manager.get_next_seed()
            if not seed:
                time.sleep(0.1)
                continue

            # Mutate and test
            mutations = self.mutator.mutate(seed)

            for mutated_data, mutation_type in mutations:
                if self.should_stop:
                    break

                # Execute with coverage
                coverage, crashed = asyncio.run(
                    self._execute_with_coverage(mutated_data)
                )

                # Process result
                asyncio.run(
                    self._process_result(
                        mutated_data, coverage, crashed, seed.id, mutation_type
                    )
                )

    async def _execute_with_coverage(self, data: bytes) -> tuple[CoverageInfo, bool]:
        """Execute target with coverage tracking.

        Returns:
            (coverage_info, crashed) tuple

        """
        crashed = False
        coverage = CoverageInfo()

        try:
            with self.coverage_tracker.track_coverage(data) as coverage:
                # Execute target with timeout
                _ = await asyncio.wait_for(
                    asyncio.to_thread(self._execute_target, data),
                    timeout=self.config.timeout_per_run,
                )
        except TimeoutError:
            logger.debug("Execution timeout")
            crashed = True
        except Exception as e:
            logger.debug(f"Execution crashed: {e}")
            crashed = True

        return coverage, crashed

    def _execute_target(self, data: bytes) -> Any:
        """Execute the target with the given input.

        Args:
            data: Input data to test

        Returns:
            Execution result

        """
        if self.config.target_function:
            # Execute Python function
            return self.config.target_function(data)

        elif self.config.target_binary:
            # Execute external binary
            import subprocess
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as f:
                f.write(data)
                temp_path = f.name

            try:
                result = subprocess.run(
                    [self.config.target_binary, temp_path],
                    capture_output=True,
                    timeout=self.config.timeout_per_run,
                )
                return result.returncode == 0
            finally:
                Path(temp_path).unlink(missing_ok=True)

        else:
            # Default: try to parse as DICOM
            try:
                from io import BytesIO

                ds = pydicom.dcmread(BytesIO(data))
                # Try to access some attributes to trigger parsing
                _ = ds.PatientName
                _ = ds.pixel_array if hasattr(ds, "PixelData") else None
                return True
            except Exception:
                raise

    async def _process_result(
        self,
        data: bytes,
        coverage: CoverageInfo,
        crashed: bool,
        parent_id: str,
        mutation_type: MutationType,
    ) -> None:
        """Process execution result."""
        # Update mutation feedback
        self.mutator.update_strategy_feedback(
            mutation_type,
            coverage.new_coverage,
            len(coverage.edges - self.coverage_tracker.global_coverage.edges),
        )

        # Handle crashes
        if crashed:
            self.stats.total_crashes += 1

            # Create crash info
            crash_hash = hashlib.sha256(data).hexdigest()[:16]
            is_unique = self.crash_analyzer.is_unique_crash(crash_hash)

            if is_unique:
                self.stats.unique_crashes += 1
                # Simple crash info object
                crash_info = type(
                    "CrashInfo",
                    (),
                    {
                        "id": crash_hash,
                        "coverage_hash": coverage.get_coverage_hash(),
                        "parent_id": parent_id,
                        "is_unique": True,
                    },
                )()
                self._save_crash(data, crash_info)

            # Update seed crash count
            self.corpus_manager.update_seed_crash(parent_id)

        # Handle new coverage
        if coverage.new_coverage:
            self.stats.coverage_increases += 1
            self.stats.current_coverage = len(
                self.coverage_tracker.global_coverage.edges
            )
            self.stats.max_coverage = max(
                self.stats.max_coverage, self.stats.current_coverage
            )

            # Add to corpus
            new_seed = self.corpus_manager.add_seed(
                data, coverage, parent_id, mutation_type.value
            )

            if new_seed and self.config.save_interesting:
                self._save_interesting_input(data, new_seed.id)

        # Update corpus stats
        self.stats.corpus_size = len(self.corpus_manager.seeds)

    def _save_crash(self, data: bytes, crash_info: Any) -> None:
        """Save crash to disk."""
        crash_file = self.config.crash_dir / f"crash_{crash_info.id}.dcm"
        with open(crash_file, "wb") as f:
            f.write(data)

        # Save crash metadata
        meta_file = self.config.crash_dir / f"crash_{crash_info.id}.json"
        with open(meta_file, "w") as f:
            json.dump(
                {
                    "id": crash_info.id,
                    "coverage_hash": crash_info.coverage_hash,
                    "timestamp": time.time(),
                    "parent_seed": crash_info.parent_id,
                },
                f,
                indent=2,
            )

    def _save_interesting_input(self, data: bytes, seed_id: str) -> None:
        """Save interesting input that increases coverage."""
        interesting_dir = self.config.output_dir / "interesting"
        interesting_dir.mkdir(exist_ok=True)

        input_file = interesting_dir / f"input_{seed_id}.dcm"
        with open(input_file, "wb") as f:
            f.write(data)

    def _report_progress(self) -> None:
        """Report fuzzing progress."""
        # Calculate metrics
        elapsed = time.time() - self.stats.start_time
        self.stats.exec_per_sec = (
            self.stats.total_executions / elapsed if elapsed > 0 else 0
        )

        # Get coverage stats
        cov_stats = self.coverage_tracker.get_coverage_stats()
        corpus_stats = self.corpus_manager.get_corpus_stats()
        mutation_stats = self.mutator.get_mutation_stats()

        # Update stats
        self.stats.mutation_stats = mutation_stats

        # Log progress
        logger.info(
            f"Progress: exec={self.stats.total_executions}, "
            f"crashes={self.stats.total_crashes}/{self.stats.unique_crashes}, "
            f"cov={self.stats.current_coverage}/{self.stats.max_coverage}, "
            f"corp={self.stats.corpus_size}, "
            f"exec/s={self.stats.exec_per_sec:.1f}"
        )

        if self.config.verbose:
            logger.info(f"Coverage stats: {cov_stats}")
            logger.info(f"Corpus stats: {corpus_stats}")

    async def _finalize(self) -> None:
        """Finalize fuzzing campaign."""
        logger.info("Finalizing fuzzing campaign...")

        # Save corpus
        if self.config.corpus_dir:
            self.corpus_manager.save_corpus(self.config.corpus_dir)

        # Export coverage data
        coverage_file = self.config.output_dir / "coverage.json"
        self.coverage_tracker.export_coverage(coverage_file)

        # Generate final report
        report = self._generate_report()
        report_file = self.config.output_dir / "fuzzing_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Fuzzing complete. Results saved to {self.config.output_dir}")

    def _generate_report(self) -> dict[str, Any]:
        """Generate final fuzzing report."""
        elapsed = time.time() - self.stats.start_time

        return {
            "duration": elapsed,
            "total_executions": self.stats.total_executions,
            "exec_per_sec": self.stats.exec_per_sec,
            "crashes": {
                "total": self.stats.total_crashes,
                "unique": self.stats.unique_crashes,
            },
            "coverage": {
                "edges": self.stats.current_coverage,
                "max_edges": self.stats.max_coverage,
                "increases": self.stats.coverage_increases,
            },
            "corpus": {
                "size": self.stats.corpus_size,
                "stats": self.corpus_manager.get_corpus_stats(),
            },
            "mutations": self.stats.mutation_stats,
            "config": {
                "max_iterations": self.config.max_iterations,
                "workers": self.config.num_workers,
                "adaptive": self.config.adaptive_mutations,
                "dicom_aware": self.config.dicom_aware,
            },
        }


def create_fuzzer_from_config(config_path: Path) -> CoverageGuidedFuzzer:
    """Create fuzzer from configuration file."""
    with open(config_path) as f:
        config_dict = json.load(f)

    config = FuzzingConfig(**config_dict)
    return CoverageGuidedFuzzer(config)
