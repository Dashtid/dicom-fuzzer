"""Atheris Coverage-Guided Fuzzing Integration

This module integrates Google's Atheris fuzzing engine for coverage-guided
DICOM fuzzing. Atheris provides libFuzzer-style instrumentation for Python.

LEARNING OBJECTIVE: Atheris uses compile-time instrumentation to track
code coverage at the Python bytecode level, making it more effective than
random mutation for finding bugs.

CONCEPT: Coverage-guided fuzzing tracks which code paths are executed and
prioritizes inputs that explore new paths. Atheris provides this capability
for pure Python code.

WHY: Traditional fuzzing is random; coverage-guided fuzzing is intelligent.
By tracking coverage, we can find bugs 10-100x faster.

Usage:
    from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

    fuzzer = AtherisDICOMFuzzer(
        target_function=my_dicom_parser,
        corpus_dir=Path("corpus"),
        crash_dir=Path("crashes"),
    )
    fuzzer.run()
"""

from __future__ import annotations

import io
import sys
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pydicom
from pydicom.dataset import Dataset

from dicom_fuzzer.core.corpus_manager import CorpusManager
from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.strategies.dictionary_fuzzer import DictionaryFuzzer
from dicom_fuzzer.utils.hashing import short_hash
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

# Check if Atheris is available
try:
    import atheris

    HAS_ATHERIS = True
except ImportError:
    HAS_ATHERIS = False
    atheris = None


@dataclass
class AtherisConfig:
    """Configuration for Atheris-based fuzzing."""

    # Target configuration
    target_function: Callable[[bytes], Any] | None = None
    target_modules: list[str] = field(default_factory=list)

    # Fuzzing parameters
    max_time_seconds: int = 3600  # 1 hour default
    max_iterations: int = 0  # 0 = unlimited
    timeout_per_run: float = 5.0

    # Corpus parameters
    corpus_dir: Path | None = None
    seed_dir: Path | None = None
    max_input_size: int = 10 * 1024 * 1024  # 10MB

    # Crash handling
    crash_dir: Path = field(default_factory=lambda: Path("atheris_crashes"))
    deduplicate_crashes: bool = True

    # Output configuration
    output_dir: Path = field(default_factory=lambda: Path("atheris_output"))
    verbose: bool = False

    # DICOM-specific options
    dicom_aware_mutations: bool = True
    use_dictionary_fuzzer: bool = True
    mutation_severity: MutationSeverity = MutationSeverity.MODERATE


@dataclass
class AtherisStats:
    """Statistics for Atheris fuzzing campaign."""

    start_time: float = field(default_factory=time.time)
    total_executions: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    coverage_increases: int = 0
    corpus_size: int = 0
    exec_per_sec: float = 0.0
    last_coverage_time: float = field(default_factory=time.time)


class AtherisDICOMFuzzer:
    """Atheris-based coverage-guided fuzzer for DICOM files.

    LEARNING: This fuzzer combines Atheris's coverage tracking with
    DICOM-aware mutations for intelligent fuzzing of DICOM parsers.

    CONCEPT: We use Atheris for coverage feedback while applying
    domain-specific DICOM mutations to generate more effective test cases.
    """

    def __init__(self, config: AtherisConfig | None = None):
        """Initialize the Atheris DICOM fuzzer.

        Args:
            config: Fuzzing configuration. If None, uses defaults.

        Raises:
            ImportError: If Atheris is not installed.

        """
        if not HAS_ATHERIS:
            raise ImportError(
                "Atheris is not installed. Install with: pip install atheris\n"
                "Note: Atheris requires Python 3.8+ and works best on Linux."
            )

        self.config = config or AtherisConfig()
        self.stats = AtherisStats()

        # Initialize components
        self.corpus_manager = CorpusManager()
        self.crash_analyzer = CrashAnalyzer(str(self.config.crash_dir))
        self.dictionary_fuzzer = (
            DictionaryFuzzer() if self.config.use_dictionary_fuzzer else None
        )

        # Track seen crashes for deduplication
        self._crash_hashes: set[str] = set()

        # Setup directories
        self._setup_directories()

        logger.info(
            "Atheris DICOM fuzzer initialized",
            dicom_aware=self.config.dicom_aware_mutations,
            max_time=self.config.max_time_seconds,
        )

    def _setup_directories(self) -> None:
        """Create necessary directories."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.config.crash_dir.mkdir(parents=True, exist_ok=True)

        if self.config.corpus_dir:
            self.config.corpus_dir.mkdir(parents=True, exist_ok=True)

    def run(self, argv: list[str] | None = None) -> AtherisStats:
        """Run the Atheris fuzzing campaign.

        Args:
            argv: Command line arguments for Atheris. If None, uses sys.argv.

        Returns:
            Fuzzing statistics.

        """
        if argv is None:
            argv = sys.argv

        logger.info("Starting Atheris coverage-guided fuzzing")

        # Load initial corpus
        self._load_corpus()

        # Setup Atheris arguments
        atheris_argv = self._build_atheris_argv(argv)

        # Instrument target modules
        if self.config.target_modules:
            logger.debug(
                "Instrumenting imports for modules: %s",
                ", ".join(self.config.target_modules),
            )
            atheris.instrument_imports()

        # Define the test function for Atheris
        def test_one_input(data: bytes) -> None:
            """Atheris test function wrapper."""
            self._fuzz_one(data)

        # Run Atheris
        try:
            atheris.Setup(atheris_argv, test_one_input)
            atheris.Fuzz()
        except SystemExit:
            # Atheris calls sys.exit() when done
            pass
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user")

        # Finalize
        self._finalize()

        return self.stats

    def _build_atheris_argv(self, argv: list[str]) -> list[str]:
        """Build Atheris command line arguments.

        Args:
            argv: Base command line arguments.

        Returns:
            Atheris-formatted arguments.

        """
        atheris_argv = [argv[0] if argv else "atheris_fuzzer"]

        # Add corpus directory if specified
        if self.config.corpus_dir and self.config.corpus_dir.exists():
            atheris_argv.append(str(self.config.corpus_dir))

        # Add seed directory if specified
        if self.config.seed_dir and self.config.seed_dir.exists():
            atheris_argv.append(str(self.config.seed_dir))

        # Add time limit
        if self.config.max_time_seconds > 0:
            atheris_argv.append(f"-max_total_time={self.config.max_time_seconds}")

        # Add iteration limit
        if self.config.max_iterations > 0:
            atheris_argv.append(f"-runs={self.config.max_iterations}")

        # Add max input size
        atheris_argv.append(f"-max_len={self.config.max_input_size}")

        # Add timeout
        atheris_argv.append(f"-timeout={int(self.config.timeout_per_run)}")

        # Add output directory for artifacts
        atheris_argv.append(f"-artifact_prefix={self.config.crash_dir}/")

        return atheris_argv

    def _load_corpus(self) -> None:
        """Load initial corpus seeds."""
        if self.config.corpus_dir and self.config.corpus_dir.exists():
            self.corpus_manager.load_corpus(self.config.corpus_dir)
            logger.info(f"Loaded {len(self.corpus_manager.seeds)} corpus seeds")

        if self.config.seed_dir and self.config.seed_dir.exists():
            for seed_file in self.config.seed_dir.glob("*.dcm"):
                try:
                    data = seed_file.read_bytes()
                    self.corpus_manager.add_seed(data, CoverageInfo())
                except Exception as e:
                    logger.warning(f"Failed to load seed {seed_file}: {e}")

        # Create minimal seed if no corpus
        if not self.corpus_manager.seeds:
            minimal = self._create_minimal_dicom()
            self.corpus_manager.add_seed(minimal, CoverageInfo())
            logger.info("Created minimal DICOM seed")

        self.stats.corpus_size = len(self.corpus_manager.seeds)

    def _create_minimal_dicom(self) -> bytes:
        """Create a minimal valid DICOM file."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = pydicom.uid.generate_uid()

        ds.file_meta = pydicom.filereader.FileMetaDataset()
        ds.file_meta.MediaStorageSOPClassUID = pydicom.uid.UID(ds.SOPClassUID)
        ds.file_meta.MediaStorageSOPInstanceUID = pydicom.uid.UID(ds.SOPInstanceUID)
        ds.file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian

        buffer = io.BytesIO()
        pydicom.dcmwrite(buffer, ds, write_like_original=False)
        return buffer.getvalue()

    def _fuzz_one(self, data: bytes) -> None:
        """Fuzz a single input.

        Args:
            data: Input data from Atheris.

        """
        self.stats.total_executions += 1

        # Optionally apply DICOM-aware mutations
        if self.config.dicom_aware_mutations and len(data) > 132:
            data = self._apply_dicom_mutations(data)

        # Execute target
        try:
            self._execute_target(data)
        except Exception as e:
            self._handle_crash(data, e)

        # Update execution rate
        elapsed = time.time() - self.stats.start_time
        if elapsed > 0:
            self.stats.exec_per_sec = self.stats.total_executions / elapsed

    def _apply_dicom_mutations(self, data: bytes) -> bytes:
        """Apply DICOM-aware mutations to the input.

        Args:
            data: Raw input data.

        Returns:
            Mutated data.

        """
        if not self.dictionary_fuzzer:
            return data

        try:
            # Try to parse as DICOM
            ds = pydicom.dcmread(io.BytesIO(data), force=True)

            # Apply dictionary-based mutations
            mutated_ds = self.dictionary_fuzzer.mutate(
                ds, self.config.mutation_severity
            )

            # Convert back to bytes
            buffer = io.BytesIO()
            pydicom.dcmwrite(buffer, mutated_ds, write_like_original=False)
            return buffer.getvalue()

        except Exception:
            # If parsing fails, return original data
            return data

    def _execute_target(self, data: bytes) -> Any:
        """Execute the target function with the given input.

        Args:
            data: Input data.

        Returns:
            Target function result.

        """
        if self.config.target_function:
            return self.config.target_function(data)

        # Default: parse as DICOM
        ds = pydicom.dcmread(io.BytesIO(data), force=True)

        # Access attributes to trigger parsing
        _ = ds.get("PatientName", "")
        _ = ds.get("PatientID", "")

        # Try to access pixel data if present
        if hasattr(ds, "PixelData"):
            _ = ds.pixel_array

        return ds

    def _handle_crash(self, data: bytes, exception: Exception) -> None:
        """Handle a crash during execution.

        Args:
            data: Input that caused the crash.
            exception: The exception that was raised.

        """
        self.stats.total_crashes += 1

        # Compute crash hash for deduplication
        crash_hash = short_hash(data)
        tb_hash = short_hash(traceback.format_exc().encode())
        combined_hash = f"{crash_hash}_{tb_hash[:8]}"

        # Check for duplicate
        if self.config.deduplicate_crashes:
            if combined_hash in self._crash_hashes:
                return
            self._crash_hashes.add(combined_hash)

        self.stats.unique_crashes += 1

        # Save crash
        self._save_crash(data, exception, combined_hash)

        logger.warning(
            f"Crash found: {type(exception).__name__}: {str(exception)[:100]}",
            crash_hash=combined_hash,
            total_crashes=self.stats.total_crashes,
            unique_crashes=self.stats.unique_crashes,
        )

    def _save_crash(self, data: bytes, exception: Exception, crash_hash: str) -> None:
        """Save crash to disk.

        Args:
            data: Input that caused the crash.
            exception: The exception that was raised.
            crash_hash: Unique hash for this crash.

        """
        # Save input
        crash_file = self.config.crash_dir / f"crash_{crash_hash}.dcm"
        crash_file.write_bytes(data)

        # Save crash info
        info_file = self.config.crash_dir / f"crash_{crash_hash}.txt"
        info_content = [
            f"Exception: {type(exception).__name__}",
            f"Message: {exception!s}",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Input size: {len(data)} bytes",
            "",
            "Traceback:",
            traceback.format_exc(),
        ]
        info_file.write_text("\n".join(info_content))

    def _finalize(self) -> None:
        """Finalize the fuzzing campaign."""
        # Save corpus
        if self.config.corpus_dir:
            self.corpus_manager.save_corpus(self.config.corpus_dir)

        # Log final stats
        elapsed = time.time() - self.stats.start_time
        logger.info(
            "Atheris fuzzing complete",
            duration=f"{elapsed:.1f}s",
            executions=self.stats.total_executions,
            exec_per_sec=f"{self.stats.exec_per_sec:.1f}",
            crashes=self.stats.total_crashes,
            unique_crashes=self.stats.unique_crashes,
        )


class AtherisCustomMutator:
    """Custom mutator for Atheris using DICOM-aware mutations.

    LEARNING: Atheris supports custom mutators that can generate
    more intelligent inputs than random byte mutations.

    CONCEPT: By providing domain-specific mutations, we can guide
    the fuzzer to explore DICOM-specific code paths more effectively.
    """

    def __init__(self, severity: MutationSeverity = MutationSeverity.MODERATE):
        """Initialize the custom mutator.

        Args:
            severity: Mutation severity level.

        """
        self.dictionary_fuzzer = DictionaryFuzzer()
        self.severity = severity
        self._mutation_count = 0

    def mutate(self, data: bytes, max_size: int, seed: int) -> bytes:
        """Mutate input data using DICOM-aware mutations.

        This method is called by Atheris to generate new inputs.

        Args:
            data: Input data to mutate.
            max_size: Maximum allowed size for output.
            seed: Random seed for reproducibility.

        Returns:
            Mutated data.

        """
        self._mutation_count += 1

        # Try DICOM-aware mutation
        try:
            if len(data) > 132:  # Minimum DICOM size
                ds = pydicom.dcmread(io.BytesIO(data), force=True)
                mutated_ds = self.dictionary_fuzzer.mutate(ds, self.severity)

                buffer = io.BytesIO()
                pydicom.dcmwrite(buffer, mutated_ds, write_like_original=False)
                result = buffer.getvalue()

                # Ensure we don't exceed max size
                if len(result) <= max_size:
                    return result
        except Exception as dicom_err:
            # DICOM-aware mutation failed, fall back to basic mutation
            logger.debug(
                f"DICOM-aware mutation failed: {dicom_err}, using basic mutation"
            )

        # Fall back to basic mutation
        return self._basic_mutate(data, max_size, seed)

    def _basic_mutate(self, data: bytes, max_size: int, seed: int) -> bytes:
        """Apply basic byte-level mutations.

        Args:
            data: Input data.
            max_size: Maximum size.
            seed: Random seed.

        Returns:
            Mutated data.

        """
        import random

        random.seed(seed)

        if not data:
            # Create minimal DICOM header
            return b"DICM" + bytes(128)

        data_list = list(data)

        # Choose mutation type
        mutation_type = random.randint(0, 4)

        if mutation_type == 0 and len(data_list) > 1:
            # Flip random bit
            pos = random.randint(0, len(data_list) - 1)
            data_list[pos] ^= 1 << random.randint(0, 7)

        elif mutation_type == 1 and len(data_list) > 1:
            # Replace random byte
            pos = random.randint(0, len(data_list) - 1)
            data_list[pos] = random.randint(0, 255)

        elif mutation_type == 2 and len(data_list) < max_size:
            # Insert random byte
            pos = random.randint(0, len(data_list))
            data_list.insert(pos, random.randint(0, 255))

        elif mutation_type == 3 and len(data_list) > 1:
            # Delete random byte
            pos = random.randint(0, len(data_list) - 1)
            del data_list[pos]

        elif mutation_type == 4 and len(data_list) > 1:
            # Swap adjacent bytes
            pos = random.randint(0, len(data_list) - 2)
            data_list[pos], data_list[pos + 1] = data_list[pos + 1], data_list[pos]

        return bytes(data_list[:max_size])


def create_atheris_harness(
    target_function: Callable[[bytes], Any],
    corpus_dir: str | Path | None = None,
    crash_dir: str | Path | None = None,
    max_time_seconds: int = 3600,
    dicom_aware: bool = True,
) -> AtherisDICOMFuzzer:
    """Create an Atheris fuzzing harness for a target function.

    Convenience function for quick setup of Atheris fuzzing.

    Args:
        target_function: Function to fuzz. Takes bytes, returns any.
        corpus_dir: Directory for corpus seeds.
        crash_dir: Directory for crash outputs.
        max_time_seconds: Maximum fuzzing time.
        dicom_aware: Whether to use DICOM-aware mutations.

    Returns:
        Configured AtherisDICOMFuzzer instance.

    Example:
        def my_parser(data: bytes) -> Dataset:
            return pydicom.dcmread(io.BytesIO(data))

        fuzzer = create_atheris_harness(my_parser, corpus_dir="corpus")
        fuzzer.run()

    """
    config = AtherisConfig(
        target_function=target_function,
        corpus_dir=Path(corpus_dir) if corpus_dir else None,
        crash_dir=Path(crash_dir) if crash_dir else Path("atheris_crashes"),
        max_time_seconds=max_time_seconds,
        dicom_aware_mutations=dicom_aware,
    )

    return AtherisDICOMFuzzer(config)


def fuzz_dicom_parser(
    parser_func: Callable[[bytes], Any] | None = None,
    argv: list[str] | None = None,
) -> None:
    """Run Atheris fuzzing on a DICOM parser function.

    Simple entry point for fuzzing DICOM parsers.

    Args:
        parser_func: Parser function to fuzz. If None, uses pydicom.dcmread.
        argv: Command line arguments. If None, uses sys.argv.

    Example:
        # Fuzz the default pydicom parser
        fuzz_dicom_parser()

        # Fuzz a custom parser
        def my_parser(data):
            ds = pydicom.dcmread(io.BytesIO(data))
            # Custom processing...
            return ds

        fuzz_dicom_parser(my_parser)

    """
    if not HAS_ATHERIS:
        logger.error("Atheris is not installed. Install with: pip install atheris")
        return

    def default_parser(data: bytes) -> Dataset:
        """Default DICOM parser using pydicom."""
        return pydicom.dcmread(io.BytesIO(data), force=True)

    target = parser_func or default_parser

    config = AtherisConfig(
        target_function=target,
        corpus_dir=Path("dicom_corpus"),
        crash_dir=Path("dicom_crashes"),
    )

    fuzzer = AtherisDICOMFuzzer(config)
    fuzzer.run(argv)


# Export public API
__all__ = [
    "HAS_ATHERIS",
    "AtherisConfig",
    "AtherisStats",
    "AtherisDICOMFuzzer",
    "AtherisCustomMutator",
    "create_atheris_harness",
    "fuzz_dicom_parser",
]
