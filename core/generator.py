import random
import struct
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from core.parser import DicomParser
from strategies.header_fuzzer import HeaderFuzzer
from strategies.metadata_fuzzer import MetadataFuzzer
from strategies.pixel_fuzzer import PixelFuzzer
from strategies.structure_fuzzer import StructureFuzzer


class GenerationStats:
    """Track statistics during file generation."""

    def __init__(self):
        self.total_attempted = 0
        self.successful = 0
        self.failed = 0
        self.skipped_due_to_write_errors = 0
        self.strategies_used: Dict[str, int] = {}
        self.error_types: Dict[str, int] = {}

    def record_success(self, strategies: List[str]):
        """Record successful file generation."""
        self.successful += 1
        for strategy in strategies:
            self.strategies_used[strategy] = self.strategies_used.get(strategy, 0) + 1

    def record_failure(self, error_type: str):
        """Record failed file generation."""
        self.failed += 1
        self.error_types[error_type] = self.error_types.get(error_type, 0) + 1


class DICOMGenerator:
    """
    Generates batches of fuzzed DICOM files for security testing.

    CONCEPT: Coordinates multiple fuzzing strategies to create
    a diverse set of test cases that stress different aspects
    of DICOM parsers.
    """

    def __init__(self, output_dir="./fuzzed_dicoms", skip_write_errors=True):
        """
        Initialize the generator.

        Args:
            output_dir: Directory to save generated files
            skip_write_errors: If True, skip files that can't be written due to
                             invalid mutations (good for fuzzing). If False,
                             raise errors (good for debugging).
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.skip_write_errors = skip_write_errors
        self.stats = GenerationStats()

    def generate_batch(
        self,
        original_file: str,
        count: int = 100,
        strategies: Optional[List[str]] = None,
    ) -> List[Path]:
        """
        Generate a batch of mutated DICOM files.

        Args:
            original_file: Path to original DICOM file
            count: Number of files to generate
            strategies: List of strategy names to use (None = all)
                       Valid: 'metadata', 'header', 'pixel', 'structure'

        Returns:
            List of paths to generated files
        """
        parser = DicomParser(original_file)
        base_dataset = parser.dataset

        # Create all available fuzzers
        all_fuzzers = {
            "metadata": MetadataFuzzer(),
            "header": HeaderFuzzer(),
            "pixel": PixelFuzzer(),
            "structure": StructureFuzzer(),
        }

        # Select fuzzers based on strategies parameter
        if strategies is None:
            # Use all fuzzers (except structure by default for compatibility)
            active_fuzzers = {
                "metadata": all_fuzzers["metadata"],
                "header": all_fuzzers["header"],
                "pixel": all_fuzzers["pixel"],
            }
        else:
            # Use only specified strategies
            active_fuzzers = {
                name: fuzzer
                for name, fuzzer in all_fuzzers.items()
                if name in strategies
            }

        generated_files = []
        self.stats = GenerationStats()

        for i in range(count):
            self.stats.total_attempted += 1

            # Create a copy for mutation
            mutated_dataset = base_dataset.copy()

            # Randomly select which fuzzers to apply (70% chance each)
            fuzzers_to_apply = []
            for name, fuzzer in active_fuzzers.items():
                if random.random() > 0.3:
                    fuzzers_to_apply.append((name, fuzzer))

            # Track which strategies were used
            strategies_applied = [name for name, _ in fuzzers_to_apply]

            # Apply selected mutations (with error handling for extreme mutations)
            mutation_failed = False
            try:
                for fuzzer_type, fuzzer in fuzzers_to_apply:
                    if fuzzer_type == "metadata":
                        mutated_dataset = fuzzer.mutate_patient_info(mutated_dataset)
                    elif fuzzer_type == "header":
                        mutated_dataset = fuzzer.mutate_tags(mutated_dataset)
                    elif fuzzer_type == "pixel":
                        mutated_dataset = fuzzer.mutate_pixels(mutated_dataset)
                    elif fuzzer_type == "structure":
                        mutated_dataset = fuzzer.mutate_structure(mutated_dataset)
            except (ValueError, TypeError, AttributeError) as e:
                # Mutation created invalid values that can't even be assigned
                if self.skip_write_errors:
                    self.stats.skipped_due_to_write_errors += 1
                    mutation_failed = True
                else:
                    self.stats.record_failure(type(e).__name__)
                    raise

            # Skip file generation if mutation failed
            if mutation_failed:
                continue

            # Generate unique filename
            filename = f"fuzzed_{uuid.uuid4().hex[:8]}.dcm"
            output_path = self.output_dir / filename

            # Save mutated file with error handling
            try:
                # Use enforce_file_format (new parameter)
                mutated_dataset.save_as(output_path, enforce_file_format=False)
                generated_files.append(output_path)
                self.stats.record_success(strategies_applied)
            except (
                OSError,
                struct.error,
                ValueError,
                TypeError,
                AttributeError,
            ) as e:
                # These errors indicate the mutation created values
                # pydicom can't write - desired fuzzing behavior!
                if self.skip_write_errors:
                    self.stats.skipped_due_to_write_errors += 1
                    # Continue to next iteration to reach desired count
                    continue
                else:
                    # Re-raise if we want to see these errors
                    self.stats.record_failure(type(e).__name__)
                    raise
            except Exception as e:
                # Unexpected errors should always be raised
                self.stats.record_failure(type(e).__name__)
                raise

        return generated_files
