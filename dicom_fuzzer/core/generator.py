import random
import struct
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.strategies.header_fuzzer import HeaderFuzzer
from dicom_fuzzer.strategies.metadata_fuzzer import MetadataFuzzer
from dicom_fuzzer.strategies.pixel_fuzzer import PixelFuzzer
from dicom_fuzzer.strategies.structure_fuzzer import StructureFuzzer


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
        active_fuzzers = self._select_fuzzers(strategies)

        generated_files = []
        self.stats = GenerationStats()

        for i in range(count):
            result = self._generate_single_file(base_dataset, active_fuzzers)
            if result is not None:
                generated_files.append(result)

        return generated_files

    def _select_fuzzers(self, strategies: Optional[List[str]]) -> dict:
        """Select fuzzers based on strategy names."""
        all_fuzzers = {
            "metadata": MetadataFuzzer(),
            "header": HeaderFuzzer(),
            "pixel": PixelFuzzer(),
            "structure": StructureFuzzer(),
        }

        if strategies is None:
            # Use all fuzzers (except structure by default for compatibility)
            return {
                "metadata": all_fuzzers["metadata"],
                "header": all_fuzzers["header"],
                "pixel": all_fuzzers["pixel"],
            }

        # Use only specified strategies
        return {
            name: fuzzer for name, fuzzer in all_fuzzers.items() if name in strategies
        }

    def _generate_single_file(self, base_dataset, active_fuzzers) -> Optional[Path]:
        """Generate a single fuzzed file. Returns None if generation fails."""
        self.stats.total_attempted += 1

        # Create mutated dataset
        mutated_dataset, strategies_applied = self._apply_mutations(
            base_dataset, active_fuzzers
        )
        if mutated_dataset is None:
            return None

        # Save to file
        return self._save_mutated_file(mutated_dataset, strategies_applied)

    def _apply_mutations(self, base_dataset, active_fuzzers):
        """Apply random mutations to dataset.

        Returns (dataset, strategies) or (None, []).
        """
        mutated_dataset = base_dataset.copy()

        # Randomly select fuzzers (70% chance each)
        fuzzers_to_apply = [
            (name, fuzzer)
            for name, fuzzer in active_fuzzers.items()
            if random.random() > 0.3
        ]

        strategies_applied = [name for name, _ in fuzzers_to_apply]

        # Apply mutations
        try:
            for fuzzer_type, fuzzer in fuzzers_to_apply:
                mutated_dataset = self._apply_single_fuzzer(
                    fuzzer_type, fuzzer, mutated_dataset
                )
        except (ValueError, TypeError, AttributeError) as e:
            return self._handle_mutation_error(e)

        return mutated_dataset, strategies_applied

    def _apply_single_fuzzer(self, fuzzer_type: str, fuzzer, dataset):
        """Apply a single fuzzer to the dataset."""
        fuzzer_methods = {
            "metadata": lambda: fuzzer.mutate_patient_info(dataset),
            "header": lambda: fuzzer.mutate_tags(dataset),
            "pixel": lambda: fuzzer.mutate_pixels(dataset),
            "structure": lambda: fuzzer.mutate_structure(dataset),
        }
        return fuzzer_methods.get(fuzzer_type, lambda: dataset)()

    def _handle_mutation_error(self, error):
        """Handle errors during mutation."""
        if self.skip_write_errors:
            self.stats.skipped_due_to_write_errors += 1
            return None, []

        self.stats.record_failure(type(error).__name__)
        raise

    def _save_mutated_file(
        self, mutated_dataset, strategies_applied: List[str]
    ) -> Optional[Path]:
        """Save mutated dataset to file. Returns path or None on error."""
        filename = f"fuzzed_{uuid.uuid4().hex[:8]}.dcm"
        output_path = self.output_dir / filename

        try:
            mutated_dataset.save_as(output_path, enforce_file_format=False)
            self.stats.record_success(strategies_applied)
            return output_path
        except (OSError, struct.error, ValueError, TypeError, AttributeError) as e:
            return self._handle_save_error(e)
        except Exception as e:
            self.stats.record_failure(type(e).__name__)
            raise

    def _handle_save_error(self, error):
        """Handle errors when saving files."""
        if self.skip_write_errors:
            self.stats.skipped_due_to_write_errors += 1
            return None

        self.stats.record_failure(type(error).__name__)
        raise
