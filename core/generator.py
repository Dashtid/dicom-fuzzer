import random
import uuid
from pathlib import Path
from typing import List, Optional

from core.parser import DicomParser
from strategies.header_fuzzer import HeaderFuzzer
from strategies.metadata_fuzzer import MetadataFuzzer
from strategies.pixel_fuzzer import PixelFuzzer
from strategies.structure_fuzzer import StructureFuzzer


class DICOMGenerator:
    """
    Generates batches of fuzzed DICOM files for security testing.

    CONCEPT: Coordinates multiple fuzzing strategies to create
    a diverse set of test cases that stress different aspects
    of DICOM parsers.
    """

    def __init__(self, output_dir="./fuzzed_dicoms"):
        """
        Initialize the generator.

        Args:
            output_dir: Directory to save generated files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

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

        for i in range(count):
            # Create a copy for mutation
            mutated_dataset = base_dataset.copy()

            # Randomly select which fuzzers to apply (70% chance each)
            fuzzers_to_apply = []
            for name, fuzzer in active_fuzzers.items():
                if random.random() > 0.3:
                    fuzzers_to_apply.append((name, fuzzer))

            # Apply selected mutations
            for fuzzer_type, fuzzer in fuzzers_to_apply:
                if fuzzer_type == "metadata":
                    mutated_dataset = fuzzer.mutate_patient_info(mutated_dataset)
                elif fuzzer_type == "header":
                    mutated_dataset = fuzzer.mutate_tags(mutated_dataset)
                elif fuzzer_type == "pixel":
                    mutated_dataset = fuzzer.mutate_pixels(mutated_dataset)
                elif fuzzer_type == "structure":
                    mutated_dataset = fuzzer.mutate_structure(mutated_dataset)

            # Generate unique filename
            filename = f"fuzzed_{uuid.uuid4().hex[:8]}.dcm"
            output_path = self.output_dir / filename

            # Save mutated file
            mutated_dataset.save_as(output_path)
            generated_files.append(output_path)

        return generated_files
