import random
import uuid
from pathlib import Path

from core.parser import DicomParser
from strategies.header_fuzzer import HeaderFuzzer
from strategies.metadata_fuzzer import MetadataFuzzer
from strategies.pixel_fuzzer import PixelFuzzer


class DICOMGenerator:
    def __init__(self, output_dir="./fuzzed_dicoms"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_batch(self, original_file, count=100):
        """Generate a batch of mutated DICOM files"""
        parser = DicomParser(original_file)
        base_dataset = parser.dataset

        # Create fuzzers with their specific mutation methods
        metadata_fuzzer = MetadataFuzzer()
        header_fuzzer = HeaderFuzzer()
        pixel_fuzzer = PixelFuzzer()

        generated_files = []

        for i in range(count):
            # Create a copy for mutation
            mutated_dataset = base_dataset.copy()

            # Randomly select which fuzzers to apply
            fuzzers_to_apply = []
            if random.random() > 0.3:
                fuzzers_to_apply.append(("metadata", metadata_fuzzer))
            if random.random() > 0.3:
                fuzzers_to_apply.append(("header", header_fuzzer))
            if random.random() > 0.3:
                fuzzers_to_apply.append(("pixel", pixel_fuzzer))

            # Apply selected mutations
            for fuzzer_type, fuzzer in fuzzers_to_apply:
                if fuzzer_type == "metadata":
                    mutated_dataset = fuzzer.mutate_patient_info(mutated_dataset)
                elif fuzzer_type == "header":
                    mutated_dataset = fuzzer.mutate_tags(mutated_dataset)
                elif fuzzer_type == "pixel":
                    mutated_dataset = fuzzer.mutate_pixels(mutated_dataset)

            # Generate unique filename
            filename = f"fuzzed_{uuid.uuid4().hex[:8]}.dcm"
            output_path = self.output_dir / filename

            # Save mutated file
            mutated_dataset.save_as(output_path)
            generated_files.append(output_path)

        return generated_files
