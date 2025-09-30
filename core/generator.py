import random
import uuid
from pathlib import Path

from core.parser import DICOMParser
from strategies.header_fuzzer import HeaderFuzzer
from strategies.metadata_fuzzer import MetadataFuzzer
from strategies.pixel_fuzzer import PixelFuzzer


class DICOMGenerator:
    def __init__(self, output_dir="./fuzzed_dicoms"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_batch(self, original_file, count=100):
        """Generate a batch of mutated DICOM files"""
        parser = DICOMParser(original_file)
        base_dataset = parser.dataset

        fuzzers = [MetadataFuzzer(), HeaderFuzzer(), PixelFuzzer()]

        generated_files = []

        for i in range(count):
            # Create a copy for mutation
            mutated_dataset = base_dataset.copy()

            # Apply random mutations
            for fuzzer in random.sample(fuzzers, k=random.randint(1, len(fuzzers))):
                mutated_dataset = fuzzer.mutate(mutated_dataset)

            # Generate unique filename
            filename = f"fuzzed_{uuid.uuid4().hex[:8]}.dcm"
            output_path = self.output_dir / filename

            # Save mutated file
            mutated_dataset.save_as(output_path)
            generated_files.append(output_path)

        return generated_files
