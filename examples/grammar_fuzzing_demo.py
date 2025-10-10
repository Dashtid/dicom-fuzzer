"""
Grammar-Based Fuzzing Demo

This example demonstrates how to use grammar-based fuzzing to generate
structurally valid but semantically interesting DICOM files.

Grammar-based fuzzing is particularly effective because it:
- Generates inputs that are more likely to pass parsing
- Focuses fuzzing on semantic logic rather than format parsing
- Can create complex nested structures efficiently
- Produces diverse test cases based on grammar rules
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.core.grammar_fuzzer import GrammarFuzzer
from dicom_fuzzer.core.parser import DicomParser


def main():
    """Run grammar-based fuzzing demonstration."""

    print("=" * 70)
    print("Grammar-Based Fuzzing Demonstration")
    print("=" * 70)
    print()
    print("This demo shows how to generate DICOM files using grammar rules")
    print("to create structurally valid but diverse test cases.")
    print()

    # Initialize grammar fuzzer
    print("Initializing grammar-based fuzzer...")
    fuzzer = GrammarFuzzer()

    # Generate some DICOM files
    print("Generating DICOM test files...")
    print()

    num_files = 10
    output_dir = Path("grammar_generated")
    output_dir.mkdir(exist_ok=True)

    for i in range(num_files):
        print(f"Generating file {i+1}/{num_files}...", end=" ")

        try:
            # Generate a DICOM file using grammar
            dicom_bytes = fuzzer.generate_dicom()

            # Save the generated file
            output_file = output_dir / f"generated_{i:03d}.dcm"
            output_file.write_bytes(dicom_bytes)

            # Try to parse it to verify it's valid
            parser = DicomParser()
            dataset = parser.parse(dicom_bytes)

            print(f"[OK] - {len(dicom_bytes)} bytes, parsed successfully")

            # Show some properties
            if hasattr(dataset, 'PatientName'):
                print(f"       PatientName: {dataset.PatientName}")
            if hasattr(dataset, 'Modality'):
                print(f"       Modality: {dataset.Modality}")

        except Exception as e:
            print(f"[FAIL] - {type(e).__name__}: {e}")

    print()
    print(f"Generated {num_files} DICOM files in '{output_dir}'")
    print()
    print("Grammar-based fuzzing is excellent for:")
    print("  - Creating diverse, structurally valid inputs")
    print("  - Testing semantic logic rather than parsing")
    print("  - Generating complex nested structures")
    print("  - Exploring the input space systematically")
    print()
    print("Demo complete!")


if __name__ == "__main__":
    main()
