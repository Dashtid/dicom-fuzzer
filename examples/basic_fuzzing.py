#!/usr/bin/env python3
"""Example: Basic DICOM File Fuzzing

This example demonstrates basic file-based fuzzing of DICOM files.
"""

from pathlib import Path

from dicom_fuzzer.core.fuzzer import DICOMFuzzer
from dicom_fuzzer.core.mutation import MutationEngine

# Configuration
INPUT_FILE = Path("./samples/sample.dcm")
OUTPUT_DIR = Path("./output/basic_fuzz")
FUZZ_COUNT = 100


def main() -> None:
    """Run basic fuzzing example."""
    print("=" * 60)
    print("  DICOM Fuzzer - Basic Fuzzing Example")
    print("=" * 60)

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Create mutation engine with all strategies
    mutation_engine = MutationEngine(
        strategies=["metadata", "header", "pixel", "structure"]
    )

    # Create fuzzer instance
    fuzzer = DICOMFuzzer(
        mutation_engine=mutation_engine,
        output_dir=OUTPUT_DIR,
    )

    print(f"\n[i] Input file: {INPUT_FILE}")
    print(f"[i] Output directory: {OUTPUT_DIR}")
    print(f"[i] Generating {FUZZ_COUNT} fuzzed variants...")

    # Generate fuzzed files
    if INPUT_FILE.exists():
        results = fuzzer.fuzz_file(INPUT_FILE, count=FUZZ_COUNT)
        print(f"\n[+] Generated {len(results)} fuzzed files")

        # Show first few results
        for result in results[:5]:
            print(f"    - {result.name}")
        if len(results) > 5:
            print(f"    ... and {len(results) - 5} more")
    else:
        print(f"[-] Input file not found: {INPUT_FILE}")
        print("[i] Generate samples first: dicom-fuzzer samples --generate")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
