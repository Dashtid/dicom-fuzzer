#!/usr/bin/env python3
"""
Example: Coverage-Guided Fuzzing for DICOM Parser

This example demonstrates how to use the coverage-guided fuzzer
to test a DICOM parser for vulnerabilities.
"""

import sys
from pathlib import Path
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pydicom
from pydicom.errors import InvalidDicomError
from io import BytesIO

from core.coverage_guided_fuzzer import CoverageGuidedFuzzer, FuzzingConfig
from core.coverage_instrumentation import configure_global_tracker


def vulnerable_dicom_parser(data: bytes) -> bool:
    """
    Example DICOM parser with intentional vulnerabilities for demonstration.

    This parser has several issues that the fuzzer should find:
    1. Buffer overflow when patient name is too long
    2. Integer overflow in pixel data handling
    3. Crash on malformed transfer syntax
    4. Stack overflow with deeply nested sequences
    """
    try:
        # Parse DICOM
        ds = pydicom.dcmread(BytesIO(data), force=True)

        # Vulnerability 1: Buffer overflow with long patient name
        if hasattr(ds, 'PatientName'):
            patient_name = str(ds.PatientName)
            if len(patient_name) > 1000:
                # Simulate buffer overflow
                raise MemoryError("Buffer overflow in patient name")

        # Vulnerability 2: Integer overflow in dimensions
        if hasattr(ds, 'Rows') and hasattr(ds, 'Columns'):
            try:
                total_pixels = int(ds.Rows) * int(ds.Columns)
                if total_pixels > 2**31:
                    raise OverflowError("Integer overflow in image dimensions")
            except (ValueError, TypeError):
                pass

        # Vulnerability 3: Crash on specific transfer syntax
        if hasattr(ds, 'file_meta') and hasattr(ds.file_meta, 'TransferSyntaxUID'):
            if 'INVALID' in str(ds.file_meta.TransferSyntaxUID):
                raise ValueError("Invalid transfer syntax causes crash")

        # Vulnerability 4: Stack overflow with nested sequences
        def count_sequence_depth(elem, depth=0):
            if depth > 50:  # Too deep
                raise RecursionError("Stack overflow in sequence parsing")

            if hasattr(elem, 'value') and isinstance(elem.value, list):
                for item in elem.value:
                    if hasattr(item, '__iter__'):
                        count_sequence_depth(item, depth + 1)

        for elem in ds:
            if elem.VR == 'SQ':
                count_sequence_depth(elem)

        # Vulnerability 5: Division by zero in pixel spacing
        if hasattr(ds, 'PixelSpacing'):
            try:
                spacing = ds.PixelSpacing
                if len(spacing) >= 2:
                    ratio = float(spacing[0]) / float(spacing[1])
            except (ZeroDivisionError, ValueError, TypeError):
                raise ZeroDivisionError("Division by zero in pixel spacing")

        return True

    except InvalidDicomError:
        # Normal DICOM parsing error
        return False

    except (MemoryError, OverflowError, ValueError, RecursionError, ZeroDivisionError) as e:
        # These are our "vulnerabilities" - the fuzzer should find these
        print(f"[VULNERABILITY FOUND] {type(e).__name__}: {e}")
        raise

    except Exception as e:
        # Other unexpected errors
        return False


def create_example_config() -> FuzzingConfig:
    """Create configuration for the example."""
    return FuzzingConfig(
        # Target our vulnerable parser
        target_function=vulnerable_dicom_parser,
        target_modules=['__main__', 'pydicom'],  # Track coverage in these modules

        # Fuzzing parameters
        max_iterations=1000,
        timeout_per_run=0.5,
        num_workers=1,

        # Coverage settings
        coverage_guided=True,
        track_branches=True,
        minimize_corpus=True,

        # Corpus settings
        corpus_dir=Path("example_corpus"),
        max_corpus_size=100,

        # Mutation settings
        max_mutations=5,
        adaptive_mutations=True,
        dicom_aware=True,  # Enable DICOM-specific mutations

        # Output settings
        output_dir=Path("example_output"),
        crash_dir=Path("example_crashes"),
        save_interesting=True,
        report_interval=50,
        verbose=True
    )


async def run_example():
    """Run the coverage-guided fuzzing example."""
    print("=" * 60)
    print("Coverage-Guided Fuzzing Example for DICOM Parser")
    print("=" * 60)
    print()
    print("This example demonstrates finding vulnerabilities in a")
    print("DICOM parser using coverage-guided fuzzing.")
    print()
    print("The parser has several intentional vulnerabilities:")
    print("1. Buffer overflow with long patient names")
    print("2. Integer overflow in pixel dimensions")
    print("3. Crash on malformed transfer syntax")
    print("4. Stack overflow with nested sequences")
    print("5. Division by zero in pixel spacing")
    print()
    print("The fuzzer will try to find these issues automatically")
    print("by generating mutated DICOM files and tracking coverage.")
    print()
    print("-" * 60)

    # Configure coverage tracking
    configure_global_tracker({'__main__', 'pydicom'})

    # Create fuzzer
    config = create_example_config()
    fuzzer = CoverageGuidedFuzzer(config)

    # Run fuzzing
    print("\nStarting fuzzing campaign...")
    print(f"Max iterations: {config.max_iterations}")
    print(f"Output directory: {config.output_dir}")
    print(f"Crash directory: {config.crash_dir}")
    print()

    try:
        stats = await fuzzer.run()

        # Print results
        print("\n" + "=" * 60)
        print("Fuzzing Results")
        print("=" * 60)
        print(f"Total executions: {stats.total_executions:,}")
        print(f"Unique crashes found: {stats.unique_crashes}")
        print(f"Total crashes: {stats.total_crashes}")
        print(f"Coverage achieved: {stats.max_coverage} edges")
        print(f"Corpus size: {stats.corpus_size}")
        print(f"Exec/sec: {stats.exec_per_sec:.1f}")

        # Show mutation effectiveness
        if stats.mutation_stats:
            print("\nTop Effective Mutations:")
            sorted_mutations = sorted(
                stats.mutation_stats.items(),
                key=lambda x: x[1].get('success_rate', 0),
                reverse=True
            )
            for mutation, data in sorted_mutations[:5]:
                print(f"  {mutation}: {data['success_rate']:.2%} success rate")

        print("\nCheck the following directories for results:")
        print(f"  Crashes: {config.crash_dir}")
        print(f"  Corpus: {config.corpus_dir}")
        print(f"  Coverage: {config.output_dir}/coverage.json")

    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")

    except Exception as e:
        print(f"\nError during fuzzing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_example())