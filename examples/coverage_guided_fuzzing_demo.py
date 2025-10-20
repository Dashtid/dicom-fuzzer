"""
Coverage-Guided Fuzzing Demo

This example demonstrates how to use the advanced coverage-guided fuzzer
to find bugs in DICOM processing code with maximum efficiency.

The coverage-guided fuzzer automatically:
- Tracks which code paths are executed
- Prioritizes inputs that discover new code paths
- Adaptively mutates inputs based on coverage feedback
- Manages a corpus of interesting test cases
- Minimizes crashes for easier debugging
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.core.coverage_guided_fuzzer import CoverageGuidedFuzzer, FuzzingConfig
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.validator import DICOMValidator


def target_function(dicom_data: bytes) -> bool:
    """
    Target function that processes DICOM data.

    This is the function we want to fuzz. The fuzzer will automatically
    try different inputs and track which code paths are executed.

    Args:
        dicom_data: Raw DICOM file data

    Returns:
        True if processing succeeded, False otherwise
    """
    try:
        # Parse DICOM data
        parser = DicomParser()
        dataset = parser.parse(dicom_data)

        # Validate the dataset
        validator = DICOMValidator()
        is_valid = validator.validate(dataset)

        # Extract some metadata
        if hasattr(dataset, 'PatientName'):
            patient_name = str(dataset.PatientName)

        if hasattr(dataset, 'StudyDate'):
            study_date = str(dataset.StudyDate)

        return True

    except Exception:
        # The fuzzer will catch crashes and save them for analysis
        raise


def main():
    """Run coverage-guided fuzzing demonstration."""

    print("="* 70)
    print("Coverage-Guided Fuzzing Demonstration")
    print("="* 70)
    print()
    print("This demo shows how to use advanced coverage-guided fuzzing")
    print("to automatically find bugs in DICOM processing code.")
    print()

    # Create fuzzing configuration
    config = FuzzingConfig(
        # Target configuration
        target_function=target_function,
        target_modules=['core.parser', 'core.validator'],  # Track coverage in these modules

        # Fuzzing parameters
        max_iterations=1000,  # Run 1000 fuzzing iterations
        timeout_per_run=1.0,  # 1 second timeout per test
        num_workers=4,  # Use 4 parallel workers

        # Coverage parameters
        coverage_guided=True,  # Enable coverage-guided mode
        track_branches=True,  # Track branch coverage
        minimize_corpus=True,  # Minimize corpus automatically

        # Corpus parameters
        seed_dir=Path("test_data/valid_dicoms"),  # Initial seed files
        max_corpus_size=500,  # Keep up to 500 interesting inputs

        # Mutation parameters
        max_mutations=10,  # Up to 10 mutations per input
        adaptive_mutations=True,  # Adapt mutations based on feedback
        dicom_aware=True,  # Use DICOM-specific mutations

        # Output configuration
        output_dir=Path("fuzzing_results"),
        crash_dir=Path("crashes"),
        save_interesting=True,  # Save inputs that find new coverage

        # Reporting
        report_interval=100,  # Report stats every 100 iterations
        verbose=True,
    )

    print("Configuration:")
    print(f"  - Max iterations: {config.max_iterations}")
    print(f"  - Workers: {config.num_workers}")
    print(f"  - Coverage-guided: {config.coverage_guided}")
    print(f"  - DICOM-aware mutations: {config.dicom_aware}")
    print()

    # Create the fuzzer
    print("Initializing coverage-guided fuzzer...")
    fuzzer = CoverageGuidedFuzzer(config)

    # Start fuzzing
    print("Starting fuzzing campaign...")
    print("Press Ctrl+C to stop")
    print()

    try:
        stats = fuzzer.run()

        # Print final statistics
        print()
        print("="* 70)
        print("Fuzzing Campaign Complete!")
        print("="* 70)
        print(f"Total executions: {stats.total_executions}")
        print(f"Executions/sec: {stats.exec_per_sec:.2f}")
        print(f"Total crashes: {stats.total_crashes}")
        print(f"Unique crashes: {stats.unique_crashes}")
        print(f"Coverage increases: {stats.coverage_increases}")
        print(f"Final coverage: {stats.current_coverage} lines")
        print(f"Corpus size: {stats.corpus_size}")
        print()

        if stats.total_crashes > 0:
            print(f"Found {stats.unique_crashes} unique crashes!")
            print(f"Check the '{config.crash_dir}' directory for crash files.")
        else:
            print("No crashes found. Consider running longer or with more seeds.")

    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
        print("Saving current state...")
        fuzzer.stop()

    print()
    print("Demo complete!")


if __name__ == "__main__":
    main()
