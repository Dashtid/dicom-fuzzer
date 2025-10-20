#!/usr/bin/env python3
"""
Demo: Dictionary-Based DICOM Fuzzing

This example demonstrates how to use intelligent, dictionary-based fuzzing
to generate test cases that bypass input validation and reach deeper code paths.

CONCEPT: Instead of random bit flips, we use domain knowledge (DICOM dictionaries)
to create valid-looking but malicious test cases.
"""

from pydicom.dataset import Dataset

from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.strategies.dictionary_fuzzer import DictionaryFuzzer


def create_sample_dataset() -> Dataset:
    """Create a sample DICOM dataset for demonstration."""
    ds = Dataset()

    # Patient Information
    ds.PatientName = "Doe^John"
    ds.PatientID = "12345"
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "M"

    # Study Information
    ds.StudyInstanceUID = "1.2.840.113619.2.55.3.12345"
    ds.StudyDate = "20240101"
    ds.StudyTime = "120000"
    ds.StudyDescription = "CT Chest"

    # Series Information
    ds.SeriesInstanceUID = "1.2.840.113619.2.55.3.12345.1"
    ds.Modality = "CT"
    ds.SeriesNumber = "1"

    # Image Information
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    ds.SOPInstanceUID = "1.2.840.113619.2.55.3.12345.1.1"

    return ds


def demo_basic_dictionary_fuzzing():
    """Demo 1: Basic dictionary-based mutations."""
    print("=" * 70)
    print("DEMO 1: Basic Dictionary-Based Fuzzing")
    print("=" * 70)

    original_ds = create_sample_dataset()
    fuzzer = DictionaryFuzzer()

    print("\nOriginal Dataset:")
    print(f"  Patient Name: {original_ds.PatientName}")
    print(f"  Patient ID: {original_ds.PatientID}")
    print(f"  Modality: {original_ds.Modality}")
    print(f"  Study Description: {original_ds.StudyDescription}")

    # Apply mutations at different severity levels
    for severity in [
        MutationSeverity.MINIMAL,
        MutationSeverity.MODERATE,
        MutationSeverity.AGGRESSIVE,
    ]:
        try:
            mutated_ds = fuzzer.mutate(original_ds, severity)
            print(f"\nMutated Dataset ({severity.value}):")
            print(f"  Patient Name: {mutated_ds.PatientName}")
            print(f"  Patient ID: {mutated_ds.PatientID}")
            print(f"  Modality: {mutated_ds.Modality}")
            if hasattr(mutated_ds, "StudyDescription"):
                print(f"  Study Description: {mutated_ds.StudyDescription}")
        except Exception as e:
            print(f"\nError during {severity.value} mutation: {e}")


def demo_systematic_edge_cases():
    """Demo 2: Systematic edge case injection."""
    print("\n" + "=" * 70)
    print("DEMO 2: Systematic Edge Case Injection")
    print("=" * 70)

    original_ds = create_sample_dataset()
    fuzzer = DictionaryFuzzer()

    # Try different edge case categories
    edge_case_categories = ["empty", "null_bytes", "very_long"]

    for category in edge_case_categories:
        print(f"\nInjecting {category} edge cases...")
        mutated_datasets = fuzzer.inject_edge_cases_systematically(
            original_ds, category
        )
        print(f"  Generated {len(mutated_datasets)} test cases")

        # Show first example
        if mutated_datasets:
            ds = mutated_datasets[0]
            if hasattr(ds, "PatientName"):
                name_val = str(ds.PatientName)
                if category == "very_long":
                    print(f"  Example: PatientName = '{name_val[:50]}...' length")
                    print(f"  (length: {len(name_val)})")
                elif category == "null_bytes":
                    print("  Example: PatientName contains null byte")
                    print(f"  (repr: {repr(name_val)})")
                else:
                    print(f"  Example: PatientName = '{name_val}'")


def demo_mutator_integration():
    """Demo 3: Integration with DICOM Mutator."""
    print("\n" + "=" * 70)
    print("DEMO 3: Mutator Integration (Auto-Registered Dictionary Fuzzer)")
    print("=" * 70)

    original_ds = create_sample_dataset()

    # Create mutator with auto-registration (includes dictionary fuzzer)
    mutator = DicomMutator({"auto_register_strategies": True})

    print(f"\nRegistered strategies: {len(mutator.strategies)}")
    for strategy in mutator.strategies:
        print(f"  - {strategy.get_strategy_name()}")

    # Start fuzzing session
    mutator.start_session(original_ds)

    # Apply dictionary-based mutations
    mutated_ds = mutator.apply_mutations(
        original_ds,
        num_mutations=3,
        severity=MutationSeverity.MODERATE,
        strategy_names=["dictionary"],  # Use only dictionary fuzzer
    )

    print("\nOriginal vs Mutated:")
    print(f"  Patient Name: '{original_ds.PatientName}' -> '{mutated_ds.PatientName}'")
    print(f"  Modality: '{original_ds.Modality}' -> '{mutated_ds.Modality}'")

    # Get session summary
    summary = mutator.get_session_summary()
    if summary:
        print("\nSession Summary:")
        print(f"  Mutations Applied: {summary['mutations_applied']}")
        print(f"  Successful: {summary['successful_mutations']}")
        print(f"  Strategies Used: {', '.join(summary['strategies_used'])}")

    mutator.end_session()


def demo_specific_dictionary():
    """Demo 4: Using specific dictionaries for targeted fuzzing."""
    print("\n" + "=" * 70)
    print("DEMO 4: Targeted Fuzzing with Specific Dictionaries")
    print("=" * 70)

    original_ds = create_sample_dataset()
    fuzzer = DictionaryFuzzer()

    # Show applicable tags and their dictionaries
    applicable_tags = fuzzer.get_applicable_tags(original_ds)
    print("\nTags with specific dictionaries:")
    for tag, dict_name in applicable_tags[:5]:  # Show first 5
        print(f"  Tag {tag:08X}: {dict_name}")

    # Mutate specific tag with specific dictionary
    print("\nMutating Modality tag with modalities dictionary...")
    mutated_ds = fuzzer.mutate_with_specific_dictionary(
        original_ds, 0x00080060, "modalities"  # Modality tag
    )

    print(f"  Original: {original_ds.Modality}")
    print(f"  Mutated: {mutated_ds.Modality}")


def main():
    """Run all dictionary fuzzing demos."""
    print("\n" + "=" * 70)
    print("Dictionary-Based DICOM Fuzzing Demonstration")
    print("=" * 70)
    print("\nThis demo shows how intelligent, domain-aware fuzzing can generate")
    print("test cases that bypass validation and reach deeper code paths.")
    print()

    try:
        demo_basic_dictionary_fuzzing()
        demo_systematic_edge_cases()
        demo_mutator_integration()
        demo_specific_dictionary()

        print("\n" + "=" * 70)
        print("Demo Complete!")
        print("=" * 70)
        print("\nKey Takeaways:")
        print("  1. Dictionary fuzzing produces valid-looking but malicious inputs")
        print("  2. Systematic edge case injection ensures comprehensive coverage")
        print("  3. Integration with mutator allows multi-strategy fuzzing")
        print("  4. Targeted fuzzing enables focused testing of specific fields")
        print()

    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
