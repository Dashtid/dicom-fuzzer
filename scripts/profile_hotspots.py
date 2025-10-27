#!/usr/bin/env python3
"""Performance Profiling Script

Profiles DICOM fuzzer operations using cProfile to identify hotspots.
Generates detailed profiling reports for optimization targets.

Usage:
    python scripts/profile_hotspots.py
"""

import cProfile
import pstats
import sys
import tempfile
from io import StringIO
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.core.corpus import CorpusManager
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.types import MutationSeverity


def create_sample_dicom() -> Dataset:
    """Create a sample DICOM dataset for profiling."""
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7.8.10"

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Profile^Test"
    ds.PatientID = "PROF001"
    ds.Modality = "CT"
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.10"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.StudyDescription = "Profiling Study"
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    return ds


def profile_mutations():
    """Profile mutation operations."""
    print("\n[+] Profiling mutation operations...")

    mutator = DicomMutator()
    dataset = create_sample_dicom()

    profiler = cProfile.Profile()
    profiler.enable()

    # Run mutations
    for _ in range(100):
        mutated = mutator.apply_mutations(
            dataset.copy(), num_mutations=3, severity=MutationSeverity.MODERATE
        )

    profiler.disable()

    # Print stats
    stream = StringIO()
    stats = pstats.Stats(profiler, stream=stream)
    stats.strip_dirs()
    stats.sort_stats("cumulative")

    print("\nTop 20 functions by cumulative time:")
    print("-" * 80)
    stats.print_stats(20)
    print(stream.getvalue())

    # Save detailed stats
    stats.dump_stats("profile_mutations.prof")
    print("\n[*] Saved detailed profile to: profile_mutations.prof")


def profile_parsing():
    """Profile parsing operations."""
    print("\n[+] Profiling parsing operations...")

    # Create temporary DICOM file
    with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as tmp:
        dataset = create_sample_dicom()
        dataset.save_as(tmp.name, write_like_original=False)
        tmp_path = Path(tmp.name)

    try:
        profiler = cProfile.Profile()
        profiler.enable()

        # Run parsing
        for _ in range(100):
            parser = DicomParser(tmp_path, security_checks=False)
            metadata = parser.extract_metadata()

        profiler.disable()

        # Print stats
        stream = StringIO()
        stats = pstats.Stats(profiler, stream=stream)
        stats.strip_dirs()
        stats.sort_stats("cumulative")

        print("\nTop 20 functions by cumulative time:")
        print("-" * 80)
        stats.print_stats(20)
        print(stream.getvalue())

        # Save detailed stats
        stats.dump_stats("profile_parsing.prof")
        print("\n[*] Saved detailed profile to: profile_parsing.prof")

    finally:
        tmp_path.unlink()


def profile_corpus():
    """Profile corpus operations."""
    print("\n[+] Profiling corpus operations...")

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"
        manager = CorpusManager(
            corpus_dir, max_corpus_size=100, min_fitness_threshold=0.0
        )

        datasets = [create_sample_dicom() for _ in range(10)]

        profiler = cProfile.Profile()
        profiler.enable()

        # Run corpus operations
        for i in range(100):
            manager.add_entry(f"entry_{i}", datasets[i % len(datasets)])

        # Get entries
        for _ in range(20):
            best = manager.get_best_entries(count=10)
            random_entry = manager.get_random_entry()

        profiler.disable()

        # Print stats
        stream = StringIO()
        stats = pstats.Stats(profiler, stream=stream)
        stats.strip_dirs()
        stats.sort_stats("cumulative")

        print("\nTop 20 functions by cumulative time:")
        print("-" * 80)
        stats.print_stats(20)
        print(stream.getvalue())

        # Save detailed stats
        stats.dump_stats("profile_corpus.prof")
        print("\n[*] Saved detailed profile to: profile_corpus.prof")


def profile_end_to_end():
    """Profile complete fuzzing workflow."""
    print("\n[+] Profiling end-to-end fuzzing workflow...")

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"
        manager = CorpusManager(
            corpus_dir, max_corpus_size=50, min_fitness_threshold=0.0
        )
        mutator = DicomMutator()

        original_ds = create_sample_dicom()

        profiler = cProfile.Profile()
        profiler.enable()

        # Run complete workflow
        for i in range(50):
            # Mutate
            mutated = mutator.apply_mutations(
                original_ds.copy(), num_mutations=3, severity=MutationSeverity.MODERATE
            )

            # Add to corpus
            manager.add_entry(f"fuzzed_{i}", mutated)

            # Occasionally retrieve entries
            if i % 10 == 0:
                best = manager.get_best_entries(count=5)

        profiler.disable()

        # Print stats
        stream = StringIO()
        stats = pstats.Stats(profiler, stream=stream)
        stats.strip_dirs()
        stats.sort_stats("cumulative")

        print("\nTop 30 functions by cumulative time:")
        print("-" * 80)
        stats.print_stats(30)
        print(stream.getvalue())

        # Save detailed stats
        stats.dump_stats("profile_end_to_end.prof")
        print("\n[*] Saved detailed profile to: profile_end_to_end.prof")


def analyze_profiles():
    """Analyze saved profiles and identify optimization targets."""
    print("\n" + "=" * 80)
    print("PROFILING ANALYSIS SUMMARY")
    print("=" * 80)

    print("\n[*] Profile files generated:")
    print("  - profile_mutations.prof")
    print("  - profile_parsing.prof")
    print("  - profile_corpus.prof")
    print("  - profile_end_to_end.prof")

    print("\n[*] To analyze in detail, use:")
    print("  python -m pstats profile_mutations.prof")
    print("  >>> sort cumulative")
    print("  >>> stats 20")

    print("\n[*] Or visualize with snakeviz:")
    print("  pip install snakeviz")
    print("  snakeviz profile_end_to_end.prof")


def main():
    """Run all profiling operations."""
    print("DICOM Fuzzer Performance Profiling")
    print("=" * 80)

    # Run profiling
    profile_mutations()
    profile_parsing()
    profile_corpus()
    profile_end_to_end()

    # Analysis
    analyze_profiles()

    print("\n[+] Profiling complete!")


if __name__ == "__main__":
    main()
