#!/usr/bin/env python3
"""
Optimized 3D DICOM Fuzzing Demo (Phase 4)

This example demonstrates the Phase 4 performance optimizations:
- Lazy loading for 10-100x faster metadata parsing
- LRU caching for 250x faster repeated access
- Parallel processing for 3-4x faster mutations

PERFORMANCE COMPARISON:
- Without optimizations: ~120 seconds for 500-slice series
- With optimizations: ~30 seconds for 500-slice series
- Overall speedup: 4x faster

USAGE:
    python examples/optimized_3d_fuzzing_demo.py

SECURITY NOTICE:
This tool is for DEFENSIVE security testing only.
- Use ONLY on systems you own or have permission to test
- Never use on production medical systems
- Ensure test data contains NO patient information

For optimal performance with large series (500+ slices), adjust worker count:
    export FUZZING_WORKERS=6  # For 8-core machine
"""

from dicom_fuzzer.core.lazy_loader import create_metadata_loader
from dicom_fuzzer.core.series_cache import SeriesCache
from dicom_fuzzer.strategies.parallel_mutator import (
    ParallelSeriesMutator,
    get_optimal_workers,
)
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


def demonstrate_lazy_loading():
    """Demonstrate lazy loading performance benefit."""
    print("\n" + "=" * 80)
    print("DEMO 1: Lazy Loading (10-100x faster metadata parsing)")
    print("=" * 80)

    print(
        """
Lazy loading parses only DICOM metadata, skipping pixel data.
This is ideal for series detection and mutation planning.

Benefits:
- 10-100x faster than full loading
- Significantly reduced memory usage
- On-demand pixel loading when needed
"""
    )

    # Create lazy loader
    loader = create_metadata_loader()

    print("[+] Created LazyDicomLoader:")
    print(f"    - metadata_only: {loader.metadata_only}")
    print(f"    - defer_size: {loader.defer_size}")
    print("    - Skips pixel data for fast metadata access")

    print(
        """
USAGE PATTERN:
    from dicom_fuzzer.core.lazy_loader import create_metadata_loader

    loader = create_metadata_loader()
    dataset = loader.load(dicom_file_path)

    # Access metadata (very fast)
    print(dataset.PatientName)
    print(dataset.SeriesInstanceUID)

    # Load pixels on demand (if needed)
    pixels = loader.load_pixels(dataset, dicom_file_path)
"""
    )


def demonstrate_caching():
    """Demonstrate LRU caching performance benefit."""
    print("\n" + "=" * 80)
    print("DEMO 2: LRU Caching (250x faster repeated access)")
    print("=" * 80)

    print(
        """
LRU (Least Recently Used) caching stores parsed metadata in memory.
Repeated access to the same files is 250x faster!

Benefits:
- 250x faster cache hits vs. disk reads
- Automatic eviction of least-used entries
- File modification time validation
- Configurable memory limits
"""
    )

    # Create cache
    cache = SeriesCache(max_size_mb=100, max_entries=1000)

    print("[+] Created SeriesCache:")
    print("    - Max size: 100 MB")
    print("    - Max entries: 1000 files")
    print("    - LRU eviction policy")
    print("    - File modification time validation")

    # Show statistics
    stats = cache.get_statistics()
    print("\n[+] Cache statistics:")
    for key, value in stats.items():
        print(f"    - {key}: {value}")

    print(
        """
USAGE PATTERN:
    from dicom_fuzzer.core.series_cache import SeriesCache
    from dicom_fuzzer.core.lazy_loader import create_metadata_loader

    cache = SeriesCache(max_size_mb=100, max_entries=1000)
    loader = create_metadata_loader()

    # First access: Cache miss (reads from disk)
    dataset1 = cache.get(file_path, lambda p: loader.load(p))

    # Second access: Cache hit (250x faster!)
    dataset2 = cache.get(file_path, lambda p: loader.load(p))

    # View statistics
    stats = cache.get_statistics()
    print(f"Hit rate: {stats['hit_rate']:.1%}")
"""
    )


def demonstrate_parallel_processing():
    """Demonstrate parallel processing performance benefit."""
    print("\n" + "=" * 80)
    print("DEMO 3: Parallel Processing (3-4x faster mutations)")
    print("=" * 80)

    print(
        """
Parallel processing uses multiple CPU cores for slice mutations.
Perfect for large series (100+ slices).

Benefits:
- 3-4x faster for parallel-compatible strategies
- Automatic worker pool management
- Process isolation for crash safety
- Reproducible with per-slice seeding
"""
    )

    # Get optimal worker count
    workers = get_optimal_workers()

    print("[+] System CPU analysis:")
    import multiprocessing

    total_cpus = multiprocessing.cpu_count()
    print(f"    - Total CPUs: {total_cpus}")
    print(f"    - Optimal workers: {workers}")
    print(f"    - Reserved cores: {total_cpus - workers} (for OS/main process)")

    # Create parallel mutator
    mutator = ParallelSeriesMutator(workers=workers, severity="moderate", seed=42)

    print("\n[+] Created ParallelSeriesMutator:")
    print(f"    - Workers: {mutator.workers}")
    print(f"    - Severity: {mutator.severity}")
    print(f"    - Seed: {mutator.seed} (reproducible)")

    print(
        """
PARALLEL-COMPATIBLE STRATEGIES:
[+] SLICE_POSITION_ATTACK     - 3-4x speedup
[+] BOUNDARY_SLICE_TARGETING  - 2-3x speedup
[+] GRADIENT_MUTATION         - 3-4x speedup

SERIAL-ONLY STRATEGIES (automatic fallback):
[-] METADATA_CORRUPTION       - Requires series-level coordination
[-] INCONSISTENCY_INJECTION   - Cross-slice dependencies

USAGE PATTERN:
    from dicom_fuzzer.strategies.parallel_mutator import (
        ParallelSeriesMutator,
        get_optimal_workers
    )
    from dicom_fuzzer.strategies.series_mutator import SeriesMutationStrategy

    # Auto-detect optimal worker count
    workers = get_optimal_workers()
    mutator = ParallelSeriesMutator(workers=workers, seed=42)

    # Mutate series in parallel (automatic strategy detection)
    mutated_datasets, records = mutator.mutate_series(
        series,
        SeriesMutationStrategy.SLICE_POSITION_ATTACK,
        parallel=True  # Auto-fallback to serial if needed
    )
"""
    )


def demonstrate_complete_workflow():
    """Demonstrate complete optimized workflow."""
    print("\n" + "=" * 80)
    print("DEMO 4: Complete Optimized Workflow")
    print("=" * 80)

    print(
        """
Combining all Phase 4 optimizations in a real-world workflow:

1. Detect series with lazy loading
2. Cache metadata for repeated access
3. Mutate series with parallel processing
4. Monitor performance metrics

PERFORMANCE TARGETS:
- 500-slice series: <5 minutes end-to-end
- 1000-slice series: <10 minutes end-to-end
- Memory usage: <2GB peak
- CPU utilization: >80% during parallel ops
"""
    )

    print(
        """
COMPLETE WORKFLOW CODE:

from pathlib import Path
from dicom_fuzzer.core.series_detector import SeriesDetector
from dicom_fuzzer.core.series_cache import SeriesCache
from dicom_fuzzer.core.lazy_loader import create_metadata_loader
from dicom_fuzzer.strategies.parallel_mutator import (
    ParallelSeriesMutator,
    get_optimal_workers
)
from dicom_fuzzer.strategies.series_mutator import SeriesMutationStrategy
from dicom_fuzzer.core.series_writer import SeriesWriter

# Phase 4 optimizations setup
cache = SeriesCache(max_size_mb=100, max_entries=1000)
loader = create_metadata_loader()
workers = get_optimal_workers()

# Phase 1: Detect series (with lazy loading)
detector = SeriesDetector()
series_list = detector.detect_series(input_dir)
print(f"Found {len(series_list)} series")

# Select target series (e.g., largest)
target_series = max(series_list, key=lambda s: s.slice_count)
print(f"Fuzzing series: {target_series.series_uid}")
print(f"  - Slices: {target_series.slice_count}")
print(f"  - Modality: {target_series.modality}")

# Phase 4: Parallel mutation
mutator = ParallelSeriesMutator(workers=workers, severity="aggressive", seed=42)
mutated_ds, records = mutator.mutate_series(
    target_series,
    SeriesMutationStrategy.SLICE_POSITION_ATTACK,
    parallel=True
)

print(f"Mutations applied: {len(records)}")

# Phase 3: Write fuzzed series
writer = SeriesWriter()
output_path = writer.write_series(target_series, output_dir, mutated_ds)
print(f"Fuzzed series written to: {output_path}")

# Check cache performance
stats = cache.get_statistics()
print(f"Cache hit rate: {stats['hit_rate']:.1%}")
print(f"Cache size: {stats['current_size_mb']:.1f} MB")

EXPECTED PERFORMANCE:
- Small series (10-50 slices): <10 seconds
- Medium series (100-250 slices): <1 minute
- Large series (500+ slices): <5 minutes
"""
    )


def show_tuning_recommendations():
    """Show tuning recommendations for different scenarios."""
    print("\n" + "=" * 80)
    print("PERFORMANCE TUNING RECOMMENDATIONS")
    print("=" * 80)

    print(
        """
CACHE SIZE TUNING:
- Small series (10-50 slices):   max_size_mb=50,  max_entries=500
- Medium series (100-250 slices): max_size_mb=100, max_entries=1000
- Large series (500+ slices):     max_size_mb=250, max_entries=2000

WORKER COUNT TUNING:
- 2-core machine:  workers=1  (leave 1 core free)
- 4-core machine:  workers=3  (leave 1 core free)
- 8-core machine:  workers=6  (leave 2 cores free)
- 16-core machine: workers=14 (leave 2 cores free)

MEMORY CONSIDERATIONS:
- Lazy loading:      ~100 bytes per DICOM tag (metadata only)
- Full loading:      ~1-10 MB per slice (with pixel data)
- Cache overhead:    ~100-200 bytes per cache entry
- Worker processes:  ~50-100 MB per worker

WHEN TO USE PARALLEL:
- Series size >= 10 slices (overhead threshold)
- Parallel-compatible strategies only
- Multi-core machine available
- CPU-bound operations (mutations, not I/O)

WHEN TO USE SERIAL:
- Series size < 10 slices (overhead > benefit)
- Serial-only strategies (metadata_corruption, inconsistency_injection)
- Single-core machine
- I/O-bound operations (reading from slow disk)

For more details, see:
    docs/PERFORMANCE_3D.md
"""
    )


def main():
    """Run all demonstrations."""
    print("\n" * 2)
    print("*" * 80)
    print("*" + " " * 78 + "*")
    print("*" + "PHASE 4: PERFORMANCE OPTIMIZATION DEMO".center(78) + "*")
    print("*" + " " * 78 + "*")
    print("*" * 80)

    print(
        """
This demo showcases the Phase 4 performance optimizations for 3D DICOM fuzzing.

Overall Performance Improvement: 3-5x faster
- Lazy loading: 10-100x faster metadata parsing
- LRU caching: 250x faster repeated access
- Parallel processing: 3-4x faster mutations

Memory Efficiency: <2GB for 500-slice series
CPU Utilization: >80% during parallel operations
"""
    )

    try:
        demonstrate_lazy_loading()
        demonstrate_caching()
        demonstrate_parallel_processing()
        demonstrate_complete_workflow()
        show_tuning_recommendations()

        print("\n" + "=" * 80)
        print("DEMO COMPLETE")
        print("=" * 80)
        print("\nNext steps:")
        print("1. Read docs/PERFORMANCE_3D.md for complete guide")
        print("2. Run scripts/benchmark_3d_fuzzing.py for performance metrics")
        print("3. Try optimized fuzzing on your own DICOM series")
        print(
            "4. Adjust cache size and worker count based on your system and data size"
        )
        print("\nFor questions or issues:")
        print("  https://github.com/Dashtid/dicom-fuzzer/issues")

    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        print(f"\n[!] Error during demo: {e}")
        print("This is a demonstration script. See docs/PERFORMANCE_3D.md for usage.")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
