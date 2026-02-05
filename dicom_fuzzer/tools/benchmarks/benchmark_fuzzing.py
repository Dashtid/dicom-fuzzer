#!/usr/bin/env python3
"""Fuzzing Performance Benchmark Script

Measures baseline performance metrics for the DICOM fuzzer:
- Executions per second
- Memory usage
- CPU time
- Throughput (files/minute)

Usage:
    python scripts/benchmark_fuzzing.py
"""

import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from statistics import mean, stdev

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.core.corpus.corpus import CorpusManager
from dicom_fuzzer.core.dicom.parser import DicomParser
from dicom_fuzzer.core.mutation.mutator import DicomMutator
from dicom_fuzzer.core.types import MutationSeverity


def create_sample_dicom() -> Dataset:
    """Create a sample DICOM dataset for benchmarking."""
    # Create file meta information
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7.8.10"

    # Create dataset
    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Benchmark^Patient"
    ds.PatientID = "BENCH001"
    ds.Modality = "CT"
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.10"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.StudyDescription = "Performance Benchmark Study"
    ds.SeriesDescription = "Benchmark Series"
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    return ds


def benchmark_mutations(iterations: int = 100) -> dict:
    """Benchmark mutation operations."""
    print(f"\n[+] Benchmarking mutation operations ({iterations} iterations)...")

    # Setup
    mutator = DicomMutator()
    dataset = create_sample_dicom()

    # Warm-up
    for _ in range(5):
        mutator.apply_mutations(
            dataset.copy(), num_mutations=3, severity=MutationSeverity.MODERATE
        )

    # Benchmark
    times = []
    tracemalloc.start()
    start_mem = tracemalloc.get_traced_memory()[0]

    start_time = time.time()
    for _ in range(iterations):
        iter_start = time.time()
        mutator.apply_mutations(
            dataset.copy(), num_mutations=3, severity=MutationSeverity.MODERATE
        )
        iter_time = time.time() - iter_start
        times.append(iter_time)

    end_time = time.time()
    end_mem = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    total_time = end_time - start_time
    avg_time = mean(times)
    std_time = stdev(times) if len(times) > 1 else 0
    throughput = iterations / total_time
    mem_used_mb = (end_mem - start_mem) / (1024 * 1024)

    return {
        "operation": "mutations",
        "iterations": iterations,
        "total_time_sec": total_time,
        "avg_time_sec": avg_time,
        "std_time_sec": std_time,
        "throughput_ops_sec": throughput,
        "memory_mb": mem_used_mb,
    }


def benchmark_parsing(iterations: int = 100) -> dict:
    """Benchmark DICOM parsing operations."""
    print(f"\n[+] Benchmarking parsing operations ({iterations} iterations)...")

    # Create temporary DICOM file
    with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as tmp:
        dataset = create_sample_dicom()
        dataset.save_as(tmp.name, write_like_original=False)
        tmp_path = Path(tmp.name)

    try:
        # Warm-up
        for _ in range(5):
            parser = DicomParser(tmp_path, security_checks=False)

        # Benchmark
        times = []
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]

        start_time = time.time()
        for _ in range(iterations):
            iter_start = time.time()
            parser = DicomParser(tmp_path, security_checks=False)
            parser.extract_metadata()
            iter_time = time.time() - iter_start
            times.append(iter_time)

        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        total_time = end_time - start_time
        avg_time = mean(times)
        std_time = stdev(times) if len(times) > 1 else 0
        throughput = iterations / total_time
        mem_used_mb = (end_mem - start_mem) / (1024 * 1024)

        return {
            "operation": "parsing",
            "iterations": iterations,
            "total_time_sec": total_time,
            "avg_time_sec": avg_time,
            "std_time_sec": std_time,
            "throughput_ops_sec": throughput,
            "memory_mb": mem_used_mb,
        }
    finally:
        tmp_path.unlink()


def benchmark_corpus_operations(iterations: int = 50) -> dict:
    """Benchmark corpus management operations."""
    print(f"\n[+] Benchmarking corpus operations ({iterations} iterations)...")

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"
        manager = CorpusManager(
            corpus_dir, max_corpus_size=100, min_fitness_threshold=0.0
        )

        # Create sample datasets
        datasets = [create_sample_dicom() for _ in range(10)]

        # Warm-up
        for i in range(5):
            manager.add_entry(f"warmup_{i}", datasets[i % len(datasets)])

        # Benchmark add operations
        times = []
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]

        start_time = time.time()
        for i in range(iterations):
            iter_start = time.time()
            manager.add_entry(f"entry_{i}", datasets[i % len(datasets)])
            iter_time = time.time() - iter_start
            times.append(iter_time)

        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        total_time = end_time - start_time
        avg_time = mean(times)
        std_time = stdev(times) if len(times) > 1 else 0
        throughput = iterations / total_time
        mem_used_mb = (end_mem - start_mem) / (1024 * 1024)

        return {
            "operation": "corpus_add",
            "iterations": iterations,
            "total_time_sec": total_time,
            "avg_time_sec": avg_time,
            "std_time_sec": std_time,
            "throughput_ops_sec": throughput,
            "memory_mb": mem_used_mb,
        }


def benchmark_end_to_end(iterations: int = 50) -> dict:
    """Benchmark complete fuzzing workflow."""
    print(f"\n[+] Benchmarking end-to-end fuzzing ({iterations} iterations)...")

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"
        manager = CorpusManager(
            corpus_dir, max_corpus_size=50, min_fitness_threshold=0.0
        )
        mutator = DicomMutator()

        # Create sample dataset
        original_ds = create_sample_dicom()

        # Warm-up
        for i in range(3):
            mutated = mutator.apply_mutations(
                original_ds.copy(), num_mutations=3, severity=MutationSeverity.MODERATE
            )
            manager.add_entry(f"warmup_{i}", mutated)

        # Benchmark
        times = []
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]

        start_time = time.time()
        for i in range(iterations):
            iter_start = time.time()

            # Mutate
            mutated = mutator.apply_mutations(
                original_ds.copy(), num_mutations=3, severity=MutationSeverity.MODERATE
            )

            # Add to corpus
            manager.add_entry(f"fuzzed_{i}", mutated)

            iter_time = time.time() - iter_start
            times.append(iter_time)

        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        total_time = end_time - start_time
        avg_time = mean(times)
        std_time = stdev(times) if len(times) > 1 else 0
        throughput = iterations / total_time
        mem_used_mb = (end_mem - start_mem) / (1024 * 1024)

        return {
            "operation": "end_to_end",
            "iterations": iterations,
            "total_time_sec": total_time,
            "avg_time_sec": avg_time,
            "std_time_sec": std_time,
            "throughput_ops_sec": throughput,
            "memory_mb": mem_used_mb,
        }


def print_results(results: list):
    """Print benchmark results in a formatted table."""
    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS")
    print("=" * 80)

    for result in results:
        print(f"\n{result['operation'].upper()}")
        print("-" * 80)
        print(f"  Iterations:        {result['iterations']}")
        print(f"  Total Time:        {result['total_time_sec']:.3f} seconds")
        print(f"  Avg Time/Op:       {result['avg_time_sec'] * 1000:.2f} ms")
        print(f"  Std Dev:           {result['std_time_sec'] * 1000:.2f} ms")
        print(f"  Throughput:        {result['throughput_ops_sec']:.2f} ops/sec")
        print(f"  Memory Used:       {result['memory_mb']:.2f} MB")

    print("\n" + "=" * 80)


def main():
    """Run all benchmarks."""
    print("DICOM Fuzzer Performance Benchmark")
    print("=" * 80)

    results = []

    # Run benchmarks
    results.append(benchmark_mutations(iterations=100))
    results.append(benchmark_parsing(iterations=100))
    results.append(benchmark_corpus_operations(iterations=50))
    results.append(benchmark_end_to_end(iterations=50))

    # Print results
    print_results(results)

    print("\n[+] Benchmark complete!")


if __name__ == "__main__":
    main()
