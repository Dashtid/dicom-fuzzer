#!/usr/bin/env python3
"""
Comprehensive Performance Benchmarking for 3D DICOM Fuzzing

Benchmarks Phase 1-4 performance with various series sizes:
- Series detection and loading
- Mutation strategies (serial and parallel)
- Series writing (full and incremental)
- Memory usage profiling

USAGE:
    python scripts/benchmark_3d_fuzzing.py
    python scripts/benchmark_3d_fuzzing.py --size 500 --iterations 5
    python scripts/benchmark_3d_fuzzing.py --profile memory
"""

import argparse
import gc
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pydicom
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.core.series_detector import SeriesDetector
from dicom_fuzzer.core.series_writer import SeriesWriter
from dicom_fuzzer.strategies.series_mutator import (
    Series3DMutator,
    SeriesMutationStrategy,
)
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class PerformanceBenchmark:
    """Comprehensive performance benchmarking suite."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = []
        self.process = psutil.Process()

    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024

    def create_synthetic_series(
        self, num_slices: int, modality: str = "CT"
    ) -> tuple[list[Dataset], Path]:
        """
        Create synthetic DICOM series for benchmarking.

        Args:
            num_slices: Number of slices to create
            modality: DICOM modality

        Returns:
            Tuple of (list of datasets, temp directory path)
        """
        series_uid = generate_uid()
        study_uid = generate_uid()
        datasets = []

        for i in range(num_slices):
            # Create file meta information first
            file_meta = Dataset()
            file_meta.TransferSyntaxUID = (
                "1.2.840.10008.1.2"  # Implicit VR Little Endian
            )
            file_meta.MediaStorageSOPClassUID = (
                "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
            )
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.ImplementationClassUID = generate_uid()

            # Create main dataset
            ds = Dataset()
            ds.file_meta = file_meta
            ds.is_implicit_VR = True
            ds.is_little_endian = True

            # Patient Module
            ds.PatientName = "BENCHMARK^TEST"
            ds.PatientID = f"BENCH{i:06d}"
            ds.PatientBirthDate = "19700101"
            ds.PatientSex = "O"

            # Study Module
            ds.StudyInstanceUID = study_uid
            ds.StudyDate = "20250123"
            ds.StudyTime = "120000"
            ds.StudyDescription = f"Benchmark Series {num_slices} slices"
            ds.AccessionNumber = f"ACC{num_slices}"

            # Series Module
            ds.SeriesInstanceUID = series_uid
            ds.SeriesNumber = 1
            ds.Modality = modality
            ds.SeriesDescription = f"Benchmark {modality} Series"

            # Image Module
            ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
            ds.InstanceNumber = i + 1
            ds.ImagePositionPatient = [0.0, 0.0, float(i)]
            ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
            ds.SliceLocation = float(i)
            ds.SliceThickness = 1.0

            # Image Pixel Module (small to keep it fast)
            ds.SamplesPerPixel = 1
            ds.PhotometricInterpretation = "MONOCHROME2"
            ds.Rows = 64
            ds.Columns = 64
            ds.BitsAllocated = 16
            ds.BitsStored = 12
            ds.HighBit = 11
            ds.PixelRepresentation = 0
            ds.PixelData = b"\x00\x00" * (64 * 64)  # Minimal pixel data

            datasets.append(ds)

        return datasets, self.output_dir

    def benchmark_series_detection(
        self, num_slices: int, iterations: int = 3
    ) -> dict[str, Any]:
        """
        Benchmark series detection performance.

        Args:
            num_slices: Number of slices in series
            iterations: Number of iterations to average

        Returns:
            Dict with benchmark results
        """
        logger.info(f"[BENCHMARK] Series Detection - {num_slices} slices")

        # Create synthetic series
        datasets, temp_dir = self.create_synthetic_series(num_slices)

        # Write to disk
        series_dir = temp_dir / f"series_{num_slices}_slices"
        series_dir.mkdir(exist_ok=True)

        for i, ds in enumerate(datasets):
            output_path = series_dir / f"slice_{i + 1:03d}.dcm"
            pydicom.dcmwrite(output_path, ds)

        detector = SeriesDetector()

        times = []
        memory_usage = []

        for iteration in range(iterations):
            gc.collect()
            start_mem = self.get_memory_usage()
            start_time = time.perf_counter()

            # Detect series
            series_list = detector.detect_series_in_directory(
                series_dir, validate=False
            )

            end_time = time.perf_counter()
            end_mem = self.get_memory_usage()

            elapsed = end_time - start_time
            mem_delta = end_mem - start_mem

            times.append(elapsed)
            memory_usage.append(mem_delta)

            logger.info(
                f"  Iteration {iteration + 1}: {elapsed:.3f}s, "
                f"+{mem_delta:.1f}MB, {len(series_list)} series"
            )

        # Clean up
        import shutil

        shutil.rmtree(series_dir)

        return {
            "operation": "series_detection",
            "num_slices": num_slices,
            "iterations": iterations,
            "avg_time_seconds": sum(times) / len(times),
            "min_time_seconds": min(times),
            "max_time_seconds": max(times),
            "avg_memory_mb": sum(memory_usage) / len(memory_usage),
            "slices_per_second": num_slices / (sum(times) / len(times)),
        }

    def benchmark_series_mutation(
        self,
        num_slices: int,
        strategy: SeriesMutationStrategy,
        iterations: int = 3,
    ) -> dict[str, Any]:
        """
        Benchmark series mutation performance.

        Args:
            num_slices: Number of slices
            strategy: Mutation strategy to test
            iterations: Number of iterations

        Returns:
            Dict with benchmark results
        """
        logger.info(
            f"[BENCHMARK] Series Mutation ({strategy.value}) - {num_slices} slices"
        )

        # Create synthetic series (in memory, not on disk)
        datasets, _ = self.create_synthetic_series(num_slices)

        # For this benchmark, we'll just measure mutation time on datasets
        mutator = Series3DMutator(severity="moderate", seed=42)

        times = []
        memory_usage = []

        for iteration in range(iterations):
            gc.collect()
            start_mem = self.get_memory_usage()
            start_time = time.perf_counter()

            # Perform mutation based on strategy
            if strategy == SeriesMutationStrategy.METADATA_CORRUPTION:
                _ = mutator._mutate_series_metadata(datasets)
            elif strategy == SeriesMutationStrategy.SLICE_POSITION_ATTACK:
                _ = mutator._mutate_slice_positions(datasets)
            elif strategy == SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING:
                _ = mutator._mutate_boundary_slices(datasets, target="first")
            elif strategy == SeriesMutationStrategy.GRADIENT_MUTATION:
                _ = mutator._mutate_gradient(datasets, pattern="linear")
            elif strategy == SeriesMutationStrategy.INCONSISTENCY_INJECTION:
                _ = mutator._inject_inconsistencies(
                    datasets, inconsistency_type="mixed_modality"
                )

            end_time = time.perf_counter()
            end_mem = self.get_memory_usage()

            elapsed = end_time - start_time
            mem_delta = end_mem - start_mem

            times.append(elapsed)
            memory_usage.append(mem_delta)

            logger.info(
                f"  Iteration {iteration + 1}: {elapsed:.3f}s, +{mem_delta:.1f}MB"
            )

        return {
            "operation": "series_mutation",
            "strategy": strategy.value,
            "num_slices": num_slices,
            "iterations": iterations,
            "avg_time_seconds": sum(times) / len(times),
            "min_time_seconds": min(times),
            "max_time_seconds": max(times),
            "avg_memory_mb": sum(memory_usage) / len(memory_usage),
            "slices_per_second": num_slices / (sum(times) / len(times)),
        }

    def benchmark_series_writing(
        self, num_slices: int, iterations: int = 3
    ) -> dict[str, Any]:
        """
        Benchmark series writing performance.

        Args:
            num_slices: Number of slices
            iterations: Number of iterations

        Returns:
            Dict with benchmark results
        """
        logger.info(f"[BENCHMARK] Series Writing - {num_slices} slices")

        # Create synthetic series
        datasets, temp_dir = self.create_synthetic_series(num_slices)

        # Create temporary DicomSeries (need paths for writer)
        temp_input_dir = temp_dir / f"temp_input_{num_slices}"
        temp_input_dir.mkdir(exist_ok=True)

        file_paths = []
        for i, ds in enumerate(datasets):
            path = temp_input_dir / f"slice_{i + 1:03d}.dcm"
            pydicom.dcmwrite(path, ds)
            file_paths.append(path)

        series_uid = datasets[0].SeriesInstanceUID
        study_uid = datasets[0].StudyInstanceUID
        modality = datasets[0].Modality

        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality=modality,
            slices=file_paths,
        )

        writer = SeriesWriter()

        times = []
        memory_usage = []

        for iteration in range(iterations):
            output_dir = temp_dir / f"output_{num_slices}_iter{iteration}"

            gc.collect()
            start_mem = self.get_memory_usage()
            start_time = time.perf_counter()

            # Write series
            _ = writer.write_series(series, output_dir, datasets)

            end_time = time.perf_counter()
            end_mem = self.get_memory_usage()

            elapsed = end_time - start_time
            mem_delta = end_mem - start_mem

            times.append(elapsed)
            memory_usage.append(mem_delta)

            logger.info(
                f"  Iteration {iteration + 1}: {elapsed:.3f}s, +{mem_delta:.1f}MB"
            )

            # Clean up output
            import shutil

            shutil.rmtree(output_dir)

        # Clean up input
        import shutil

        shutil.rmtree(temp_input_dir)

        return {
            "operation": "series_writing",
            "num_slices": num_slices,
            "iterations": iterations,
            "avg_time_seconds": sum(times) / len(times),
            "min_time_seconds": min(times),
            "max_time_seconds": max(times),
            "avg_memory_mb": sum(memory_usage) / len(memory_usage),
            "slices_per_second": num_slices / (sum(times) / len(times)),
        }

    def run_comprehensive_benchmark(self, slice_counts: list[int]) -> None:
        """
        Run comprehensive benchmark across different series sizes.

        Args:
            slice_counts: List of slice counts to test
        """
        logger.info("=" * 80)
        logger.info("COMPREHENSIVE 3D FUZZING PERFORMANCE BENCHMARK")
        logger.info("=" * 80)

        all_results = []

        for num_slices in slice_counts:
            logger.info(f"\n[+] Testing with {num_slices} slices...\n")

            # Benchmark series detection
            result = self.benchmark_series_detection(num_slices, iterations=3)
            all_results.append(result)
            self.results.append(result)

            # Benchmark mutations
            for strategy in SeriesMutationStrategy:
                result = self.benchmark_series_mutation(
                    num_slices, strategy, iterations=3
                )
                all_results.append(result)
                self.results.append(result)

            # Benchmark writing
            result = self.benchmark_series_writing(num_slices, iterations=3)
            all_results.append(result)
            self.results.append(result)

        # Print summary
        self.print_summary(all_results)

    def print_summary(self, results: list[dict[str, Any]]) -> None:
        """Print benchmark summary."""
        logger.info("\n" + "=" * 80)
        logger.info("BENCHMARK SUMMARY")
        logger.info("=" * 80)

        # Group by operation
        operations = {}
        for result in results:
            op = result["operation"]
            if op not in operations:
                operations[op] = []
            operations[op].append(result)

        for op_name, op_results in operations.items():
            logger.info(f"\n{op_name.upper().replace('_', ' ')}:")
            logger.info("-" * 80)
            logger.info(
                f"{'Slices':<10} {'Time (avg)':<15} {'Memory (avg)':<15} {'Slices/sec':<15}"
            )
            logger.info("-" * 80)

            for result in op_results:
                num_slices = result["num_slices"]
                avg_time = result["avg_time_seconds"]
                avg_mem = result["avg_memory_mb"]
                slices_per_sec = result.get("slices_per_second", 0)

                # Add strategy info if mutation
                extra = ""
                if "strategy" in result:
                    extra = f" ({result['strategy']})"

                logger.info(
                    f"{num_slices:<10} {avg_time:<15.3f} {avg_mem:<15.1f} "
                    f"{slices_per_sec:<15.1f}{extra}"
                )


def main():
    """Main benchmark entry point."""
    parser = argparse.ArgumentParser(
        description="Benchmark 3D DICOM fuzzing performance"
    )
    parser.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=[50, 100, 250, 500],
        help="Series sizes to benchmark (default: 50 100 250 500)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations per test (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark_results"),
        help="Output directory for temp files (default: benchmark_results)",
    )

    args = parser.parse_args()

    # Create benchmark
    benchmark = PerformanceBenchmark(args.output)

    # Run comprehensive benchmark
    benchmark.run_comprehensive_benchmark(args.sizes)

    logger.info("\n[+] Benchmark complete!")


if __name__ == "__main__":
    main()
