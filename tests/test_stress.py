"""
Stress Testing Suite for DICOM Fuzzer

CONCEPT: Stress tests validate system behavior under extreme load:
- Large batch processing (10,000+ files)
- Memory pressure scenarios
- CPU intensive operations
- Disk space constraints
- Concurrent operations
- Long-running campaigns

PURPOSE: Ensure the fuzzer remains stable and doesn't crash under production
stress conditions that might occur in real-world security testing.
"""

import gc
import os
import time
from unittest.mock import Mock, patch

import psutil
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager
from dicom_fuzzer.core.statistics import StatisticsCollector
from dicom_fuzzer.core.target_runner import ExecutionStatus, TargetRunner
from dicom_fuzzer.core.validator import DicomValidator


# Mark all tests as slow
pytestmark = pytest.mark.slow


class TestLargeBatchProcessing:
    """Stress test large batch processing capabilities."""

    def test_generate_1000_files(self, sample_dicom_file, temp_dir):
        """Test generating 1000 mutated files (scaled down from 10k for CI)."""
        output_dir = temp_dir / "stress_batch_1k"
        generator = DICOMGenerator(output_dir=str(output_dir))

        start_time = time.time()
        files = generator.generate_batch(sample_dicom_file, count=1000)
        duration = time.time() - start_time

        # Verify all files generated
        assert len(files) == 1000
        assert all(f.exists() for f in files)

        # Performance check: should complete in reasonable time
        # Allow 0.1s per file = 100s total (generous for CI)
        assert duration < 100, f"Took {duration:.2f}s, expected < 100s"

        # Memory check: should not consume excessive memory
        process = psutil.Process()
        memory_mb = process.memory_info().rss / (1024 * 1024)
        assert memory_mb < 2048, f"Memory usage {memory_mb:.0f}MB exceeds 2GB"

    def test_validate_large_batch(self, sample_dicom_file, temp_dir):
        """Test validating large batch of DICOM files."""
        # Generate test batch
        output_dir = temp_dir / "stress_validation"
        generator = DICOMGenerator(output_dir=str(output_dir))
        files = generator.generate_batch(sample_dicom_file, count=500)

        # Validate entire batch
        validator = DicomValidator(strict_mode=False)
        results = []

        start_time = time.time()
        for file in files:
            result, _ = validator.validate_file(file)
            results.append(result)
        duration = time.time() - start_time

        # Should complete all validations
        assert len(results) == 500

        # Performance: reasonable time
        assert duration < 50, f"Validation took {duration:.2f}s, expected < 50s"

    def test_mutate_continuously(self, sample_dicom_file):
        """Test continuous mutation without memory leaks."""
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(sample_dicom_file)
        mutator = DicomMutator()

        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)

        # Perform 5000 mutations
        for i in range(5000):
            dataset = parser.dataset.copy()
            mutated = mutator.mutate(dataset)

            # Verify mutation didn't crash
            assert mutated is not None

            # Periodic garbage collection to help track real leaks
            if i % 1000 == 0:
                gc.collect()

        final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        memory_growth = final_memory - initial_memory

        # Allow some growth, but should not have major leak
        # Allow up to 500MB growth for 5000 mutations
        assert memory_growth < 500, (
            f"Memory grew by {memory_growth:.0f}MB, potential leak"
        )


class TestResourcePressure:
    """Test behavior under resource constraints."""

    def test_low_memory_handling(self, sample_dicom_file, temp_dir):
        """Test operation with strict memory limits."""
        output_dir = temp_dir / "stress_low_memory"

        # Create resource manager with low memory limit
        limits = ResourceLimits(
            max_memory_mb=256,  # 256MB soft limit
            max_memory_mb_hard=512,  # 512MB hard limit
            max_cpu_seconds=60,
        )
        manager = ResourceManager(limits)

        # Try to generate files under memory constraint
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Should complete without crashing
        with manager.limited_execution():
            files = generator.generate_batch(sample_dicom_file, count=100)

        assert len(files) == 100

    def test_disk_space_monitoring(self, sample_dicom_file, temp_dir):
        """Test disk space monitoring during large generation."""
        output_dir = temp_dir / "stress_disk"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Check initial disk space
        disk_usage = psutil.disk_usage(str(temp_dir))
        initial_free_mb = disk_usage.free / (1024 * 1024)

        # Generate files
        files = generator.generate_batch(sample_dicom_file, count=500)

        # Check disk usage growth
        final_disk_usage = psutil.disk_usage(str(temp_dir))
        final_free_mb = final_disk_usage.free / (1024 * 1024)
        used_mb = initial_free_mb - final_free_mb

        # Should not consume excessive disk (allow 1MB per file)
        assert used_mb < 500, f"Used {used_mb:.0f}MB disk, expected < 500MB"

        # Cleanup to free space
        for f in files:
            f.unlink(missing_ok=True)

    def test_cpu_intensive_operations(self, sample_dicom_file):
        """Test CPU intensive mutation operations."""
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(sample_dicom_file)
        mutator = DicomMutator()

        start_time = time.time()
        cpu_start = time.process_time()

        # Perform CPU-heavy mutations
        for _ in range(1000):
            dataset = parser.dataset.copy()
            # Apply multiple mutation passes
            for _ in range(10):
                mutated = mutator.mutate(dataset)

        wall_time = time.time() - start_time
        cpu_time = time.process_time() - cpu_start

        # Should complete in reasonable time
        assert wall_time < 120, f"CPU test took {wall_time:.2f}s"

        # CPU time should be significant portion of wall time
        cpu_ratio = cpu_time / wall_time if wall_time > 0 else 0
        # Allow for CI variability - just check it's not zero
        assert cpu_ratio > 0.1, f"CPU ratio {cpu_ratio:.2f} too low"


class TestConcurrentOperations:
    """Test concurrent fuzzing operations."""

    def test_concurrent_generation(self, sample_dicom_file, temp_dir):
        """Test multiple concurrent file generation."""
        from concurrent.futures import ThreadPoolExecutor

        def generate_batch(batch_id):
            output_dir = temp_dir / f"concurrent_{batch_id}"
            generator = DICOMGenerator(output_dir=str(output_dir))
            return generator.generate_batch(sample_dicom_file, count=100)

        # Run 5 concurrent generation tasks
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(generate_batch, i) for i in range(5)]
            results = [f.result() for f in futures]

        # All batches should complete
        assert len(results) == 5
        assert all(len(batch) == 100 for batch in results)

    def test_concurrent_validation(self, sample_dicom_file, temp_dir):
        """Test concurrent validation operations."""
        from concurrent.futures import ThreadPoolExecutor

        # Generate test files
        output_dir = temp_dir / "concurrent_validation"
        generator = DICOMGenerator(output_dir=str(output_dir))
        files = generator.generate_batch(sample_dicom_file, count=100)

        def validate_file(file_path):
            validator = DicomValidator()
            result, _ = validator.validate_file(file_path)
            return result

        # Validate concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_file, f) for f in files]
            results = [f.result() for f in futures]

        # All validations should complete
        assert len(results) == 100


class TestLongRunningCampaigns:
    """Test long-running fuzzing campaigns."""

    def test_extended_campaign_stability(self, sample_dicom_file, temp_dir):
        """Test campaign running for extended period."""
        from dicom_fuzzer.core.statistics import StatisticsCollector

        output_dir = temp_dir / "extended_campaign"
        generator = DICOMGenerator(output_dir=str(output_dir))
        stats = StatisticsCollector()

        start_time = time.time()
        iterations = 0
        target_duration = 30  # Run for 30 seconds

        while time.time() - start_time < target_duration:
            # Generate file
            files = generator.generate_batch(sample_dicom_file, count=10)

            # Track stats
            for f in files:
                stats.track_iteration(str(f), mutations_applied=3, severity="moderate")

            iterations += 1

            # Periodic garbage collection
            if iterations % 10 == 0:
                gc.collect()

        # Should have completed many iterations
        assert iterations > 10, f"Only {iterations} iterations in {target_duration}s"

        # Should still be responsive
        process = psutil.Process()
        memory_mb = process.memory_info().rss / (1024 * 1024)
        assert memory_mb < 1024, f"Memory at {memory_mb:.0f}MB after long run"

    def test_campaign_statistics_accuracy(self, sample_dicom_file, temp_dir):
        """Test statistics tracking over long campaign."""
        stats = StatisticsCollector()

        # Simulate campaign with known numbers
        test_iterations = 1000
        crash_rate = 0.1  # 10% crashes

        for i in range(test_iterations):
            stats.track_iteration(
                f"test_{i}.dcm", mutations_applied=5, severity="moderate"
            )

            # Simulate crashes at expected rate
            if i % 10 == 0:  # Every 10th iteration
                stats.track_crash(f"test_{i}.dcm")

        # Verify statistics accuracy
        report = stats.get_report()
        assert report["total_iterations"] == test_iterations
        assert report["total_crashes"] == 100  # 10% of 1000

    def test_target_runner_extended_execution(self, temp_dir):
        """Test target runner over extended period."""
        # Create mock target executable
        target_exe = temp_dir / "mock_target.bat"
        target_exe.write_text("@echo off\nexit 0")

        # Create test files
        test_files = []
        for i in range(500):
            test_file = temp_dir / f"test_{i}.dcm"
            test_file.write_bytes(b"dummy")
            test_files.append(test_file)

        runner = TargetRunner(
            target_executable=str(target_exe),
            max_retries=2,
            enable_circuit_breaker=True,
        )

        # Mock subprocess to speed up test
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout="Success", stderr="", args=[]
            )

            # Execute all test files
            start_time = time.time()
            for test_file in test_files:
                result = runner.execute_test(str(test_file))
                assert result.status == ExecutionStatus.SUCCESS

            duration = time.time() - start_time

        # Should complete in reasonable time (mocked, so very fast)
        assert duration < 10, f"Extended execution took {duration:.2f}s"


class TestMemoryLeakDetection:
    """Tests specifically for memory leak detection."""

    def test_repeated_parse_no_leak(self, sample_dicom_file):
        """Test repeated parsing doesn't leak memory."""
        from dicom_fuzzer.core.parser import DicomParser

        gc.collect()
        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)

        # Parse same file 1000 times
        for _ in range(1000):
            parser = DicomParser(sample_dicom_file)
            _ = parser.dataset

        gc.collect()
        final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        memory_growth = final_memory - initial_memory

        # Should not grow significantly (allow 100MB growth)
        assert memory_growth < 100, f"Memory grew {memory_growth:.0f}MB, potential leak"

    def test_repeated_validation_no_leak(self, sample_dicom_file):
        """Test repeated validation doesn't leak memory."""
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(sample_dicom_file)
        validator = DicomValidator()

        gc.collect()
        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)

        # Validate 1000 times
        for _ in range(1000):
            result = validator.validate(parser.dataset.copy())

        gc.collect()
        final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        memory_growth = final_memory - initial_memory

        # Should not grow significantly
        assert memory_growth < 100, f"Memory grew {memory_growth:.0f}MB, potential leak"


class TestEdgeCaseStress:
    """Stress test edge cases and boundary conditions."""

    def test_maximum_dicom_elements(self, temp_dir):
        """Test handling DICOM with maximum elements."""
        # Create dataset with many elements (not quite 10,000 to stay reasonable)
        dataset = Dataset()
        for i in range(1000):  # 1000 elements
            tag_group = 0x0010 + (i // 256)
            tag_element = i % 256
            try:
                dataset.add_new((tag_group, tag_element), "LO", f"Value{i}")
            except Exception:
                # Some tag combos invalid, skip
                pass

        validator = DicomValidator()
        result = validator.validate(dataset)

        # Should handle large dataset
        assert result is not None

    def test_deeply_nested_sequences(self):
        """Test handling deeply nested DICOM sequences."""
        from pydicom.sequence import Sequence

        dataset = Dataset()
        current = dataset

        # Create nested structure (20 levels)
        for level in range(20):
            seq = Sequence()
            inner_dataset = Dataset()
            inner_dataset.add_new((0x0040, 0x0260), "LO", f"Level{level}")
            seq.append(inner_dataset)
            current.add_new((0x0040, 0x0260 + level), "SQ", seq)
            current = inner_dataset

        validator = DicomValidator()
        result = validator.validate(dataset)

        # Should detect deep nesting
        assert any(
            "nested" in w.lower() or "depth" in w.lower() for w in result.warnings
        )

    def test_extremely_long_strings(self):
        """Test handling extremely long string values."""
        dataset = Dataset()
        # Create 100KB string
        long_string = "A" * (100 * 1024)
        dataset.PatientName = long_string

        validator = DicomValidator()
        result = validator.validate(dataset)

        # Should handle but warn
        assert any("long" in w.lower() for w in result.warnings)


@pytest.mark.skipif(
    os.environ.get("CI") == "true", reason="Skip full stress test in CI"
)
class TestFullStress:
    """Full stress tests (disabled in CI)."""

    def test_generate_10000_files(self, sample_dicom_file, temp_dir):
        """Test generating 10,000 files (full stress test)."""
        output_dir = temp_dir / "stress_10k"
        generator = DICOMGenerator(output_dir=str(output_dir))

        start_time = time.time()
        files = generator.generate_batch(sample_dicom_file, count=10000)
        duration = time.time() - start_time

        assert len(files) == 10000
        assert all(f.exists() for f in files)

        # Should complete in under 1000s (0.1s per file)
        assert duration < 1000, f"10k generation took {duration:.2f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
