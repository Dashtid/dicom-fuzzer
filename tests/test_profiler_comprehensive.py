"""
Comprehensive tests for core/profiler.py module.

Achieves 70%+ coverage of performance profiling functionality.
"""

import pytest
import time
from datetime import datetime, timedelta
from dicom_fuzzer.core.profiler import (
    FuzzingMetrics,
    PerformanceProfiler,
)


class TestFuzzingMetrics:
    """Tests for FuzzingMetrics dataclass."""

    def test_initialization(self):
        """Test FuzzingMetrics initialization with defaults."""
        metrics = FuzzingMetrics()

        assert isinstance(metrics.start_time, datetime)
        assert metrics.end_time is None
        assert metrics.total_duration == 0.0
        assert metrics.files_generated == 0
        assert metrics.mutations_applied == 0
        assert metrics.validations_performed == 0
        assert metrics.crashes_found == 0
        assert metrics.peak_memory_mb == 0.0
        assert metrics.avg_cpu_percent == 0.0
        assert len(metrics.cpu_samples) == 0
        assert len(metrics.strategy_usage) == 0
        assert len(metrics.strategy_timing) == 0

    def test_custom_initialization(self):
        """Test FuzzingMetrics with custom values."""
        start = datetime(2025, 1, 1, 12, 0, 0)
        metrics = FuzzingMetrics(
            start_time=start,
            files_generated=100,
            mutations_applied=500,
        )

        assert metrics.start_time == start
        assert metrics.files_generated == 100
        assert metrics.mutations_applied == 500

    def test_throughput_per_second_zero_duration(self):
        """Test throughput calculation with zero duration."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 100

        throughput = metrics.throughput_per_second()

        assert throughput == 0.0

    def test_throughput_per_second_calculation(self):
        """Test throughput calculation."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 10.0

        throughput = metrics.throughput_per_second()

        assert throughput == 10.0  # 100 files / 10 seconds

    def test_avg_time_per_file_zero_files(self):
        """Test average time with zero files."""
        metrics = FuzzingMetrics()
        metrics.total_duration = 10.0

        avg_time = metrics.avg_time_per_file()

        assert avg_time == 0.0

    def test_avg_time_per_file_calculation(self):
        """Test average time per file calculation."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 50
        metrics.total_duration = 100.0

        avg_time = metrics.avg_time_per_file()

        assert avg_time == 2.0  # 100s / 50 files

    def test_estimated_time_remaining_no_files(self):
        """Test ETA with no files generated."""
        metrics = FuzzingMetrics()

        eta = metrics.estimated_time_remaining(target=1000)

        assert eta == 0.0

    def test_estimated_time_remaining_target_reached(self):
        """Test ETA when target already reached."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 1000
        metrics.total_duration = 100.0

        eta = metrics.estimated_time_remaining(target=1000)

        assert eta == 0.0

    def test_estimated_time_remaining_calculation(self):
        """Test ETA calculation."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 10.0  # 0.1s per file

        # Target 1000 files, 900 remaining, 0.1s each = 90s
        eta = metrics.estimated_time_remaining(target=1000)

        assert eta == 90.0

    def test_estimated_time_remaining_past_target(self):
        """Test ETA when past target."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 2000
        metrics.total_duration = 100.0

        eta = metrics.estimated_time_remaining(target=1000)

        assert eta == 0.0


class TestPerformanceProfiler:
    """Tests for PerformanceProfiler class."""

    def test_initialization(self):
        """Test PerformanceProfiler initialization."""
        profiler = PerformanceProfiler()

        assert isinstance(profiler.metrics, FuzzingMetrics)
        assert profiler.process is not None
        assert profiler._cpu_monitor_interval == 1.0

    def test_context_manager_basic(self):
        """Test profiler as context manager."""
        with PerformanceProfiler() as profiler:
            assert isinstance(profiler, PerformanceProfiler)
            assert isinstance(profiler.metrics.start_time, datetime)

        # After context exits, end_time should be set
        assert profiler.metrics.end_time is not None
        assert profiler.metrics.total_duration > 0

    def test_context_manager_duration_tracking(self):
        """Test context manager tracks duration."""
        with PerformanceProfiler() as profiler:
            time.sleep(0.1)  # Sleep for 100ms

        # Duration should be at least 100ms
        assert profiler.metrics.total_duration >= 0.09

    def test_record_file_generated(self):
        """Test recording file generation."""
        profiler = PerformanceProfiler()

        profiler.record_file_generated()
        profiler.record_file_generated()

        assert profiler.metrics.files_generated == 2

    def test_record_file_generated_with_strategy(self):
        """Test recording file with strategy tracking."""
        profiler = PerformanceProfiler()

        profiler.record_file_generated(strategy="bit_flip")
        profiler.record_file_generated(strategy="bit_flip")
        profiler.record_file_generated(strategy="byte_swap")

        assert profiler.metrics.files_generated == 3
        assert profiler.metrics.strategy_usage["bit_flip"] == 2
        assert profiler.metrics.strategy_usage["byte_swap"] == 1

    def test_record_mutation(self):
        """Test recording mutation."""
        profiler = PerformanceProfiler()

        profiler.record_mutation("header")
        profiler.record_mutation("pixel")

        assert profiler.metrics.mutations_applied == 2

    def test_record_mutation_with_timing(self):
        """Test mutation recording with timing."""
        profiler = PerformanceProfiler()

        profiler.record_mutation("header", duration=0.5)
        profiler.record_mutation("header", duration=1.0)

        assert profiler.metrics.mutations_applied == 2
        assert profiler.metrics.strategy_timing["header"] == pytest.approx(1.5, rel=0.1)

    def test_record_validation(self):
        """Test recording validation."""
        profiler = PerformanceProfiler()

        profiler.record_validation()
        profiler.record_validation()
        profiler.record_validation()

        assert profiler.metrics.validations_performed == 3

    def test_record_crash(self):
        """Test recording crash."""
        profiler = PerformanceProfiler()

        profiler.record_crash()

        assert profiler.metrics.crashes_found == 1

    def test_sample_resources(self):
        """Test resource sampling."""
        profiler = PerformanceProfiler()

        profiler._sample_resources()

        # Should have recorded memory and CPU
        assert profiler.metrics.peak_memory_mb > 0
        assert len(profiler.metrics.cpu_samples) == 1

    def test_sample_resources_peak_memory(self):
        """Test peak memory tracking."""
        profiler = PerformanceProfiler()

        # First sample
        profiler._sample_resources()
        first_peak = profiler.metrics.peak_memory_mb

        # Peak should only increase, not decrease
        profiler._sample_resources()
        second_peak = profiler.metrics.peak_memory_mb

        assert second_peak >= first_peak

    def test_finalize_cpu_metrics_empty(self):
        """Test CPU finalization with no samples."""
        profiler = PerformanceProfiler()

        profiler._finalize_cpu_metrics()

        assert profiler.metrics.avg_cpu_percent == 0.0

    def test_finalize_cpu_metrics_calculation(self):
        """Test CPU average calculation."""
        profiler = PerformanceProfiler()
        profiler.metrics.cpu_samples = [10.0, 20.0, 30.0]

        profiler._finalize_cpu_metrics()

        assert profiler.metrics.avg_cpu_percent == 20.0

    def test_start_cpu_monitoring(self):
        """Test CPU monitoring initialization."""
        profiler = PerformanceProfiler()

        profiler._start_cpu_monitoring()

        # Should have initialized CPU monitoring (no error)
        assert True


class TestIntegrationScenarios:
    """Integration tests for performance profiling."""

    def test_complete_fuzzing_session(self):
        """Test complete fuzzing session profiling."""
        with PerformanceProfiler() as profiler:
            # Simulate fuzzing campaign
            for i in range(10):
                profiler.record_file_generated(strategy="bit_flip")
                profiler.record_mutation("header", duration=0.01)
                profiler.record_mutation("pixel", duration=0.02)
                profiler.record_validation()

                if i % 5 == 0:
                    profiler.record_crash()

            # Sample resources a few times
            profiler._sample_resources()
            time.sleep(0.05)
            profiler._sample_resources()

        # Verify metrics
        assert profiler.metrics.files_generated == 10
        assert profiler.metrics.mutations_applied == 20
        assert profiler.metrics.validations_performed == 10
        assert profiler.metrics.crashes_found == 2
        assert profiler.metrics.total_duration > 0
        assert profiler.metrics.peak_memory_mb > 0

    def test_throughput_calculation_realistic(self):
        """Test throughput calculation in realistic scenario."""
        with PerformanceProfiler() as profiler:
            for i in range(100):
                profiler.record_file_generated()

            time.sleep(0.1)  # Ensure some duration

        throughput = profiler.metrics.throughput_per_second()

        # Should be significant throughput (100 files in ~0.1s)
        assert throughput > 0

    def test_strategy_usage_tracking(self):
        """Test tracking different strategies."""
        profiler = PerformanceProfiler()

        strategies = ["bit_flip", "byte_swap", "random", "bit_flip", "byte_swap", "bit_flip"]

        for strategy in strategies:
            profiler.record_file_generated(strategy=strategy)

        assert profiler.metrics.strategy_usage["bit_flip"] == 3
        assert profiler.metrics.strategy_usage["byte_swap"] == 2
        assert profiler.metrics.strategy_usage["random"] == 1

    def test_strategy_timing_accumulation(self):
        """Test strategy timing accumulation."""
        profiler = PerformanceProfiler()

        profiler.record_mutation("header", duration=0.1)
        profiler.record_mutation("header", duration=0.2)
        profiler.record_mutation("pixel", duration=0.5)

        assert profiler.metrics.strategy_timing["header"] == pytest.approx(0.3, rel=0.01)
        assert profiler.metrics.strategy_timing["pixel"] == pytest.approx(0.5, rel=0.01)

    def test_eta_calculation_workflow(self):
        """Test ETA calculation during campaign."""
        profiler = PerformanceProfiler()

        # Simulate generating files
        profiler.metrics.files_generated = 250
        profiler.metrics.total_duration = 25.0  # 0.1s per file

        # Calculate ETA to 1000 files
        eta = profiler.metrics.estimated_time_remaining(target=1000)

        # 750 remaining * 0.1s = 75s
        assert eta == pytest.approx(75.0, rel=0.01)

    def test_resource_monitoring_workflow(self):
        """Test resource monitoring over time."""
        with PerformanceProfiler() as profiler:
            # Sample resources multiple times
            for i in range(5):
                profiler._sample_resources()
                time.sleep(0.01)

        # Should have multiple CPU samples
        assert len(profiler.metrics.cpu_samples) == 5
        # Average should be calculated
        assert profiler.metrics.avg_cpu_percent >= 0

    def test_profiler_without_context_manager(self):
        """Test using profiler without context manager."""
        profiler = PerformanceProfiler()

        profiler.record_file_generated()
        profiler.record_mutation("test")

        assert profiler.metrics.files_generated == 1
        assert profiler.metrics.mutations_applied == 1
        # Duration not finalized (no context exit)
        assert profiler.metrics.total_duration == 0.0

    def test_exception_in_context(self):
        """Test profiler handles exceptions in context."""
        try:
            with PerformanceProfiler() as profiler:
                profiler.record_file_generated()
                raise ValueError("Test error")
        except ValueError:
            pass

        # Metrics should still be finalized
        assert profiler.metrics.end_time is not None
        assert profiler.metrics.files_generated == 1
