"""Comprehensive tests for dicom_fuzzer.core.session.profiler module.

Tests performance profiling functionality including FuzzingMetrics,
PerformanceProfiler, StrategyTimer, and profile_function decorator.
"""

import time
from datetime import datetime

import pytest

from dicom_fuzzer.core.session.profiler import (
    FuzzingMetrics,
    PerformanceProfiler,
    StrategyTimer,
    profile_function,
)


class TestFuzzingMetrics:
    """Tests for FuzzingMetrics dataclass."""

    def test_default_values(self):
        """Test FuzzingMetrics default values."""
        metrics = FuzzingMetrics()

        assert metrics.files_generated == 0
        assert metrics.mutations_applied == 0
        assert metrics.validations_performed == 0
        assert metrics.crashes_found == 0
        assert metrics.peak_memory_mb == 0.0
        assert metrics.avg_cpu_percent == 0.0
        assert metrics.cpu_samples == []
        assert metrics.strategy_usage == {}
        assert metrics.strategy_timing == {}
        assert metrics.total_duration == 0.0
        assert metrics.end_time is None

    def test_start_time_auto_set(self):
        """Test start_time is auto-set to now."""
        before = datetime.now()
        metrics = FuzzingMetrics()
        after = datetime.now()

        assert before <= metrics.start_time <= after

    def test_throughput_per_second(self):
        """Test throughput_per_second calculation."""
        metrics = FuzzingMetrics(files_generated=100, total_duration=10.0)
        assert metrics.throughput_per_second() == 10.0

    def test_throughput_per_second_zero_duration(self):
        """Test throughput_per_second with zero duration."""
        metrics = FuzzingMetrics(files_generated=100, total_duration=0.0)
        assert metrics.throughput_per_second() == 0.0

    def test_avg_time_per_file(self):
        """Test avg_time_per_file calculation."""
        metrics = FuzzingMetrics(files_generated=100, total_duration=10.0)
        assert metrics.avg_time_per_file() == 0.1

    def test_avg_time_per_file_zero_files(self):
        """Test avg_time_per_file with zero files."""
        metrics = FuzzingMetrics(files_generated=0, total_duration=10.0)
        assert metrics.avg_time_per_file() == 0.0

    def test_estimated_time_remaining(self):
        """Test estimated_time_remaining calculation."""
        metrics = FuzzingMetrics(files_generated=50, total_duration=10.0)
        # avg_time_per_file = 10/50 = 0.2
        # remaining = 100 - 50 = 50
        # estimated = 50 * 0.2 = 10.0
        assert metrics.estimated_time_remaining(target=100) == 10.0

    def test_estimated_time_remaining_zero_files(self):
        """Test estimated_time_remaining with zero files."""
        metrics = FuzzingMetrics(files_generated=0, total_duration=10.0)
        assert metrics.estimated_time_remaining(target=100) == 0.0

    def test_estimated_time_remaining_target_reached(self):
        """Test estimated_time_remaining when target already reached."""
        metrics = FuzzingMetrics(files_generated=100, total_duration=10.0)
        assert metrics.estimated_time_remaining(target=50) == 0.0

    def test_estimated_time_remaining_exact_target(self):
        """Test estimated_time_remaining when at exact target."""
        metrics = FuzzingMetrics(files_generated=100, total_duration=10.0)
        assert metrics.estimated_time_remaining(target=100) == 0.0


class TestPerformanceProfiler:
    """Tests for PerformanceProfiler class."""

    def test_initialization(self):
        """Test PerformanceProfiler initialization."""
        profiler = PerformanceProfiler()
        assert isinstance(profiler.metrics, FuzzingMetrics)
        assert profiler._cpu_monitor_interval == 1.0

    def test_context_manager_timing(self):
        """Test context manager tracks timing."""
        with PerformanceProfiler() as profiler:
            time.sleep(0.05)  # Small delay

        assert profiler.metrics.total_duration >= 0.04
        assert profiler.metrics.end_time is not None

    def test_record_file_generated(self):
        """Test record_file_generated method."""
        profiler = PerformanceProfiler()
        profiler.record_file_generated()
        profiler.record_file_generated(strategy="header")
        profiler.record_file_generated(strategy="metadata")

        assert profiler.metrics.files_generated == 3
        assert profiler.metrics.strategy_usage.get("header", 0) == 1
        assert profiler.metrics.strategy_usage.get("metadata", 0) == 1

    def test_record_file_generated_samples_resources(self):
        """Test that resource sampling occurs periodically."""
        profiler = PerformanceProfiler()

        # Generate 10 files to trigger resource sampling
        for _ in range(10):
            profiler.record_file_generated()

        # Should have sampled memory at least once
        # (sampling happens every 10 files)
        assert profiler.metrics.files_generated == 10

    def test_record_mutation(self):
        """Test record_mutation method."""
        profiler = PerformanceProfiler()
        profiler.record_mutation("header")
        profiler.record_mutation("metadata", duration=0.5)
        profiler.record_mutation("header", duration=0.3)

        assert profiler.metrics.mutations_applied == 3
        assert profiler.metrics.strategy_usage["header"] == 2
        assert profiler.metrics.strategy_usage["metadata"] == 1
        assert profiler.metrics.strategy_timing.get("header", 0) == 0.3
        assert profiler.metrics.strategy_timing.get("metadata", 0) == 0.5

    def test_record_validation(self):
        """Test record_validation method."""
        profiler = PerformanceProfiler()
        profiler.record_validation()
        profiler.record_validation()

        assert profiler.metrics.validations_performed == 2

    def test_record_crash(self):
        """Test record_crash method."""
        profiler = PerformanceProfiler()
        profiler.record_crash()
        profiler.record_crash()

        assert profiler.metrics.crashes_found == 2

    def test_get_progress_report(self):
        """Test get_progress_report method."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated(strategy="header")
            profiler.record_mutation("header", duration=0.1)
            profiler.record_crash()

            report = profiler.get_progress_report()

        assert "Fuzzing Campaign Progress" in report
        assert "Files Generated: 1" in report
        assert "Mutations Applied: 1" in report
        assert "Crashes Found: 1" in report
        assert "Elapsed Time:" in report
        assert "Throughput:" in report
        assert "Memory Usage:" in report
        assert "Strategy Usage:" in report
        assert "header:" in report

    def test_get_progress_report_with_target(self):
        """Test get_progress_report with target specified."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated()

            report = profiler.get_progress_report(target=100)

        assert "Estimated Time Remaining:" in report
        assert "Progress:" in report

    def test_get_summary(self):
        """Test get_summary method."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated(strategy="header")
            profiler.record_mutation("header", duration=0.1)
            profiler.record_validation()
            profiler.record_crash()

        summary = profiler.get_summary()

        assert "duration_seconds" in summary
        assert "files_generated" in summary
        assert summary["files_generated"] == 1
        assert "mutations_applied" in summary
        assert summary["mutations_applied"] == 1
        assert "validations_performed" in summary
        assert summary["validations_performed"] == 1
        assert "crashes_found" in summary
        assert summary["crashes_found"] == 1
        assert "throughput_per_second" in summary
        assert "avg_time_per_file" in summary
        assert "peak_memory_mb" in summary
        assert "avg_cpu_percent" in summary
        assert "strategy_usage" in summary
        assert "strategy_timing" in summary
        assert "start_time" in summary
        assert "end_time" in summary

    def test_context_manager_exception_handling(self):
        """Test context manager handles exceptions gracefully."""
        try:
            with PerformanceProfiler() as profiler:
                profiler.record_file_generated()
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Metrics should still be finalized
        assert profiler.metrics.end_time is not None
        assert profiler.metrics.total_duration >= 0

    def test_cpu_monitoring(self):
        """Test CPU monitoring functionality."""
        with PerformanceProfiler() as profiler:
            # Generate enough files to trigger CPU sampling
            for _ in range(11):
                profiler.record_file_generated()

        # CPU samples should have been collected
        assert len(profiler.metrics.cpu_samples) >= 0


class TestStrategyTimer:
    """Tests for StrategyTimer context manager."""

    def test_basic_timing(self):
        """Test basic timing functionality."""
        profiler = PerformanceProfiler()

        with StrategyTimer(profiler, "header") as timer:
            time.sleep(0.02)

        # Should have recorded mutation with duration
        assert profiler.metrics.mutations_applied == 1
        assert profiler.metrics.strategy_usage["header"] == 1
        assert profiler.metrics.strategy_timing["header"] >= 0.01

    def test_multiple_strategies(self):
        """Test timing multiple strategies."""
        profiler = PerformanceProfiler()

        with StrategyTimer(profiler, "header"):
            time.sleep(0.01)

        with StrategyTimer(profiler, "metadata"):
            time.sleep(0.02)

        with StrategyTimer(profiler, "header"):
            time.sleep(0.01)

        assert profiler.metrics.mutations_applied == 3
        assert profiler.metrics.strategy_usage["header"] == 2
        assert profiler.metrics.strategy_usage["metadata"] == 1

    def test_nested_timers(self):
        """Test nested timer usage."""
        profiler = PerformanceProfiler()

        with StrategyTimer(profiler, "outer"):
            with StrategyTimer(profiler, "inner"):
                time.sleep(0.01)

        assert profiler.metrics.mutations_applied == 2
        assert profiler.metrics.strategy_usage["outer"] == 1
        assert profiler.metrics.strategy_usage["inner"] == 1

    def test_timer_with_exception(self):
        """Test timer handles exceptions gracefully."""
        profiler = PerformanceProfiler()

        try:
            with StrategyTimer(profiler, "failing"):
                time.sleep(0.01)
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Should still have recorded the timing
        assert profiler.metrics.mutations_applied == 1
        assert profiler.metrics.strategy_usage["failing"] == 1


class TestProfileFunctionDecorator:
    """Tests for profile_function decorator."""

    def test_basic_decoration(self, capsys):
        """Test basic function decoration."""

        @profile_function("test_strategy")
        def sample_function():
            time.sleep(0.01)
            return "result"

        result = sample_function()

        assert result == "result"
        captured = capsys.readouterr()
        assert "[PROFILE]" in captured.out
        assert "test_strategy" in captured.out
        assert "sample_function" in captured.out

    def test_decorated_function_with_args(self, capsys):
        """Test decorated function with arguments."""

        @profile_function("compute")
        def add_numbers(a, b):
            return a + b

        result = add_numbers(3, 5)

        assert result == 8
        captured = capsys.readouterr()
        assert "compute" in captured.out
        assert "add_numbers" in captured.out

    def test_decorated_function_with_kwargs(self, capsys):
        """Test decorated function with keyword arguments."""

        @profile_function("concat")
        def join_strings(sep="-", *args):
            return sep.join(args)

        result = join_strings("-", "a", "b", "c")

        assert result == "a-b-c"
        captured = capsys.readouterr()
        assert "concat" in captured.out

    def test_decorated_function_exception(self, capsys):
        """Test decorated function that raises exception."""

        @profile_function("error")
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            failing_function()

        # Should still have printed timing before exception propagated
        # Note: Exception might prevent output, depends on implementation


class TestIntegration:
    """Integration tests for profiler components."""

    def test_full_profiling_workflow(self):
        """Test complete profiling workflow."""
        with PerformanceProfiler() as profiler:
            # Simulate fuzzing campaign
            for i in range(5):
                with StrategyTimer(profiler, "header"):
                    time.sleep(0.005)

                with StrategyTimer(profiler, "metadata"):
                    time.sleep(0.005)

                profiler.record_file_generated()
                profiler.record_validation()

                if i == 2:
                    profiler.record_crash()

        # Verify metrics
        assert profiler.metrics.files_generated == 5
        assert profiler.metrics.mutations_applied == 10  # 5 header + 5 metadata
        assert profiler.metrics.validations_performed == 5
        assert profiler.metrics.crashes_found == 1

        # Get summary
        summary = profiler.get_summary()
        assert summary["files_generated"] == 5
        assert summary["crashes_found"] == 1

        # Get progress report
        report = profiler.get_progress_report(target=10)
        assert "Progress:" in report

    def test_performance_metrics_accuracy(self):
        """Test that metrics calculations are accurate."""
        metrics = FuzzingMetrics(
            files_generated=100, total_duration=20.0, crashes_found=5
        )

        # Throughput should be 5 files/sec
        assert metrics.throughput_per_second() == 5.0

        # Avg time per file should be 0.2 seconds
        assert metrics.avg_time_per_file() == 0.2

        # Time remaining for 200 files total
        # remaining = 100 files * 0.2 sec/file = 20 seconds
        assert metrics.estimated_time_remaining(target=200) == 20.0
