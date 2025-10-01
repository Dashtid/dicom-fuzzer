"""Tests for performance profiler module."""

import time

import pytest

from core.profiler import FuzzingMetrics, PerformanceProfiler, StrategyTimer


class TestFuzzingMetrics:
    """Test FuzzingMetrics dataclass."""

    def test_metrics_initialization(self):
        """Test metrics are initialized correctly."""
        metrics = FuzzingMetrics()

        assert metrics.files_generated == 0
        assert metrics.mutations_applied == 0
        assert metrics.crashes_found == 0
        assert metrics.peak_memory_mb == 0.0
        assert metrics.start_time is not None

    def test_throughput_calculation(self):
        """Test throughput calculation."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 10.0

        assert metrics.throughput_per_second() == 10.0

    def test_throughput_zero_duration(self):
        """Test throughput with zero duration."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 0.0

        assert metrics.throughput_per_second() == 0.0

    def test_avg_time_per_file(self):
        """Test average time per file calculation."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 50
        metrics.total_duration = 100.0

        assert metrics.avg_time_per_file() == 2.0

    def test_avg_time_zero_files(self):
        """Test average time with zero files."""
        metrics = FuzzingMetrics()
        metrics.total_duration = 100.0

        assert metrics.avg_time_per_file() == 0.0

    def test_estimated_time_remaining(self):
        """Test time estimation."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 25
        metrics.total_duration = 50.0

        # Average time: 2s per file
        # Remaining: 75 files
        # Estimate: 150s
        remaining = metrics.estimated_time_remaining(target=100)
        assert remaining == 150.0

    def test_estimated_time_target_reached(self):
        """Test estimation when target reached."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 100

        remaining = metrics.estimated_time_remaining(target=100)
        assert remaining == 0.0

    def test_estimated_time_exceeded(self):
        """Test estimation when target exceeded."""
        metrics = FuzzingMetrics()
        metrics.files_generated = 150

        remaining = metrics.estimated_time_remaining(target=100)
        assert remaining == 0.0


class TestPerformanceProfiler:
    """Test PerformanceProfiler class."""

    def test_profiler_initialization(self):
        """Test profiler initializes correctly."""
        profiler = PerformanceProfiler()

        assert profiler.metrics is not None
        assert profiler.process is not None
        assert profiler.metrics.files_generated == 0

    def test_context_manager_usage(self):
        """Test profiler as context manager."""
        with PerformanceProfiler() as profiler:
            assert profiler.metrics.start_time is not None
            profiler.record_file_generated()

        assert profiler.metrics.end_time is not None
        assert profiler.metrics.total_duration > 0
        assert profiler.metrics.files_generated == 1

    def test_record_file_generated(self):
        """Test recording file generation."""
        profiler = PerformanceProfiler()

        profiler.record_file_generated("metadata")
        assert profiler.metrics.files_generated == 1
        assert profiler.metrics.strategy_usage["metadata"] == 1

    def test_record_multiple_files(self):
        """Test recording multiple files."""
        profiler = PerformanceProfiler()

        for _ in range(5):
            profiler.record_file_generated("header")

        assert profiler.metrics.files_generated == 5
        assert profiler.metrics.strategy_usage["header"] == 5

    def test_record_mutation(self):
        """Test recording mutations."""
        profiler = PerformanceProfiler()

        profiler.record_mutation("header", duration=0.5)
        assert profiler.metrics.mutations_applied == 1
        assert profiler.metrics.strategy_usage["header"] == 1
        assert profiler.metrics.strategy_timing["header"] == 0.5

    def test_record_mutation_accumulates_timing(self):
        """Test mutation timing accumulates."""
        profiler = PerformanceProfiler()

        profiler.record_mutation("header", duration=0.5)
        profiler.record_mutation("header", duration=0.3)

        assert profiler.metrics.strategy_timing["header"] == 0.8

    def test_record_validation(self):
        """Test recording validations."""
        profiler = PerformanceProfiler()

        profiler.record_validation()
        profiler.record_validation()

        assert profiler.metrics.validations_performed == 2

    def test_record_crash(self):
        """Test recording crashes."""
        profiler = PerformanceProfiler()

        profiler.record_crash()
        assert profiler.metrics.crashes_found == 1

    def test_get_progress_report(self):
        """Test progress report generation."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated("metadata")
            profiler.record_mutation("header")
            time.sleep(0.1)

            report = profiler.get_progress_report()

        assert "Files Generated: 1" in report
        assert "Mutations Applied: 1" in report
        assert "Throughput:" in report

    def test_get_progress_report_with_target(self):
        """Test progress report with target."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated()
            time.sleep(0.1)

            report = profiler.get_progress_report(target=100)

        assert "Estimated Time Remaining:" in report
        assert "Progress:" in report

    def test_get_summary(self):
        """Test summary generation."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated("metadata")
            profiler.record_mutation("header", duration=0.5)
            profiler.record_crash()

        summary = profiler.get_summary()

        assert summary["files_generated"] == 1
        assert summary["mutations_applied"] == 1
        assert summary["crashes_found"] == 1
        assert "throughput_per_second" in summary
        assert "strategy_usage" in summary

    def test_resource_sampling(self):
        """Test resource sampling on batch operations."""
        profiler = PerformanceProfiler()

        # Generate 20 files to trigger sampling (every 10)
        for i in range(20):
            profiler.record_file_generated()

        # Should have sampled resources at least once
        assert profiler.metrics.peak_memory_mb > 0

    def test_strategy_usage_tracking(self):
        """Test strategy usage is tracked correctly."""
        profiler = PerformanceProfiler()

        profiler.record_file_generated("metadata")
        profiler.record_file_generated("header")
        profiler.record_file_generated("metadata")

        assert profiler.metrics.strategy_usage["metadata"] == 2
        assert profiler.metrics.strategy_usage["header"] == 1


class TestStrategyTimer:
    """Test StrategyTimer context manager."""

    def test_timer_records_duration(self):
        """Test timer records duration."""
        profiler = PerformanceProfiler()

        with StrategyTimer(profiler, "test_strategy"):
            time.sleep(0.1)

        assert profiler.metrics.mutations_applied == 1
        assert profiler.metrics.strategy_timing["test_strategy"] > 0.05

    def test_timer_with_exception(self):
        """Test timer records even with exceptions."""
        profiler = PerformanceProfiler()

        try:
            with StrategyTimer(profiler, "test_strategy"):
                raise ValueError("Test error")
        except ValueError:
            pass

        # Should still have recorded the mutation
        assert profiler.metrics.mutations_applied == 1

    def test_multiple_timers(self):
        """Test multiple timers for same strategy."""
        profiler = PerformanceProfiler()

        with StrategyTimer(profiler, "header"):
            time.sleep(0.05)

        with StrategyTimer(profiler, "header"):
            time.sleep(0.05)

        assert profiler.metrics.mutations_applied == 2
        assert profiler.metrics.strategy_timing["header"] > 0.08


class TestIntegration:
    """Integration tests for profiler."""

    def test_complete_fuzzing_session(self):
        """Test profiling a complete fuzzing session."""
        with PerformanceProfiler() as profiler:
            # Simulate fuzzing campaign
            strategies = ["metadata", "header", "pixel"]

            for i in range(10):
                strategy = strategies[i % 3]

                with StrategyTimer(profiler, strategy):
                    time.sleep(0.01)  # Simulate work

                profiler.record_file_generated(strategy)

                if i % 5 == 0:
                    profiler.record_validation()

                if i == 7:
                    profiler.record_crash()

        # Verify all metrics were captured
        assert profiler.metrics.files_generated == 10
        assert profiler.metrics.mutations_applied == 10
        assert profiler.metrics.validations_performed == 2
        assert profiler.metrics.crashes_found == 1
        assert profiler.metrics.total_duration > 0.1

        # Verify strategy tracking
        # Each iteration: 1 mutation (StrategyTimer) + 1 file generation = 2 counts
        assert len(profiler.metrics.strategy_usage) == 3
        assert (
            sum(profiler.metrics.strategy_usage.values()) == 20
        )  # 10 mutations + 10 files

    def test_profiler_summary_completeness(self):
        """Test summary contains all expected fields."""
        with PerformanceProfiler() as profiler:
            profiler.record_file_generated("test")
            profiler.record_mutation("test", duration=0.5)

        summary = profiler.get_summary()

        required_fields = [
            "duration_seconds",
            "files_generated",
            "mutations_applied",
            "throughput_per_second",
            "avg_time_per_file",
            "peak_memory_mb",
            "strategy_usage",
            "start_time",
        ]

        for field in required_fields:
            assert field in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
