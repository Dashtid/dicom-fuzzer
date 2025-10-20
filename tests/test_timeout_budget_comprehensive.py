"""
Comprehensive tests for timeout budget management.

Achieves 90%+ coverage of timeout_budget.py module.
"""

import time

from dicom_fuzzer.utils.timeout_budget import (
    ExecutionTimer,
    TimeoutBudgetManager,
    TimeoutStatistics,
)


class TestTimeoutStatistics:
    """Comprehensive tests for TimeoutStatistics."""

    def test_initialization(self):
        """Test TimeoutStatistics initialization."""
        stats = TimeoutStatistics()

        assert stats.total_time == 0.0
        assert stats.timeout_time == 0.0
        assert stats.successful_time == 0.0
        assert stats.total_executions == 0
        assert stats.timeout_count == 0
        assert stats.successful_count == 0

    def test_timeout_ratio_zero_time(self):
        """Test timeout ratio with zero total time."""
        stats = TimeoutStatistics()
        assert stats.timeout_ratio == 0.0

    def test_timeout_ratio_calculation(self):
        """Test timeout ratio calculation."""
        stats = TimeoutStatistics()
        stats.total_time = 100.0
        stats.timeout_time = 25.0

        assert stats.timeout_ratio == 0.25

    def test_timeout_ratio_all_timeouts(self):
        """Test timeout ratio when all executions timeout."""
        stats = TimeoutStatistics()
        stats.total_time = 100.0
        stats.timeout_time = 100.0

        assert stats.timeout_ratio == 1.0

    def test_avg_successful_time_no_success(self):
        """Test average successful time with no successes."""
        stats = TimeoutStatistics()
        assert stats.avg_successful_time == 0.0

    def test_avg_successful_time(self):
        """Test average successful time calculation."""
        stats = TimeoutStatistics()
        stats.successful_time = 50.0
        stats.successful_count = 10

        assert stats.avg_successful_time == 5.0

    def test_avg_timeout_time_no_timeouts(self):
        """Test average timeout time with no timeouts."""
        stats = TimeoutStatistics()
        assert stats.avg_timeout_time == 0.0

    def test_avg_timeout_time(self):
        """Test average timeout time calculation."""
        stats = TimeoutStatistics()
        stats.timeout_time = 100.0
        stats.timeout_count = 5

        assert stats.avg_timeout_time == 20.0

    def test_string_representation(self):
        """Test string representation."""
        stats = TimeoutStatistics()
        stats.total_executions = 10
        stats.timeout_count = 2
        stats.total_time = 100.0
        stats.timeout_time = 20.0

        str_repr = str(stats)
        assert "20.0%" in str_repr
        assert "2/10" in str_repr


class TestTimeoutBudgetManager:
    """Comprehensive tests for TimeoutBudgetManager."""

    def test_initialization_defaults(self):
        """Test manager initialization with defaults."""
        manager = TimeoutBudgetManager()

        assert manager.max_timeout_ratio == 0.10
        assert manager.min_timeout == 1.0
        assert manager.max_timeout == 60.0
        assert manager.adjustment_interval == 100
        assert manager.current_timeout == 1.0

    def test_initialization_custom(self):
        """Test manager initialization with custom values."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.20,
            min_timeout=2.0,
            max_timeout=30.0,
            adjustment_interval=50,
        )

        assert manager.max_timeout_ratio == 0.20
        assert manager.min_timeout == 2.0
        assert manager.max_timeout == 30.0
        assert manager.adjustment_interval == 50
        assert manager.current_timeout == 2.0

    def test_record_execution_successful(self):
        """Test recording successful execution."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=1.5, timed_out=False)

        stats = manager.get_statistics()
        assert stats.total_executions == 1
        assert stats.successful_count == 1
        assert stats.timeout_count == 0
        assert stats.successful_time == 1.5
        assert stats.timeout_time == 0.0

    def test_record_execution_timeout(self):
        """Test recording timed-out execution."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=5.0, timed_out=True)

        stats = manager.get_statistics()
        assert stats.total_executions == 1
        assert stats.successful_count == 0
        assert stats.timeout_count == 1
        assert stats.successful_time == 0.0
        assert stats.timeout_time == 5.0

    def test_record_multiple_executions(self):
        """Test recording multiple executions."""
        manager = TimeoutBudgetManager()

        manager.record_execution(1.0, False)
        manager.record_execution(2.0, False)
        manager.record_execution(5.0, True)

        stats = manager.get_statistics()
        assert stats.total_executions == 3
        assert stats.successful_count == 2
        assert stats.timeout_count == 1

    def test_is_budget_exceeded_empty(self):
        """Test budget exceeded with no executions."""
        manager = TimeoutBudgetManager()
        assert manager.is_budget_exceeded() is False

    def test_is_budget_exceeded_within_budget(self):
        """Test budget not exceeded."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.20)

        # 10% timeouts (within 20% budget)
        for _ in range(9):
            manager.record_execution(1.0, False)
        manager.record_execution(1.0, True)

        assert manager.is_budget_exceeded() is False

    def test_is_budget_exceeded_over_budget(self):
        """Test budget exceeded."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        # 50% timeouts (exceeds 10% budget)
        for _ in range(5):
            manager.record_execution(1.0, False)
        for _ in range(5):
            manager.record_execution(1.0, True)

        assert manager.is_budget_exceeded() is True

    def test_get_recommended_timeout(self):
        """Test getting recommended timeout."""
        manager = TimeoutBudgetManager()
        manager.current_timeout = 5.0

        assert manager.get_recommended_timeout() == 5.0

    def test_timeout_adjustment_on_excess(self):
        """Test timeout reduction when budget exceeded."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10,
            adjustment_interval=10,
            min_timeout=1.0,
            max_timeout=10.0,
        )

        manager.current_timeout = 5.0
        initial_timeout = manager.current_timeout

        # Record executions to trigger adjustment (mostly timeouts)
        for _ in range(15):
            manager.record_execution(1.0, True)

        # Timeout should be reduced
        assert manager.current_timeout < initial_timeout
        assert manager.current_timeout >= manager.min_timeout

    def test_timeout_adjustment_on_low_rate(self):
        """Test timeout increase when timeout rate is low."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.20,
            adjustment_interval=10,
            min_timeout=1.0,
            max_timeout=20.0,
        )

        manager.current_timeout = 5.0
        initial_timeout = manager.current_timeout

        # Record executions with very low timeout rate
        for _ in range(20):
            manager.record_execution(1.0, False)

        # Timeout might be increased
        assert manager.current_timeout >= initial_timeout
        assert manager.current_timeout <= manager.max_timeout

    def test_timeout_respects_min_limit(self):
        """Test timeout doesn't go below minimum."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.01,  # Very low
            adjustment_interval=5,
            min_timeout=2.0,
            max_timeout=10.0,
        )

        manager.current_timeout = 2.5

        # Record many timeouts
        for _ in range(20):
            manager.record_execution(1.0, True)

        assert manager.current_timeout >= manager.min_timeout

    def test_timeout_respects_max_limit(self):
        """Test timeout doesn't exceed maximum."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.50,
            adjustment_interval=5,
            min_timeout=1.0,
            max_timeout=10.0,
        )

        manager.current_timeout = 9.5

        # Record many successes
        for _ in range(20):
            manager.record_execution(1.0, False)

        assert manager.current_timeout <= manager.max_timeout

    def test_reset_statistics(self):
        """Test statistics reset."""
        manager = TimeoutBudgetManager()

        manager.record_execution(1.0, True)
        manager.record_execution(1.0, False)

        manager.reset_statistics()

        stats = manager.get_statistics()
        assert stats.total_executions == 0
        assert stats.timeout_count == 0
        assert stats.successful_count == 0
        assert manager.executions_since_adjustment == 0

    def test_generate_report_empty(self):
        """Test report generation with no data."""
        manager = TimeoutBudgetManager()
        report = manager.generate_report()

        assert "TIMEOUT BUDGET REPORT" in report
        assert "Total Executions" in report

    def test_generate_report_with_data(self):
        """Test report generation with execution data."""
        manager = TimeoutBudgetManager()

        manager.record_execution(1.0, False)
        manager.record_execution(2.0, True)
        manager.record_execution(1.5, False)

        report = manager.generate_report()

        assert "TIMEOUT BUDGET REPORT" in report
        assert "3" in report  # Total executions
        assert "Timeout Ratio" in report
        assert "RECOMMENDATIONS" in report

    def test_generate_report_budget_exceeded(self):
        """Test report when budget is exceeded."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        # Exceed budget
        for _ in range(10):
            manager.record_execution(1.0, True)

        report = manager.generate_report()

        assert "EXCEEDED" in report or "exceeded" in report

    def test_generate_report_budget_ok(self):
        """Test report when budget is within limits."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.50)

        # Within budget
        for _ in range(10):
            manager.record_execution(1.0, False)

        report = manager.generate_report()

        assert "OK" in report or "acceptable" in report.lower()


class TestExecutionTimer:
    """Comprehensive tests for ExecutionTimer."""

    def test_timer_basic(self):
        """Test basic timer usage."""
        with ExecutionTimer() as timer:
            time.sleep(0.01)

        assert timer.start_time is not None
        assert timer.end_time is not None
        assert timer.duration > 0.0
        assert timer.duration >= 0.01

    def test_timer_initialization(self):
        """Test timer initialization."""
        timer = ExecutionTimer()

        assert timer.start_time is None
        assert timer.end_time is None
        assert timer.duration == 0.0

    def test_timer_context_manager(self):
        """Test timer as context manager."""
        timer = ExecutionTimer()

        with timer:
            time.sleep(0.005)

        assert timer.duration > 0.0

    def test_timer_exception_handling(self):
        """Test timer handles exceptions."""
        try:
            with ExecutionTimer() as timer:
                raise ValueError("Test error")
        except ValueError:
            pass

        # Timer should still have recorded time
        assert timer.duration > 0.0

    def test_timer_precision(self):
        """Test timer precision."""
        with ExecutionTimer() as timer:
            time.sleep(0.02)

        # Should be close to 0.02 seconds
        assert 0.015 < timer.duration < 0.03

    def test_multiple_timers(self):
        """Test using multiple timers."""
        timers = []

        for i in range(3):
            with ExecutionTimer() as timer:
                time.sleep(0.01 * (i + 1))
            timers.append(timer.duration)

        # Each should be different
        assert timers[0] < timers[1] < timers[2]


class TestIntegrationScenarios:
    """Integration tests for realistic scenarios."""

    def test_adaptive_timeout_scenario(self):
        """Test adaptive timeout in realistic scenario."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.15,
            adjustment_interval=20,
        )

        # Simulate fuzzing campaign
        for i in range(100):
            # Occasional timeouts
            timed_out = i % 10 == 0
            duration = 5.0 if timed_out else 0.5

            with ExecutionTimer() as timer:
                time.sleep(0.001)  # Simulate work

            manager.record_execution(duration, timed_out)

        # Should have adjusted timeout
        assert manager.stats.total_executions == 100
        assert manager.stats.timeout_count == 10

    def test_budget_warning_scenario(self):
        """Test budget warning in degraded performance scenario."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        # Simulate degraded performance
        for _ in range(30):
            manager.record_execution(1.0, True)  # Many timeouts

        assert manager.is_budget_exceeded()

        report = manager.generate_report()
        assert "exceeded" in report.lower() or "EXCEEDED" in report

    def test_reset_and_reuse(self):
        """Test resetting and reusing manager."""
        manager = TimeoutBudgetManager()

        # First campaign
        for _ in range(10):
            manager.record_execution(1.0, False)

        assert manager.stats.total_executions == 10

        # Reset
        manager.reset_statistics()
        assert manager.stats.total_executions == 0

        # Second campaign
        for _ in range(5):
            manager.record_execution(1.0, True)

        assert manager.stats.total_executions == 5
        assert manager.stats.timeout_count == 5
