"""Comprehensive tests for utils/timeout_budget.py

Tests cover timeout statistics tracking, budget management,
adaptive timeout adjustment, and timeout enforcement.
"""

import time

import pytest

from dicom_fuzzer.core.session.timeout_budget import (
    ExecutionTimer,
    TimeoutBudget,
    TimeoutBudgetManager,
    TimeoutStatistics,
)

# ============================================================================
# Test TimeoutStatistics
# ============================================================================


class TestTimeoutStatistics:
    """Test TimeoutStatistics dataclass."""

    def test_default_values(self):
        """Test default statistics values."""
        stats = TimeoutStatistics()

        assert stats.total_time == 0.0
        assert stats.timeout_time == 0.0
        assert stats.successful_time == 0.0
        assert stats.total_executions == 0
        assert stats.timeout_count == 0
        assert stats.successful_count == 0

    def test_timeout_ratio_no_time(self):
        """Test timeout ratio when no time recorded."""
        stats = TimeoutStatistics()

        assert stats.timeout_ratio == 0.0

    def test_timeout_ratio_calculation(self):
        """Test timeout ratio calculation."""
        stats = TimeoutStatistics()
        stats.total_time = 100.0
        stats.timeout_time = 25.0

        assert stats.timeout_ratio == 0.25

    def test_avg_successful_time_no_executions(self):
        """Test avg successful time with no executions."""
        stats = TimeoutStatistics()

        assert stats.avg_successful_time == 0.0

    def test_avg_successful_time_calculation(self):
        """Test avg successful time calculation."""
        stats = TimeoutStatistics()
        stats.successful_time = 50.0
        stats.successful_count = 10

        assert stats.avg_successful_time == 5.0

    def test_avg_timeout_time_no_timeouts(self):
        """Test avg timeout time with no timeouts."""
        stats = TimeoutStatistics()

        assert stats.avg_timeout_time == 0.0

    def test_avg_timeout_time_calculation(self):
        """Test avg timeout time calculation."""
        stats = TimeoutStatistics()
        stats.timeout_time = 30.0
        stats.timeout_count = 3

        assert stats.avg_timeout_time == 10.0

    def test_str_representation(self):
        """Test string representation."""
        stats = TimeoutStatistics()
        stats.total_time = 100.0
        stats.timeout_time = 10.0
        stats.total_executions = 100
        stats.timeout_count = 5

        result = str(stats)

        assert "10.0%" in result
        assert "5/100" in result


# ============================================================================
# Test TimeoutBudgetManager
# ============================================================================


class TestTimeoutBudgetManagerInit:
    """Test TimeoutBudgetManager initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        manager = TimeoutBudgetManager()

        assert manager.max_timeout_ratio == 0.10
        assert manager.min_timeout == 1.0
        assert manager.max_timeout == 60.0
        assert manager.adjustment_interval == 100
        assert manager.current_timeout == 1.0

    def test_custom_initialization(self):
        """Test custom initialization."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.20,
            min_timeout=0.5,
            max_timeout=30.0,
            adjustment_interval=50,
        )

        assert manager.max_timeout_ratio == 0.20
        assert manager.min_timeout == 0.5
        assert manager.max_timeout == 30.0
        assert manager.adjustment_interval == 50


class TestRecordExecution:
    """Test record_execution method."""

    def test_record_successful_execution(self):
        """Test recording successful execution."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=0.5, timed_out=False)

        assert manager.stats.total_executions == 1
        assert manager.stats.successful_count == 1
        assert manager.stats.timeout_count == 0
        assert manager.stats.total_time == 0.5
        assert manager.stats.successful_time == 0.5

    def test_record_timeout_execution(self):
        """Test recording timed out execution."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=5.0, timed_out=True)

        assert manager.stats.total_executions == 1
        assert manager.stats.successful_count == 0
        assert manager.stats.timeout_count == 1
        assert manager.stats.timeout_time == 5.0

    def test_record_multiple_executions(self):
        """Test recording multiple executions."""
        manager = TimeoutBudgetManager()

        manager.record_execution(0.5, timed_out=False)
        manager.record_execution(1.0, timed_out=False)
        manager.record_execution(5.0, timed_out=True)

        assert manager.stats.total_executions == 3
        assert manager.stats.successful_count == 2
        assert manager.stats.timeout_count == 1

    def test_record_triggers_adjustment(self):
        """Test that recording triggers adjustment at interval."""
        manager = TimeoutBudgetManager(adjustment_interval=10)

        # Record enough executions to trigger adjustment
        for i in range(15):
            manager.record_execution(0.5, timed_out=False)

        # Should have triggered adjustment once (at 10)
        assert manager.executions_since_adjustment == 5


class TestIsBudgetExceeded:
    """Test is_budget_exceeded method."""

    def test_not_exceeded_no_time(self):
        """Test budget not exceeded with no time."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        assert manager.is_budget_exceeded() is False

    def test_not_exceeded_under_limit(self):
        """Test budget not exceeded when under limit."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 5.0  # 5%

        assert manager.is_budget_exceeded() is False

    def test_exceeded_over_limit(self):
        """Test budget exceeded when over limit."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 20.0  # 20%

        assert manager.is_budget_exceeded() is True


class TestGetRecommendedTimeout:
    """Test get_recommended_timeout method."""

    def test_returns_current_timeout(self):
        """Test returns current timeout value."""
        manager = TimeoutBudgetManager(min_timeout=2.0)

        assert manager.get_recommended_timeout() == 2.0


class TestAdjustTimeout:
    """Test _adjust_timeout method."""

    def test_no_adjustment_insufficient_data(self):
        """Test no adjustment with insufficient data."""
        manager = TimeoutBudgetManager(min_timeout=5.0)

        # Less than 10 executions
        for i in range(5):
            manager.record_execution(0.5, timed_out=False)

        manager._adjust_timeout()

        assert manager.current_timeout == 5.0  # Unchanged

    def test_reduction_when_exceeded(self):
        """Test timeout reduction when budget exceeded."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10, min_timeout=1.0, max_timeout=10.0
        )
        manager.current_timeout = 5.0

        # Set up stats to exceed budget
        manager.stats.total_executions = 100
        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 50.0  # 50% > 10%

        manager._adjust_timeout()

        # Should be reduced by 20%
        assert manager.current_timeout == 4.0

    def test_reduction_respects_minimum(self):
        """Test timeout reduction respects minimum."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10, min_timeout=1.0, max_timeout=10.0
        )
        manager.current_timeout = 1.0  # Already at minimum

        # Set up stats to exceed budget
        manager.stats.total_executions = 100
        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 50.0

        manager._adjust_timeout()

        # Should stay at minimum
        assert manager.current_timeout == 1.0

    def test_increase_when_low_timeout_ratio(self):
        """Test timeout increase when timeout ratio is low."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10, min_timeout=1.0, max_timeout=10.0
        )
        manager.current_timeout = 5.0

        # Set up stats with very low timeout ratio (< 5%)
        manager.stats.total_executions = 100
        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 1.0  # 1% < 5%

        manager._adjust_timeout()

        # Should be increased by 10%
        assert manager.current_timeout == 5.5

    def test_increase_respects_maximum(self):
        """Test timeout increase respects maximum."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10, min_timeout=1.0, max_timeout=10.0
        )
        manager.current_timeout = 10.0  # Already at maximum

        # Set up stats with very low timeout ratio
        manager.stats.total_executions = 100
        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 1.0

        manager._adjust_timeout()

        # Should stay at maximum
        assert manager.current_timeout == 10.0


class TestGetStatistics:
    """Test get_statistics method."""

    def test_returns_stats_object(self):
        """Test returns statistics object."""
        manager = TimeoutBudgetManager()

        stats = manager.get_statistics()

        assert isinstance(stats, TimeoutStatistics)
        assert stats is manager.stats


class TestResetStatistics:
    """Test reset_statistics method."""

    def test_reset_clears_stats(self):
        """Test reset clears statistics."""
        manager = TimeoutBudgetManager()

        # Add some data
        manager.record_execution(1.0, timed_out=False)
        manager.record_execution(2.0, timed_out=True)

        manager.reset_statistics()

        assert manager.stats.total_executions == 0
        assert manager.stats.total_time == 0.0
        assert manager.executions_since_adjustment == 0


class TestGenerateReport:
    """Test generate_report method."""

    def test_report_structure(self):
        """Test report has expected structure."""
        manager = TimeoutBudgetManager()

        # Add some data
        manager.record_execution(0.5, timed_out=False)
        manager.record_execution(5.0, timed_out=True)

        report = manager.generate_report()

        assert "TIMEOUT BUDGET REPORT" in report
        assert "Total Executions" in report
        assert "Total Time" in report
        assert "Timeout Ratio" in report
        assert "RECOMMENDATIONS" in report

    def test_report_shows_exceeded(self):
        """Test report shows exceeded status."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        # Set up exceeded budget
        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 50.0
        manager.stats.total_executions = 100
        manager.stats.timeout_count = 50

        report = manager.generate_report()

        assert "EXCEEDED" in report

    def test_report_shows_ok(self):
        """Test report shows OK status."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        # Set up under budget
        manager.stats.total_time = 100.0
        manager.stats.timeout_time = 5.0
        manager.stats.total_executions = 100
        manager.stats.timeout_count = 5
        manager.stats.successful_count = 95

        report = manager.generate_report()

        assert "OK" in report


# ============================================================================
# Test ExecutionTimer
# ============================================================================


class TestExecutionTimer:
    """Test ExecutionTimer context manager."""

    def test_timer_measures_duration(self):
        """Test timer measures duration."""
        with ExecutionTimer() as timer:
            time.sleep(0.01)  # 10ms

        assert timer.duration >= 0.01
        assert timer.start_time is not None
        assert timer.end_time is not None

    def test_timer_initial_values(self):
        """Test timer initial values."""
        timer = ExecutionTimer()

        assert timer.start_time is None
        assert timer.end_time is None
        assert timer.duration == 0.0

    def test_timer_with_exception(self):
        """Test timer still records when exception occurs."""
        timer = ExecutionTimer()

        try:
            with timer:
                time.sleep(0.01)
                raise ValueError("Test error")
        except ValueError:
            pass

        assert timer.duration >= 0.01


# ============================================================================
# Test TimeoutBudget
# ============================================================================


class TestTimeoutBudget:
    """Test TimeoutBudget class."""

    def test_initialization(self):
        """Test initialization."""
        budget = TimeoutBudget(total_seconds=10.0)

        assert budget.total_seconds == 10.0
        assert budget.remaining_seconds == 10.0
        assert budget.start_time is not None

    def test_is_exhausted_not_exhausted(self):
        """Test is_exhausted when budget remains."""
        budget = TimeoutBudget(total_seconds=10.0)

        assert budget.is_exhausted() is False

    def test_is_exhausted_after_time_passes(self):
        """Test is_exhausted after time passes."""
        budget = TimeoutBudget(total_seconds=0.01)

        time.sleep(0.02)

        assert budget.is_exhausted() is True
        assert budget.remaining_seconds == 0

    def test_remaining_seconds_updates(self):
        """Test remaining seconds updates on check."""
        budget = TimeoutBudget(total_seconds=10.0)

        time.sleep(0.01)
        budget.is_exhausted()

        assert budget.remaining_seconds < 10.0


class TestTimeoutBudgetOperationContext:
    """Test TimeoutBudget.operation_context method."""

    def test_operation_context_success(self):
        """Test operation context with successful operation."""
        budget = TimeoutBudget(total_seconds=10.0)

        with budget.operation_context("test_op") as ctx:
            time.sleep(0.01)

        # Should complete without error
        assert budget.remaining_seconds < 10.0

    def test_operation_context_exhausted(self):
        """Test operation context when budget exhausted."""
        budget = TimeoutBudget(total_seconds=0.01)

        time.sleep(0.02)  # Exhaust budget

        with pytest.raises(TimeoutError, match="exhausted"):
            with budget.operation_context("test_op"):
                pass

    def test_operation_context_updates_remaining(self):
        """Test operation context updates remaining time."""
        budget = TimeoutBudget(total_seconds=10.0)
        initial = budget.remaining_seconds

        with budget.operation_context("test_op"):
            time.sleep(0.01)

        assert budget.remaining_seconds < initial

    def test_operation_context_with_exception(self):
        """Test operation context still updates on exception."""
        budget = TimeoutBudget(total_seconds=10.0)

        try:
            with budget.operation_context("test_op"):
                time.sleep(0.01)
                raise ValueError("Test error")
        except ValueError:
            pass

        assert budget.remaining_seconds < 10.0


# ============================================================================
# Test Integration
# ============================================================================


class TestIntegration:
    """Integration tests for timeout budget components."""

    def test_timer_with_manager(self):
        """Test using ExecutionTimer with TimeoutBudgetManager."""
        manager = TimeoutBudgetManager()

        with ExecutionTimer() as timer:
            time.sleep(0.01)
            timed_out = False

        manager.record_execution(timer.duration, timed_out)

        assert manager.stats.total_executions == 1
        assert manager.stats.successful_count == 1

    def test_multiple_operations_with_budget(self):
        """Test multiple operations with TimeoutBudget."""
        budget = TimeoutBudget(total_seconds=1.0)

        for i in range(5):
            if budget.is_exhausted():
                break

            with budget.operation_context(f"op_{i}"):
                time.sleep(0.01)

        assert budget.remaining_seconds < 1.0

    def test_adaptive_timeout_scenario(self):
        """Test realistic adaptive timeout scenario."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10,
            min_timeout=1.0,
            max_timeout=10.0,
            adjustment_interval=20,
        )
        manager.current_timeout = 5.0

        # Simulate many successful executions
        for _ in range(15):
            manager.record_execution(0.1, timed_out=False)

        # Simulate high timeout rate
        for _ in range(10):
            manager.record_execution(5.0, timed_out=True)

        # Should have triggered adjustment and reduced timeout
        assert manager.stats.total_executions == 25
        assert manager.is_budget_exceeded() is True

    def test_report_after_full_simulation(self):
        """Test report generation after full simulation."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10, adjustment_interval=50)

        # Simulate mixed executions
        for i in range(100):
            timed_out = i % 10 == 0  # 10% timeout
            duration = 5.0 if timed_out else 0.5
            manager.record_execution(duration, timed_out)

        report = manager.generate_report()

        assert "100" in report  # Total executions
        assert "RECOMMENDATIONS" in report
