"""Timeout Budget Management

CONCEPT: Manage global timeout budget for fuzzing campaigns to prevent
runaway campaigns that spend too much time on timeouts.

STABILITY: Adaptive timeout adjustment prevents wasting resources on
consistently slow or hanging inputs.
"""

import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TimeoutStatistics:
    """Statistics for timeout budget tracking.

    Tracks how much time is spent on timeouts vs successful executions.
    """

    total_time: float = 0.0
    timeout_time: float = 0.0
    successful_time: float = 0.0
    total_executions: int = 0
    timeout_count: int = 0
    successful_count: int = 0

    @property
    def timeout_ratio(self) -> float:
        """Percentage of time spent on timeouts (0.0 - 1.0)."""
        if self.total_time == 0:
            return 0.0
        return self.timeout_time / self.total_time

    @property
    def avg_successful_time(self) -> float:
        """Average execution time for successful runs."""
        if self.successful_count == 0:
            return 0.0
        return self.successful_time / self.successful_count

    @property
    def avg_timeout_time(self) -> float:
        """Average execution time for timed-out runs."""
        if self.timeout_count == 0:
            return 0.0
        return self.timeout_time / self.timeout_count

    def __str__(self) -> str:
        """String representation for logging."""
        return (
            f"Timeout Budget: {self.timeout_ratio * 100:.1f}% of time spent on timeouts "
            f"({self.timeout_count}/{self.total_executions} executions)"
        )


class TimeoutBudgetManager:
    """Manage timeout budget for fuzzing campaigns.

    CONCEPT: Prevent runaway campaigns by:
    1. Tracking time spent on timeouts vs successful runs
    2. Adjusting timeout dynamically if too much time wasted
    3. Flagging when timeout budget is exceeded

    WHY: Some inputs may consistently hang/timeout, wasting valuable
    fuzzing time. Adaptive timeout management keeps campaign productive.
    """

    def __init__(
        self,
        max_timeout_ratio: float = 0.10,
        min_timeout: float = 1.0,
        max_timeout: float = 60.0,
        adjustment_interval: int = 100,
    ):
        """Initialize timeout budget manager.

        Args:
            max_timeout_ratio: Max % of time allowed for timeouts (0.10 = 10%)
            min_timeout: Minimum timeout value in seconds
            max_timeout: Maximum timeout value in seconds
            adjustment_interval: Adjust timeout every N executions

        """
        self.max_timeout_ratio = max_timeout_ratio
        self.min_timeout = min_timeout
        self.max_timeout = max_timeout
        self.adjustment_interval = adjustment_interval

        # Statistics
        self.stats = TimeoutStatistics()

        # Current timeout value
        self.current_timeout = min_timeout

        # Execution counter for adjustment
        self.executions_since_adjustment = 0

        logger.info(
            f"TimeoutBudgetManager initialized: max_ratio={max_timeout_ratio * 100:.1f}%, "
            f"timeout_range=[{min_timeout}, {max_timeout}]s"
        )

    def record_execution(
        self, duration: float, timed_out: bool, start_time: float | None = None
    ):
        """Record execution result and update statistics.

        Args:
            duration: Execution duration in seconds
            timed_out: Whether execution timed out
            start_time: Optional start timestamp for precise timing

        """
        # Update statistics
        self.stats.total_executions += 1
        self.stats.total_time += duration

        if timed_out:
            self.stats.timeout_count += 1
            self.stats.timeout_time += duration
            logger.debug(f"Timeout recorded: {duration:.2f}s")
        else:
            self.stats.successful_count += 1
            self.stats.successful_time += duration

        self.executions_since_adjustment += 1

        # Check if adjustment needed
        if self.executions_since_adjustment >= self.adjustment_interval:
            self._adjust_timeout()
            self.executions_since_adjustment = 0

    def is_budget_exceeded(self) -> bool:
        """Check if timeout budget has been exceeded.

        Returns:
            True if too much time spent on timeouts

        """
        if self.stats.total_time == 0:
            return False

        exceeded = self.stats.timeout_ratio > self.max_timeout_ratio

        if exceeded:
            logger.warning(
                f"Timeout budget exceeded: {self.stats.timeout_ratio * 100:.1f}% "
                f"(max: {self.max_timeout_ratio * 100:.1f}%)"
            )

        return exceeded

    def get_recommended_timeout(self) -> float:
        """Get recommended timeout value based on current statistics.

        Returns:
            Recommended timeout in seconds

        """
        return self.current_timeout

    def _adjust_timeout(self):
        """Adjust timeout based on recent statistics.

        CONCEPT: If spending too much time on timeouts, reduce timeout.
        If success rate is high, can slightly increase for edge cases.
        """
        if self.stats.total_executions < 10:
            # Not enough data yet
            return

        old_timeout = self.current_timeout

        # Strategy: Adjust based on timeout ratio
        if self.is_budget_exceeded():
            # Too many timeouts - reduce timeout by 20%
            reduction_factor = 0.8
            self.current_timeout = max(
                self.min_timeout, self.current_timeout * reduction_factor
            )

            logger.info(
                f"Timeout reduced: {old_timeout:.2f}s -> {self.current_timeout:.2f}s "
                f"(too many timeouts: {self.stats.timeout_ratio * 100:.1f}%)"
            )

        elif self.stats.timeout_ratio < self.max_timeout_ratio * 0.5:
            # Very few timeouts - can slightly increase timeout for edge cases
            # But be conservative - only increase by 10%
            increase_factor = 1.1
            self.current_timeout = min(
                self.max_timeout, self.current_timeout * increase_factor
            )

            if self.current_timeout != old_timeout:
                logger.debug(
                    f"Timeout increased: {old_timeout:.2f}s -> {self.current_timeout:.2f}s "
                    f"(low timeout rate: {self.stats.timeout_ratio * 100:.1f}%)"
                )

    def get_statistics(self) -> TimeoutStatistics:
        """Get current timeout statistics.

        Returns:
            TimeoutStatistics object

        """
        return self.stats

    def reset_statistics(self):
        """Reset statistics (for new campaign or phase)."""
        self.stats = TimeoutStatistics()
        self.executions_since_adjustment = 0
        logger.info("Timeout budget statistics reset")

    def generate_report(self) -> str:
        """Generate human-readable timeout budget report.

        Returns:
            Formatted report string

        """
        stats = self.stats
        report = []

        report.append("=" * 60)
        report.append("TIMEOUT BUDGET REPORT")
        report.append("=" * 60)
        report.append(
            f"Total Executions:     {stats.total_executions:,} "
            f"({stats.successful_count:,} success, {stats.timeout_count:,} timeout)"
        )
        report.append(f"Total Time:           {stats.total_time:.1f}s")
        report.append(f"Timeout Time:         {stats.timeout_time:.1f}s")
        report.append(f"Successful Time:      {stats.successful_time:.1f}s")
        report.append("")
        report.append(f"Timeout Ratio:        {stats.timeout_ratio * 100:.1f}%")
        report.append(
            f"Budget Limit:         {self.max_timeout_ratio * 100:.1f}% "
            f"({'EXCEEDED' if self.is_budget_exceeded() else 'OK'})"
        )
        report.append("")
        report.append(f"Current Timeout:      {self.current_timeout:.2f}s")
        report.append(f"Avg Successful Time:  {stats.avg_successful_time:.2f}s")
        if stats.timeout_count > 0:
            report.append(f"Avg Timeout Time:     {stats.avg_timeout_time:.2f}s")
        report.append("")

        # Recommendations
        report.append("RECOMMENDATIONS:")
        if self.is_budget_exceeded():
            report.append("  [!] Timeout budget exceeded - timeout has been reduced")
            report.append("  [!] Consider filtering out consistently slow inputs")
        else:
            report.append("  [+] Timeout budget within acceptable limits")

        report.append("=" * 60)

        return "\n".join(report)


# Convenience function for timing executions
class ExecutionTimer:
    """Context manager for timing executions.

    Usage:
        with ExecutionTimer() as timer:
            result = run_test()
            timed_out = (result == TIMEOUT)

        budget_manager.record_execution(
            duration=timer.duration,
            timed_out=timed_out
        )
    """

    def __init__(self):
        """Initialize timer."""
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.duration: float = 0.0

    def __enter__(self):
        """Start timer."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timer."""
        self.end_time = time.time()
        if self.start_time:
            self.duration = self.end_time - self.start_time
        return False  # Don't suppress exceptions


class TimeoutBudget:
    """Simple timeout budget for operations with context manager support.

    Provides a simple API for enforcing timeouts on operations using
    context managers. For test compatibility.
    """

    def __init__(self, total_seconds: float):
        """Initialize timeout budget.

        Args:
            total_seconds: Total timeout budget in seconds

        """
        self.total_seconds = total_seconds
        self.start_time = time.time()
        self.remaining_seconds = total_seconds

    def is_exhausted(self) -> bool:
        """Check if timeout budget is exhausted.

        Returns:
            True if budget exhausted, False otherwise

        """
        elapsed = time.time() - self.start_time
        self.remaining_seconds = max(0, self.total_seconds - elapsed)
        return self.remaining_seconds <= 0

    def operation_context(self, operation_name: str):
        """Context manager for timeout-enforced operations.

        Args:
            operation_name: Name of the operation (for logging)

        Returns:
            Context manager that enforces timeout

        Raises:
            TimeoutError: If operation exceeds remaining budget

        """
        return _TimeoutContext(self, operation_name)


class _TimeoutContext:
    """Internal context manager for timeout enforcement."""

    def __init__(self, budget: TimeoutBudget, operation_name: str):
        self.budget = budget
        self.operation_name = operation_name
        self.start_time = None

    def __enter__(self):
        """Enter context - check if budget available."""
        if self.budget.is_exhausted():
            raise TimeoutError(f"Timeout budget exhausted before {self.operation_name}")
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context - update remaining budget."""
        if self.start_time:
            elapsed = time.time() - self.start_time
            self.budget.remaining_seconds = max(
                0, self.budget.remaining_seconds - elapsed
            )
        return False  # Don't suppress exceptions
