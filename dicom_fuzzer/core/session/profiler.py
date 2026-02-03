"""Performance Profiler - Fuzzing Campaign Metrics.

Tracks execution time, memory usage, and throughput for fuzzing campaigns.
Enables performance optimization and resource monitoring.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, TypeVar

import psutil

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class FuzzingMetrics:
    """Metrics collected during a fuzzing campaign.

    CONCEPT: We track multiple dimensions of performance:
    - Time metrics: How long operations take
    - Throughput metrics: Operations per second
    - Resource metrics: Memory and CPU usage
    - Success metrics: Valid outputs, crashes found
    """

    # Time metrics
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    total_duration: float = 0.0  # seconds

    # Throughput metrics
    files_generated: int = 0
    mutations_applied: int = 0
    validations_performed: int = 0
    crashes_found: int = 0

    # Resource metrics
    peak_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    cpu_samples: list[float] = field(default_factory=list)

    # Strategy metrics
    strategy_usage: dict[str, int] = field(default_factory=dict)
    strategy_timing: dict[str, float] = field(default_factory=dict)

    def throughput_per_second(self) -> float:
        """Calculate files generated per second."""
        if self.total_duration > 0:
            return self.files_generated / self.total_duration
        return 0.0

    def avg_time_per_file(self) -> float:
        """Calculate average time per file."""
        if self.files_generated > 0:
            return self.total_duration / self.files_generated
        return 0.0

    def estimated_time_remaining(self, target: int) -> float:
        """Estimate time remaining to reach target.

        Args:
            target: Target number of files to generate

        Returns:
            Estimated seconds remaining

        """
        if self.files_generated == 0:
            return 0.0

        remaining = target - self.files_generated
        if remaining <= 0:
            return 0.0

        avg_time = self.avg_time_per_file()
        return remaining * avg_time


class PerformanceProfiler:
    """Tracks performance metrics during fuzzing campaigns.

    CONCEPT: Context manager pattern for automatic tracking.
    Usage:
        with PerformanceProfiler() as profiler:
            # Do fuzzing work
            profiler.record_file_generated()
            profiler.record_mutation("header")

        # Metrics automatically finalized
        print(profiler.metrics.throughput_per_second())
    """

    def __init__(self) -> None:
        """Initialize profiler."""
        self.metrics = FuzzingMetrics()
        self.process = psutil.Process()
        self._cpu_monitor_interval = 1.0  # seconds

    def __enter__(self) -> "PerformanceProfiler":
        """Start profiling session."""
        self.metrics.start_time = datetime.now()
        self._start_cpu_monitoring()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """End profiling session and finalize metrics."""
        self.metrics.end_time = datetime.now()
        self.metrics.total_duration = (
            self.metrics.end_time - self.metrics.start_time
        ).total_seconds()
        self._finalize_cpu_metrics()

    def _start_cpu_monitoring(self) -> None:
        """Start monitoring CPU usage."""
        # Take initial CPU sample
        self.process.cpu_percent(interval=None)

    def _sample_resources(self) -> None:
        """Sample current resource usage."""
        # Memory
        memory_info = self.process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        if memory_mb > self.metrics.peak_memory_mb:
            self.metrics.peak_memory_mb = memory_mb

        # CPU
        cpu_percent = self.process.cpu_percent(interval=None)
        self.metrics.cpu_samples.append(cpu_percent)

    def _finalize_cpu_metrics(self) -> None:
        """Calculate final CPU metrics."""
        if self.metrics.cpu_samples:
            self.metrics.avg_cpu_percent = sum(self.metrics.cpu_samples) / len(
                self.metrics.cpu_samples
            )

    def record_file_generated(self, strategy: str | None = None) -> None:
        """Record that a file was generated.

        Args:
            strategy: Strategy used to generate file

        """
        self.metrics.files_generated += 1

        if strategy:
            self.metrics.strategy_usage[strategy] = (
                self.metrics.strategy_usage.get(strategy, 0) + 1
            )

        # Sample resources periodically
        if self.metrics.files_generated % 10 == 0:
            self._sample_resources()

    def record_mutation(self, strategy: str, duration: float = 0.0) -> None:
        """Record that a mutation was applied.

        Args:
            strategy: Strategy that performed mutation
            duration: Time taken for mutation (seconds)

        """
        self.metrics.mutations_applied += 1
        self.metrics.strategy_usage[strategy] = (
            self.metrics.strategy_usage.get(strategy, 0) + 1
        )

        if duration > 0:
            self.metrics.strategy_timing[strategy] = (
                self.metrics.strategy_timing.get(strategy, 0.0) + duration
            )

    def record_validation(self) -> None:
        """Record that a validation was performed."""
        self.metrics.validations_performed += 1

    def record_crash(self) -> None:
        """Record that a crash was found."""
        self.metrics.crashes_found += 1

    def get_progress_report(self, target: int | None = None) -> str:
        """Generate a progress report.

        Args:
            target: Target number of files (optional)

        Returns:
            Formatted progress report

        """
        elapsed = (datetime.now() - self.metrics.start_time).total_seconds()
        throughput = self.metrics.files_generated / elapsed if elapsed > 0 else 0

        report = [
            "=== Fuzzing Campaign Progress ===",
            f"Files Generated: {self.metrics.files_generated}",
            f"Mutations Applied: {self.metrics.mutations_applied}",
            f"Crashes Found: {self.metrics.crashes_found}",
            f"Elapsed Time: {timedelta(seconds=int(elapsed))}",
            f"Throughput: {throughput:.2f} files/sec",
            f"Memory Usage: {self.metrics.peak_memory_mb:.1f} MB",
        ]

        if target and target > self.metrics.files_generated:
            remaining = self.metrics.estimated_time_remaining(target)
            report.append(
                f"Estimated Time Remaining: {timedelta(seconds=int(remaining))}"
            )
            progress = (self.metrics.files_generated / target) * 100
            report.append(f"Progress: {progress:.1f}%")

        if self.metrics.strategy_usage:
            report.append("\nStrategy Usage:")
            for strategy, count in sorted(
                self.metrics.strategy_usage.items(), key=lambda x: x[1], reverse=True
            ):
                percentage = (count / self.metrics.mutations_applied) * 100
                report.append(f"  {strategy}: {count} ({percentage:.1f}%)")

        return "\n".join(report)

    def get_summary(self) -> dict[str, Any]:
        """Get metrics summary as dictionary.

        Returns:
            Dictionary with all metrics

        """
        return {
            "duration_seconds": self.metrics.total_duration,
            "files_generated": self.metrics.files_generated,
            "mutations_applied": self.metrics.mutations_applied,
            "validations_performed": self.metrics.validations_performed,
            "crashes_found": self.metrics.crashes_found,
            "throughput_per_second": self.metrics.throughput_per_second(),
            "avg_time_per_file": self.metrics.avg_time_per_file(),
            "peak_memory_mb": self.metrics.peak_memory_mb,
            "avg_cpu_percent": self.metrics.avg_cpu_percent,
            "strategy_usage": dict(self.metrics.strategy_usage),
            "strategy_timing": dict(self.metrics.strategy_timing),
            "start_time": self.metrics.start_time.isoformat(),
            "end_time": (
                self.metrics.end_time.isoformat() if self.metrics.end_time else None
            ),
        }


class StrategyTimer:
    """Context manager for timing individual strategy operations.

    CONCEPT: Decorator pattern for automatic timing.
    Usage:
        with StrategyTimer(profiler, "header") as timer:
            # Perform mutation
            pass
        # Time automatically recorded
    """

    def __init__(self, profiler: PerformanceProfiler, strategy: str) -> None:
        """Initialize timer.

        Args:
            profiler: Profiler to record timing to
            strategy: Strategy being timed

        """
        self.profiler = profiler
        self.strategy = strategy
        self.start_time = 0.0

    def __enter__(self) -> "StrategyTimer":
        """Start timing."""
        self.start_time = time.time()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """End timing and record."""
        duration = time.time() - self.start_time
        self.profiler.record_mutation(self.strategy, duration)


def profile_function(strategy: str) -> Callable[[F], F]:
    """Decorator to profile a function.

    CONCEPT: Decorator pattern for automatic profiling.

    Usage:
        @profile_function("header")
        def mutate_header(dataset):
            # Perform mutation
            pass
    """

    def decorator(func: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            result = func(*args, **kwargs)
            duration = time.time() - start_time

            # Log timing (could integrate with profiler if available)
            print(f"[PROFILE] {strategy}.{func.__name__}: {duration:.3f}s")

            return result

        return wrapper  # type: ignore[return-value]

    return decorator
