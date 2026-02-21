"""Mutation effectiveness tracking.

Tracks mutation effectiveness to identify which strategies find the most
bugs and optimize fuzzing efficiency.
"""

from dataclasses import dataclass, field


@dataclass
class MutationStatistics:
    """Statistics for a specific mutation strategy."""

    strategy_name: str = ""
    times_used: int = 0
    unique_outputs: int = 0
    crashes_found: int = 0
    validation_failures: int = 0
    total_duration: float = 0.0
    file_sizes: list[int] = field(default_factory=list)
    total_mutations: int = 0
    total_executions: int = 0

    def effectiveness_score(self) -> float:
        """Calculate effectiveness score (0-1).

        Returns:
            Effectiveness score between 0 and 1

        """
        if self.times_used == 0:
            return 0.0

        # Weighted components
        crash_score = min(self.crashes_found * 10, 100) / 100  # Max 10 crashes = 1.0
        failure_score = (
            min(self.validation_failures * 2, 100) / 100
        )  # Max 50 failures = 1.0
        diversity_score = min(self.unique_outputs, 100) / 100  # Max 100 unique = 1.0

        # Weighted average (crashes weighted highest)
        score = crash_score * 0.6 + failure_score * 0.25 + diversity_score * 0.15

        return min(score, 1.0)

    def avg_duration(self) -> float:
        """Calculate average duration per use."""
        if self.times_used > 0:
            return self.total_duration / self.times_used
        return 0.0

    def avg_file_size(self) -> int:
        """Calculate average file size."""
        if self.file_sizes:
            return sum(self.file_sizes) // len(self.file_sizes)
        return 0

    def record_mutation(self, strategy: str) -> None:
        """Record a mutation operation.

        Args:
            strategy: Name of mutation strategy used

        """
        self.strategy_name = strategy
        self.times_used += 1
        self.total_mutations += 1

    def record_execution(self, duration: float) -> None:
        """Record an execution.

        Args:
            duration: Execution duration in seconds

        """
        self.total_executions += 1
        self.total_duration += duration
