"""Statistics Collector - Mutation Effectiveness Tracking

LEARNING OBJECTIVE: This module demonstrates statistical analysis of
fuzzing campaigns to understand which mutations are most effective.

CONCEPT: Not all mutations are equally valuable. By tracking statistics:
1. Identify which strategies find the most bugs
2. Optimize mutation selection
3. Understand coverage patterns
4. Improve fuzzing efficiency

This enables data-driven fuzzing optimization.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class IterationData:
    """Data for a single fuzzing iteration.

    CONCEPT: Track per-iteration metrics for fine-grained analysis:
    - Which file was fuzzed?
    - How many mutations were applied?
    - What was the severity level?
    - When did it occur?
    """

    iteration_number: int
    file_path: str
    mutations_applied: int
    severity: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class MutationStatistics:
    """Statistics for a specific mutation strategy.

    CONCEPT: Track both usage and effectiveness:
    - How often was this mutation used?
    - How many unique outputs did it create?
    - Did it find any crashes?
    - How long did it take?
    """

    strategy_name: str = ""
    times_used: int = 0
    unique_outputs: int = 0
    crashes_found: int = 0
    validation_failures: int = 0
    total_duration: float = 0.0
    file_sizes: list[int] = field(default_factory=list)
    # For compatibility with test expectations
    total_mutations: int = 0
    total_executions: int = 0

    def effectiveness_score(self) -> float:
        """Calculate effectiveness score (0-1).

        CONCEPT: Weighted score considering:
        - Crash discovery (most important)
        - Validation failures (interesting edge cases)
        - Unique outputs (diversity)
        - Performance (speed)

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
        """Record a mutation operation (for test compatibility).

        Args:
            strategy: Name of mutation strategy used

        """
        self.strategy_name = strategy
        self.times_used += 1
        self.total_mutations += 1

    def record_execution(self, duration: float) -> None:
        """Record an execution (for test compatibility).

        Args:
            duration: Execution duration in seconds

        """
        self.total_executions += 1
        self.total_duration += duration


class StatisticsCollector:
    """Collects and analyzes fuzzing campaign statistics.

    CONCEPT: Central repository for all statistics.
    Tracks per-strategy metrics and campaign-wide patterns.
    """

    def __init__(self) -> None:
        """Initialize statistics collector."""
        self.strategies: dict[str, MutationStatistics] = {}
        self.campaign_start = datetime.now()

        # Campaign-wide tracking
        self.total_files_generated = 0
        self.total_mutations_applied = 0
        self.total_crashes_found = 0

        # Uniqueness tracking
        self.seen_hashes: set[str] = set()
        self.crash_hashes: set[str] = set()

        # Coverage tracking (which tags were mutated)
        self.mutated_tags: dict[str, int] = defaultdict(int)

        # Iteration tracking
        self.iterations: list[IterationData] = []
        self.total_iterations = 0

        # Severity-based statistics
        self.severity_stats: dict[str, dict] = defaultdict(
            lambda: {"count": 0, "mutations": 0}
        )

    def record_mutation(
        self,
        strategy: str,
        duration: float = 0.0,
        output_hash: str | None = None,
        file_size: int | None = None,
    ) -> None:
        """Record a mutation operation.

        Args:
            strategy: Name of strategy used
            duration: Time taken for mutation (seconds)
            output_hash: Hash of output file (for uniqueness tracking)
            file_size: Size of generated file (bytes)

        """
        # Get or create strategy stats
        if strategy not in self.strategies:
            self.strategies[strategy] = MutationStatistics(strategy_name=strategy)

        stats = self.strategies[strategy]
        stats.times_used += 1
        stats.total_duration += duration
        self.total_mutations_applied += 1

        # Track uniqueness
        if output_hash:
            if output_hash not in self.seen_hashes:
                stats.unique_outputs += 1
                self.seen_hashes.add(output_hash)

        # Track file size
        if file_size:
            stats.file_sizes.append(file_size)

    def record_crash(self, strategy: str, crash_hash: str) -> None:
        """Record a crash discovered by a strategy.

        Args:
            strategy: Strategy that found the crash
            crash_hash: Hash of the crash

        """
        if strategy in self.strategies:
            # Only count unique crashes per strategy
            if crash_hash not in self.crash_hashes:
                self.strategies[strategy].crashes_found += 1
                self.crash_hashes.add(crash_hash)
                self.total_crashes_found += 1

    def record_validation_failure(self, strategy: str) -> None:
        """Record a validation failure.

        Args:
            strategy: Strategy that caused validation failure

        """
        if strategy in self.strategies:
            self.strategies[strategy].validation_failures += 1

    def record_file_generated(self) -> None:
        """Record that a file was generated."""
        self.total_files_generated += 1

    def record_tag_mutated(self, tag_name: str) -> None:
        """Record that a DICOM tag was mutated.

        Args:
            tag_name: Name of the tag that was mutated

        """
        self.mutated_tags[tag_name] += 1

    def track_iteration(
        self, file_path: str, mutations_applied: int, severity: str
    ) -> int:
        """Track a fuzzing iteration with detailed metrics.

        CONCEPT: Per-iteration tracking enables:
        - Understanding fuzzing progress over time
        - Analyzing effectiveness by severity level
        - Identifying performance bottlenecks
        - Correlating crashes with specific iterations

        Best practices from fuzzing research:
        - Track exec/s (executions per second) for performance monitoring
        - Record severity levels to analyze mutation effectiveness
        - Maintain iteration history for statistical analysis

        Args:
            file_path: Path to the file being fuzzed
            mutations_applied: Number of mutations applied in this iteration
            severity: Severity level (low/moderate/high) used for this iteration

        Returns:
            int: Iteration number (1-indexed)

        """
        self.total_iterations += 1

        # Create iteration data
        iteration_data = IterationData(
            iteration_number=self.total_iterations,
            file_path=str(Path(file_path).name),  # Store just filename for privacy
            mutations_applied=mutations_applied,
            severity=severity.lower() if severity else "unknown",
        )

        self.iterations.append(iteration_data)

        # Update severity statistics
        severity_key = severity.lower() if severity else "unknown"
        self.severity_stats[severity_key]["count"] += 1
        self.severity_stats[severity_key]["mutations"] += mutations_applied

        return self.total_iterations

    def get_strategy_ranking(self) -> list[tuple]:
        """Get strategies ranked by effectiveness.

        Returns:
            List of (strategy_name, effectiveness_score) tuples, sorted

        """
        rankings = [
            (name, stats.effectiveness_score())
            for name, stats in self.strategies.items()
        ]
        return sorted(rankings, key=lambda x: x[1], reverse=True)

    def get_most_effective_strategy(self) -> str | None:
        """Get the most effective strategy.

        Returns:
            Name of most effective strategy, or None

        """
        rankings = self.get_strategy_ranking()
        if rankings:
            return rankings[0][0]
        return None

    def get_coverage_report(self) -> dict[str, int]:
        """Get coverage report (which tags were mutated).

        Returns:
            Dictionary mapping tag names to mutation counts

        """
        return dict(self.mutated_tags)

    def get_summary(self) -> dict:
        """Get complete statistics summary.

        Returns:
            Dictionary with all statistics

        """
        campaign_duration = (datetime.now() - self.campaign_start).total_seconds()

        # Calculate executions per second (exec/s) - important fuzzing metric
        exec_per_second = (
            self.total_iterations / campaign_duration if campaign_duration > 0 else 0
        )

        return {
            "campaign_duration_seconds": campaign_duration,
            "total_files_generated": self.total_files_generated,
            "total_mutations_applied": self.total_mutations_applied,
            "total_crashes_found": self.total_crashes_found,
            "unique_outputs": len(self.seen_hashes),
            "total_iterations": self.total_iterations,
            "executions_per_second": round(exec_per_second, 2),
            "strategies": {
                name: {
                    "times_used": stats.times_used,
                    "unique_outputs": stats.unique_outputs,
                    "crashes_found": stats.crashes_found,
                    "validation_failures": stats.validation_failures,
                    "effectiveness_score": stats.effectiveness_score(),
                    "avg_duration": stats.avg_duration(),
                    "avg_file_size": stats.avg_file_size(),
                }
                for name, stats in self.strategies.items()
            },
            "strategy_rankings": [
                {"strategy": name, "score": score}
                for name, score in self.get_strategy_ranking()
            ],
            "tag_coverage": dict(self.mutated_tags),
            "severity_statistics": dict(self.severity_stats),
            "iteration_count": len(self.iterations),
        }

    def print_summary(self) -> None:
        """Print a formatted summary to console."""
        print("\n" + "=" * 60)
        print("FUZZING CAMPAIGN STATISTICS")
        print("=" * 60)

        duration = (datetime.now() - self.campaign_start).total_seconds()
        exec_per_second = self.total_iterations / duration if duration > 0 else 0

        print(f"\nCampaign Duration: {duration:.1f}s")
        print(f"Total Iterations: {self.total_iterations}")
        print(f"Executions/Second: {exec_per_second:.2f} exec/s")
        print(f"Files Generated: {self.total_files_generated}")
        print(f"Mutations Applied: {self.total_mutations_applied}")
        print(f"Crashes Found: {self.total_crashes_found}")
        print(f"Unique Outputs: {len(self.seen_hashes)}")

        # Print severity statistics
        if self.severity_stats:
            print("\n--- Severity Distribution ---")
            for severity, stats in sorted(self.severity_stats.items()):
                avg_mutations = (
                    stats["mutations"] / stats["count"] if stats["count"] > 0 else 0
                )
                print(
                    f"  {severity.capitalize()}: {stats['count']} iterations, "
                    f"avg {avg_mutations:.1f} mutations/iter"
                )

        print("\n--- Strategy Effectiveness Rankings ---")
        for rank, (strategy, score) in enumerate(self.get_strategy_ranking(), 1):
            stats = self.strategies[strategy]
            print(
                f"{rank}. {strategy}: {score:.3f} "
                f"(used {stats.times_used}x, {stats.crashes_found} crashes)"
            )

        print("\n--- Top Mutated Tags ---")
        sorted_tags = sorted(
            self.mutated_tags.items(), key=lambda x: x[1], reverse=True
        )
        for tag, count in sorted_tags[:10]:
            print(f"  {tag}: {count} mutations")

        print("=" * 60 + "\n")
