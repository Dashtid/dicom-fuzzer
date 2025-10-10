"""
Statistics Collector - Mutation Effectiveness Tracking

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
from typing import Dict, List, Optional, Set


@dataclass
class MutationStatistics:
    """
    Statistics for a specific mutation strategy.

    CONCEPT: Track both usage and effectiveness:
    - How often was this mutation used?
    - How many unique outputs did it create?
    - Did it find any crashes?
    - How long did it take?
    """

    strategy_name: str
    times_used: int = 0
    unique_outputs: int = 0
    crashes_found: int = 0
    validation_failures: int = 0
    total_duration: float = 0.0
    file_sizes: List[int] = field(default_factory=list)

    def effectiveness_score(self) -> float:
        """
        Calculate effectiveness score (0-1).

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


class StatisticsCollector:
    """
    Collects and analyzes fuzzing campaign statistics.

    CONCEPT: Central repository for all statistics.
    Tracks per-strategy metrics and campaign-wide patterns.
    """

    def __init__(self):
        """Initialize statistics collector."""
        self.strategies: Dict[str, MutationStatistics] = {}
        self.campaign_start = datetime.now()

        # Campaign-wide tracking
        self.total_files_generated = 0
        self.total_mutations_applied = 0
        self.total_crashes_found = 0

        # Uniqueness tracking
        self.seen_hashes: Set[str] = set()
        self.crash_hashes: Set[str] = set()

        # Coverage tracking (which tags were mutated)
        self.mutated_tags: Dict[str, int] = defaultdict(int)

    def record_mutation(
        self,
        strategy: str,
        duration: float = 0.0,
        output_hash: Optional[str] = None,
        file_size: Optional[int] = None,
    ):
        """
        Record a mutation operation.

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

    def record_crash(self, strategy: str, crash_hash: str):
        """
        Record a crash discovered by a strategy.

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

    def record_validation_failure(self, strategy: str):
        """
        Record a validation failure.

        Args:
            strategy: Strategy that caused validation failure
        """
        if strategy in self.strategies:
            self.strategies[strategy].validation_failures += 1

    def record_file_generated(self):
        """Record that a file was generated."""
        self.total_files_generated += 1

    def record_tag_mutated(self, tag_name: str):
        """
        Record that a DICOM tag was mutated.

        Args:
            tag_name: Name of the tag that was mutated
        """
        self.mutated_tags[tag_name] += 1

    def get_strategy_ranking(self) -> List[tuple]:
        """
        Get strategies ranked by effectiveness.

        Returns:
            List of (strategy_name, effectiveness_score) tuples, sorted
        """
        rankings = [
            (name, stats.effectiveness_score())
            for name, stats in self.strategies.items()
        ]
        return sorted(rankings, key=lambda x: x[1], reverse=True)

    def get_most_effective_strategy(self) -> Optional[str]:
        """
        Get the most effective strategy.

        Returns:
            Name of most effective strategy, or None
        """
        rankings = self.get_strategy_ranking()
        if rankings:
            return rankings[0][0]
        return None

    def get_coverage_report(self) -> Dict[str, int]:
        """
        Get coverage report (which tags were mutated).

        Returns:
            Dictionary mapping tag names to mutation counts
        """
        return dict(self.mutated_tags)

    def get_summary(self) -> Dict:
        """
        Get complete statistics summary.

        Returns:
            Dictionary with all statistics
        """
        campaign_duration = (datetime.now() - self.campaign_start).total_seconds()

        return {
            "campaign_duration_seconds": campaign_duration,
            "total_files_generated": self.total_files_generated,
            "total_mutations_applied": self.total_mutations_applied,
            "total_crashes_found": self.total_crashes_found,
            "unique_outputs": len(self.seen_hashes),
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
        }

    def print_summary(self):
        """Print a formatted summary to console."""
        print("\n" + "=" * 60)
        print("FUZZING CAMPAIGN STATISTICS")
        print("=" * 60)

        duration = (datetime.now() - self.campaign_start).total_seconds()
        print(f"\nCampaign Duration: {duration:.1f}s")
        print(f"Files Generated: {self.total_files_generated}")
        print(f"Mutations Applied: {self.total_mutations_applied}")
        print(f"Crashes Found: {self.total_crashes_found}")
        print(f"Unique Outputs: {len(self.seen_hashes)}")

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
