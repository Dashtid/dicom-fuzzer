"""Tests for statistics collector module."""

import pytest

from core.statistics import MutationStatistics, StatisticsCollector


class TestMutationStatistics:
    """Test MutationStatistics dataclass."""

    def test_statistics_initialization(self):
        """Test statistics initialize correctly."""
        stats = MutationStatistics(strategy_name="test")

        assert stats.strategy_name == "test"
        assert stats.times_used == 0
        assert stats.unique_outputs == 0
        assert stats.crashes_found == 0

    def test_effectiveness_score_no_usage(self):
        """Test effectiveness score with no usage."""
        stats = MutationStatistics(strategy_name="test")

        assert stats.effectiveness_score() == 0.0

    def test_effectiveness_score_with_crashes(self):
        """Test effectiveness score weighted by crashes."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 100
        stats.crashes_found = 5

        # Crashes weighted highest (0.6)
        score = stats.effectiveness_score()
        assert score > 0.25  # Should have significant score from crashes

    def test_effectiveness_score_with_failures(self):
        """Test effectiveness score with validation failures."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 100
        stats.validation_failures = 20

        score = stats.effectiveness_score()
        assert score > 0.0
        assert score < 1.0

    def test_effectiveness_score_with_diversity(self):
        """Test effectiveness score with unique outputs."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 100
        stats.unique_outputs = 50

        score = stats.effectiveness_score()
        assert score > 0.0

    def test_effectiveness_score_max_value(self):
        """Test effectiveness score is capped at 1.0."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 1000
        stats.crashes_found = 100  # Way over threshold
        stats.validation_failures = 1000
        stats.unique_outputs = 1000

        score = stats.effectiveness_score()
        assert score <= 1.0

    def test_avg_duration(self):
        """Test average duration calculation."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 10
        stats.total_duration = 5.0

        assert stats.avg_duration() == 0.5

    def test_avg_duration_zero_usage(self):
        """Test average duration with zero usage."""
        stats = MutationStatistics(strategy_name="test")
        stats.total_duration = 5.0

        assert stats.avg_duration() == 0.0

    def test_avg_file_size(self):
        """Test average file size calculation."""
        stats = MutationStatistics(strategy_name="test")
        stats.file_sizes = [100, 200, 300]

        assert stats.avg_file_size() == 200

    def test_avg_file_size_empty(self):
        """Test average file size with no files."""
        stats = MutationStatistics(strategy_name="test")

        assert stats.avg_file_size() == 0


class TestStatisticsCollector:
    """Test StatisticsCollector class."""

    def test_collector_initialization(self):
        """Test collector initializes correctly."""
        collector = StatisticsCollector()

        assert collector.total_files_generated == 0
        assert collector.total_mutations_applied == 0
        assert collector.total_crashes_found == 0
        assert len(collector.strategies) == 0

    def test_record_mutation(self):
        """Test recording mutations."""
        collector = StatisticsCollector()

        collector.record_mutation("header", duration=0.5)

        assert collector.total_mutations_applied == 1
        assert "header" in collector.strategies
        assert collector.strategies["header"].times_used == 1
        assert collector.strategies["header"].total_duration == 0.5

    def test_record_mutation_creates_strategy(self):
        """Test recording mutation creates strategy if not exists."""
        collector = StatisticsCollector()

        collector.record_mutation("new_strategy")

        assert "new_strategy" in collector.strategies

    def test_record_mutation_with_hash(self):
        """Test recording mutation with output hash."""
        collector = StatisticsCollector()

        collector.record_mutation("header", output_hash="hash1")
        collector.record_mutation("header", output_hash="hash2")
        collector.record_mutation("header", output_hash="hash1")  # Duplicate

        assert collector.strategies["header"].unique_outputs == 2

    def test_record_mutation_with_file_size(self):
        """Test recording mutation with file size."""
        collector = StatisticsCollector()

        collector.record_mutation("header", file_size=1000)
        collector.record_mutation("header", file_size=2000)

        assert len(collector.strategies["header"].file_sizes) == 2
        assert collector.strategies["header"].avg_file_size() == 1500

    def test_record_crash(self):
        """Test recording crashes."""
        collector = StatisticsCollector()
        collector.record_mutation("header")  # Create strategy

        collector.record_crash("header", "crash_hash_1")

        assert collector.total_crashes_found == 1
        assert collector.strategies["header"].crashes_found == 1

    def test_record_crash_deduplication(self):
        """Test crash deduplication."""
        collector = StatisticsCollector()
        collector.record_mutation("header")

        collector.record_crash("header", "crash_hash_1")
        collector.record_crash("header", "crash_hash_1")  # Duplicate

        assert collector.total_crashes_found == 1
        assert collector.strategies["header"].crashes_found == 1

    def test_record_crash_multiple_strategies(self):
        """Test crashes tracked per strategy."""
        collector = StatisticsCollector()
        collector.record_mutation("header")
        collector.record_mutation("metadata")

        collector.record_crash("header", "crash1")
        collector.record_crash("metadata", "crash2")

        assert collector.total_crashes_found == 2
        assert collector.strategies["header"].crashes_found == 1
        assert collector.strategies["metadata"].crashes_found == 1

    def test_record_validation_failure(self):
        """Test recording validation failures."""
        collector = StatisticsCollector()
        collector.record_mutation("header")

        collector.record_validation_failure("header")

        assert collector.strategies["header"].validation_failures == 1

    def test_record_file_generated(self):
        """Test recording file generation."""
        collector = StatisticsCollector()

        collector.record_file_generated()
        collector.record_file_generated()

        assert collector.total_files_generated == 2

    def test_record_tag_mutated(self):
        """Test recording tag mutations."""
        collector = StatisticsCollector()

        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("StudyDate")

        assert collector.mutated_tags["PatientName"] == 2
        assert collector.mutated_tags["StudyDate"] == 1

    def test_get_strategy_ranking(self):
        """Test strategy ranking."""
        collector = StatisticsCollector()

        # Strategy with crashes (most effective)
        collector.record_mutation("crash_finder")
        collector.strategies["crash_finder"].times_used = 10
        collector.strategies["crash_finder"].crashes_found = 3

        # Strategy with failures (moderately effective)
        collector.record_mutation("validator_breaker")
        collector.strategies["validator_breaker"].times_used = 10
        collector.strategies["validator_breaker"].validation_failures = 10

        # Strategy with little effect
        collector.record_mutation("boring")
        collector.strategies["boring"].times_used = 10

        rankings = collector.get_strategy_ranking()

        # Verify ordering (crash finder should be first)
        assert rankings[0][0] == "crash_finder"
        assert rankings[0][1] > rankings[1][1]
        assert rankings[1][1] > rankings[2][1]

    def test_get_most_effective_strategy(self):
        """Test getting most effective strategy."""
        collector = StatisticsCollector()

        collector.record_mutation("best")
        collector.strategies["best"].times_used = 10
        collector.strategies["best"].crashes_found = 5

        collector.record_mutation("worst")
        collector.strategies["worst"].times_used = 10

        most_effective = collector.get_most_effective_strategy()
        assert most_effective == "best"

    def test_get_most_effective_strategy_empty(self):
        """Test getting most effective with no strategies."""
        collector = StatisticsCollector()

        assert collector.get_most_effective_strategy() is None

    def test_get_coverage_report(self):
        """Test getting coverage report."""
        collector = StatisticsCollector()

        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("StudyDate")
        collector.record_tag_mutated("PatientName")

        coverage = collector.get_coverage_report()

        assert coverage["PatientName"] == 2
        assert coverage["StudyDate"] == 1

    def test_get_summary(self):
        """Test getting complete summary."""
        collector = StatisticsCollector()

        collector.record_mutation("header", duration=0.5)
        collector.record_file_generated()
        collector.record_crash("header", "crash1")
        collector.record_tag_mutated("PatientName")

        summary = collector.get_summary()

        assert "total_files_generated" in summary
        assert "total_mutations_applied" in summary
        assert "total_crashes_found" in summary
        assert "strategies" in summary
        assert "strategy_rankings" in summary
        assert "tag_coverage" in summary

    def test_summary_strategy_details(self):
        """Test summary contains strategy details."""
        collector = StatisticsCollector()

        collector.record_mutation("header", duration=0.5, file_size=1000)
        collector.strategies["header"].times_used = 10
        collector.strategies["header"].crashes_found = 2

        summary = collector.get_summary()

        header_stats = summary["strategies"]["header"]
        assert header_stats["times_used"] == 10
        assert header_stats["crashes_found"] == 2
        assert "effectiveness_score" in header_stats
        assert "avg_duration" in header_stats


class TestIntegration:
    """Integration tests for statistics collector."""

    def test_complete_fuzzing_campaign(self):
        """Test tracking complete fuzzing campaign."""
        collector = StatisticsCollector()

        # Simulate fuzzing campaign
        strategies = ["metadata", "header", "pixel"]

        for i in range(100):
            strategy = strategies[i % 3]

            collector.record_mutation(
                strategy, duration=0.01, output_hash=f"hash_{i}", file_size=1000 + i
            )
            collector.record_file_generated()

            # Some strategies find crashes
            if strategy == "header" and i % 10 == 0:
                collector.record_crash(strategy, f"crash_{i}")

            # Some cause validation failures
            if strategy == "pixel" and i % 5 == 0:
                collector.record_validation_failure(strategy)

            # Track tag mutations
            tags = ["PatientName", "StudyDate", "Modality"]
            collector.record_tag_mutated(tags[i % 3])

        # Verify campaign metrics
        assert collector.total_files_generated == 100
        assert collector.total_mutations_applied == 100
        assert collector.total_crashes_found > 0

        # Verify strategy tracking
        assert len(collector.strategies) == 3
        for strategy in strategies:
            assert collector.strategies[strategy].times_used > 0

        # Verify rankings
        rankings = collector.get_strategy_ranking()
        assert len(rankings) == 3

        # Header should be most effective (has crashes)
        most_effective = collector.get_most_effective_strategy()
        assert most_effective == "header"

    def test_print_summary_does_not_crash(self, capsys):
        """Test print summary doesn't crash."""
        collector = StatisticsCollector()

        collector.record_mutation("test")
        collector.record_file_generated()

        # Should not raise exception
        collector.print_summary()

        # Verify output was printed
        captured = capsys.readouterr()
        assert "STATISTICS" in captured.out

    def test_print_summary_with_mutated_tags(self, capsys):
        """Test print summary with mutated tags (line 275)."""
        collector = StatisticsCollector()

        # Record some tag mutations
        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("StudyDate")
        collector.record_tag_mutated("PatientName")  # Duplicate to test counting

        collector.print_summary()

        # Verify mutated tags are printed
        captured = capsys.readouterr()
        assert "Top Mutated Tags" in captured.out
        assert "PatientName" in captured.out
        assert "StudyDate" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
