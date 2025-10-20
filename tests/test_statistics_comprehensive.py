"""
Comprehensive tests for core/statistics.py module.

Achieves 80%+ coverage of statistics tracking functionality.
"""

import pytest
from datetime import datetime
from dicom_fuzzer.core.statistics import (
    IterationData,
    MutationStatistics,
    StatisticsCollector,
)


class TestIterationData:
    """Tests for IterationData dataclass."""

    def test_basic_initialization(self):
        """Test basic IterationData creation."""
        iteration = IterationData(
            iteration_number=1,
            file_path="test.dcm",
            mutations_applied=5,
            severity="critical",
        )

        assert iteration.iteration_number == 1
        assert iteration.file_path == "test.dcm"
        assert iteration.mutations_applied == 5
        assert iteration.severity == "critical"
        assert isinstance(iteration.timestamp, datetime)

    def test_custom_timestamp(self):
        """Test IterationData with custom timestamp."""
        custom_time = datetime(2025, 1, 1, 12, 0, 0)
        iteration = IterationData(
            iteration_number=10,
            file_path="test.dcm",
            mutations_applied=3,
            severity="low",
            timestamp=custom_time,
        )

        assert iteration.timestamp == custom_time

    def test_default_timestamp(self):
        """Test default timestamp is recent."""
        before = datetime.now()
        iteration = IterationData(
            iteration_number=1,
            file_path="test.dcm",
            mutations_applied=1,
            severity="medium",
        )
        after = datetime.now()

        assert before <= iteration.timestamp <= after


class TestMutationStatistics:
    """Tests for MutationStatistics class."""

    def test_initialization(self):
        """Test MutationStatistics initialization."""
        stats = MutationStatistics(strategy_name="bit_flip")

        assert stats.strategy_name == "bit_flip"
        assert stats.times_used == 0
        assert stats.unique_outputs == 0
        assert stats.crashes_found == 0
        assert stats.validation_failures == 0
        assert stats.total_duration == 0.0
        assert stats.file_sizes == []

    def test_effectiveness_score_no_usage(self):
        """Test effectiveness score with no usage."""
        stats = MutationStatistics(strategy_name="test")

        score = stats.effectiveness_score()

        assert score == 0.0

    def test_effectiveness_score_crashes_only(self):
        """Test effectiveness score with crashes."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 10
        stats.crashes_found = 5

        score = stats.effectiveness_score()

        # 5 crashes = 0.5 crash_score * 0.6 weight = 0.3
        assert score == pytest.approx(0.3, rel=0.01)

    def test_effectiveness_score_max_crashes(self):
        """Test effectiveness score caps at 1.0 for crashes."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 100
        stats.crashes_found = 20  # More than max of 10

        score = stats.effectiveness_score()

        # Max crash_score is 1.0, so 1.0 * 0.6 = 0.6
        assert score == pytest.approx(0.6, rel=0.01)

    def test_effectiveness_score_validation_failures(self):
        """Test effectiveness score with validation failures."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 10
        stats.validation_failures = 10

        score = stats.effectiveness_score()

        # 10 failures = 0.2 failure_score * 0.25 weight = 0.05
        assert score == pytest.approx(0.05, rel=0.01)

    def test_effectiveness_score_unique_outputs(self):
        """Test effectiveness score with unique outputs."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 10
        stats.unique_outputs = 50

        score = stats.effectiveness_score()

        # 50 unique = 0.5 diversity_score * 0.15 weight = 0.075
        assert score == pytest.approx(0.075, rel=0.01)

    def test_effectiveness_score_combined(self):
        """Test effectiveness score with all components."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 100
        stats.crashes_found = 5
        stats.validation_failures = 20
        stats.unique_outputs = 60

        score = stats.effectiveness_score()

        # Weighted: 0.5*0.6 + 0.4*0.25 + 0.6*0.15 = 0.3 + 0.1 + 0.09 = 0.49
        assert 0.48 <= score <= 0.50

    def test_avg_duration_no_usage(self):
        """Test average duration with no usage."""
        stats = MutationStatistics(strategy_name="test")

        avg = stats.avg_duration()

        assert avg == 0.0

    def test_avg_duration_with_usage(self):
        """Test average duration calculation."""
        stats = MutationStatistics(strategy_name="test")
        stats.times_used = 5
        stats.total_duration = 10.0

        avg = stats.avg_duration()

        assert avg == 2.0

    def test_avg_file_size_empty(self):
        """Test average file size with no files."""
        stats = MutationStatistics(strategy_name="test")

        avg = stats.avg_file_size()

        assert avg == 0

    def test_avg_file_size_calculation(self):
        """Test average file size calculation."""
        stats = MutationStatistics(strategy_name="test")
        stats.file_sizes = [100, 200, 300]

        avg = stats.avg_file_size()

        assert avg == 200  # (100+200+300)//3


class TestStatisticsCollector:
    """Tests for StatisticsCollector class."""

    def test_initialization(self):
        """Test StatisticsCollector initialization."""
        collector = StatisticsCollector()

        assert isinstance(collector.strategies, dict)
        assert len(collector.strategies) == 0
        assert isinstance(collector.campaign_start, datetime)
        assert collector.total_files_generated == 0
        assert collector.total_mutations_applied == 0
        assert collector.total_crashes_found == 0
        assert len(collector.seen_hashes) == 0
        assert len(collector.crash_hashes) == 0
        assert len(collector.mutated_tags) == 0
        assert len(collector.iterations) == 0

    def test_record_mutation_creates_strategy(self):
        """Test recording mutation creates strategy if not exists."""
        collector = StatisticsCollector()

        collector.record_mutation("bit_flip", duration=1.0)

        assert "bit_flip" in collector.strategies
        assert collector.strategies["bit_flip"].times_used == 1
        assert collector.total_mutations_applied == 1

    def test_record_mutation_increments_existing(self):
        """Test recording mutation increments existing strategy."""
        collector = StatisticsCollector()

        collector.record_mutation("bit_flip", duration=1.0)
        collector.record_mutation("bit_flip", duration=2.0)

        assert collector.strategies["bit_flip"].times_used == 2
        assert collector.strategies["bit_flip"].total_duration == 3.0
        assert collector.total_mutations_applied == 2

    def test_record_mutation_with_hash_uniqueness(self):
        """Test mutation recording tracks unique outputs."""
        collector = StatisticsCollector()

        collector.record_mutation("test", output_hash="hash1")
        collector.record_mutation("test", output_hash="hash2")
        collector.record_mutation("test", output_hash="hash1")  # Duplicate

        stats = collector.strategies["test"]
        assert stats.unique_outputs == 2  # Only 2 unique
        assert len(collector.seen_hashes) == 2

    def test_record_mutation_with_file_size(self):
        """Test mutation recording tracks file sizes."""
        collector = StatisticsCollector()

        collector.record_mutation("test", file_size=100)
        collector.record_mutation("test", file_size=200)

        stats = collector.strategies["test"]
        assert stats.file_sizes == [100, 200]

    def test_record_crash(self):
        """Test crash recording."""
        collector = StatisticsCollector()
        collector.record_mutation("bit_flip")

        collector.record_crash("bit_flip", "crash_hash_1")

        assert collector.strategies["bit_flip"].crashes_found == 1
        assert collector.total_crashes_found == 1
        assert "crash_hash_1" in collector.crash_hashes

    def test_record_crash_unique_only(self):
        """Test only unique crashes are counted."""
        collector = StatisticsCollector()
        collector.record_mutation("test")

        collector.record_crash("test", "crash1")
        collector.record_crash("test", "crash1")  # Duplicate
        collector.record_crash("test", "crash2")

        assert collector.strategies["test"].crashes_found == 2
        assert collector.total_crashes_found == 2

    def test_record_crash_nonexistent_strategy(self):
        """Test recording crash for nonexistent strategy."""
        collector = StatisticsCollector()

        # Should not raise error
        collector.record_crash("nonexistent", "crash1")

        # No crash should be recorded
        assert collector.total_crashes_found == 0

    def test_record_validation_failure(self):
        """Test validation failure recording."""
        collector = StatisticsCollector()
        collector.record_mutation("test")

        collector.record_validation_failure("test")

        assert collector.strategies["test"].validation_failures == 1

    def test_record_validation_failure_nonexistent(self):
        """Test validation failure for nonexistent strategy."""
        collector = StatisticsCollector()

        # Should not raise error
        collector.record_validation_failure("nonexistent")

        assert "nonexistent" not in collector.strategies

    def test_multiple_strategies(self):
        """Test tracking multiple strategies."""
        collector = StatisticsCollector()

        collector.record_mutation("bit_flip", duration=1.0)
        collector.record_mutation("byte_swap", duration=2.0)
        collector.record_mutation("random_mutation", duration=3.0)

        assert len(collector.strategies) == 3
        assert "bit_flip" in collector.strategies
        assert "byte_swap" in collector.strategies
        assert "random_mutation" in collector.strategies

    def test_campaign_start_timestamp(self):
        """Test campaign start timestamp is set."""
        collector = StatisticsCollector()

        assert isinstance(collector.campaign_start, datetime)
        # Should be recent (within last second)
        age = (datetime.now() - collector.campaign_start).total_seconds()
        assert age < 1.0


class TestIntegrationScenarios:
    """Integration tests for statistics collection."""

    def test_complete_fuzzing_campaign_stats(self):
        """Test statistics for complete fuzzing campaign."""
        collector = StatisticsCollector()

        # Simulate fuzzing campaign
        strategies = ["bit_flip", "byte_swap", "random"]

        for i in range(100):
            strategy = strategies[i % 3]
            collector.record_mutation(
                strategy,
                duration=0.1,
                output_hash=f"hash_{i}",
                file_size=1000 + i,
            )

            # Some mutations find crashes
            if i % 20 == 0:
                collector.record_crash(strategy, f"crash_{i}")

            # Some fail validation
            if i % 15 == 0:
                collector.record_validation_failure(strategy)

        # Verify campaign stats
        assert collector.total_mutations_applied == 100
        assert collector.total_crashes_found == 5
        assert len(collector.seen_hashes) == 100

        # Verify each strategy was used
        for strategy in strategies:
            assert strategy in collector.strategies
            assert collector.strategies[strategy].times_used > 0

    def test_effectiveness_comparison(self):
        """Test comparing strategy effectiveness."""
        collector = StatisticsCollector()

        # Strategy 1: Many uses, few crashes
        for i in range(100):
            collector.record_mutation("volume_strategy", duration=0.1)
        collector.record_crash("volume_strategy", "crash1")

        # Strategy 2: Few uses, many crashes
        for i in range(10):
            collector.record_mutation("quality_strategy", duration=0.1)
        for i in range(3):
            collector.record_crash("quality_strategy", f"crash_{i}")

        vol_score = collector.strategies["volume_strategy"].effectiveness_score()
        qual_score = collector.strategies["quality_strategy"].effectiveness_score()

        # Quality strategy should have higher score
        assert qual_score > vol_score

    def test_uniqueness_tracking(self):
        """Test unique output tracking."""
        collector = StatisticsCollector()

        # Generate outputs with some duplicates
        hashes = ["h1", "h2", "h3", "h1", "h2", "h4"]

        for h in hashes:
            collector.record_mutation("test", output_hash=h)

        assert len(collector.seen_hashes) == 4  # h1, h2, h3, h4
        assert collector.strategies["test"].unique_outputs == 4

    def test_crash_deduplication(self):
        """Test crash deduplication."""
        collector = StatisticsCollector()
        collector.record_mutation("test")

        # Record same crash multiple times
        for i in range(5):
            collector.record_crash("test", "duplicate_crash")

        assert collector.strategies["test"].crashes_found == 1
        assert collector.total_crashes_found == 1
        assert len(collector.crash_hashes) == 1


class TestAdditionalMethods:
    """Tests for additional StatisticsCollector methods."""

    def test_record_file_generated(self):
        """Test recording generated files."""
        collector = StatisticsCollector()

        collector.record_file_generated()
        collector.record_file_generated()
        collector.record_file_generated()

        assert collector.total_files_generated == 3

    def test_record_tag_mutated(self):
        """Test recording mutated tags."""
        collector = StatisticsCollector()

        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("StudyDate")
        collector.record_tag_mutated("PatientName")  # Duplicate

        assert collector.mutated_tags["PatientName"] == 2
        assert collector.mutated_tags["StudyDate"] == 1

    def test_track_iteration(self):
        """Test iteration tracking."""
        collector = StatisticsCollector()

        iteration_num = collector.track_iteration(
            file_path="/path/to/test.dcm",
            mutations_applied=5,
            severity="high"
        )

        assert iteration_num == 1
        assert collector.total_iterations == 1
        assert len(collector.iterations) == 1
        assert collector.iterations[0].mutations_applied == 5
        assert collector.iterations[0].severity == "high"

    def test_track_multiple_iterations(self):
        """Test tracking multiple iterations."""
        collector = StatisticsCollector()

        for i in range(10):
            iteration_num = collector.track_iteration(
                file_path=f"/test{i}.dcm",
                mutations_applied=i + 1,
                severity="medium"
            )
            assert iteration_num == i + 1

        assert collector.total_iterations == 10
        assert len(collector.iterations) == 10

    def test_track_iteration_severity_stats(self):
        """Test iteration tracking updates severity statistics."""
        collector = StatisticsCollector()

        collector.track_iteration("/test1.dcm", 5, "high")
        collector.track_iteration("/test2.dcm", 3, "high")
        collector.track_iteration("/test3.dcm", 2, "low")

        assert collector.severity_stats["high"]["count"] == 2
        assert collector.severity_stats["high"]["mutations"] == 8
        assert collector.severity_stats["low"]["count"] == 1
        assert collector.severity_stats["low"]["mutations"] == 2

    def test_get_strategy_ranking(self):
        """Test strategy ranking by effectiveness."""
        collector = StatisticsCollector()

        # Create strategies with different effectiveness
        collector.record_mutation("good_strategy", duration=0.1)
        collector.record_crash("good_strategy", "crash1")
        collector.record_crash("good_strategy", "crash2")

        collector.record_mutation("poor_strategy", duration=0.1)

        rankings = collector.get_strategy_ranking()

        assert len(rankings) == 2
        # Good strategy should be first
        assert rankings[0][0] == "good_strategy"
        assert rankings[0][1] > rankings[1][1]

    def test_get_most_effective_strategy(self):
        """Test getting most effective strategy."""
        collector = StatisticsCollector()

        collector.record_mutation("strategy1", duration=0.1)
        collector.record_crash("strategy1", "crash1")

        collector.record_mutation("strategy2", duration=0.1)

        most_effective = collector.get_most_effective_strategy()

        assert most_effective == "strategy1"

    def test_get_most_effective_strategy_empty(self):
        """Test getting most effective strategy when none exist."""
        collector = StatisticsCollector()

        result = collector.get_most_effective_strategy()

        assert result is None

    def test_get_coverage_report(self):
        """Test coverage report generation."""
        collector = StatisticsCollector()

        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("StudyDate")
        collector.record_tag_mutated("PatientName")

        report = collector.get_coverage_report()

        assert isinstance(report, dict)
        assert report["PatientName"] == 2
        assert report["StudyDate"] == 1

    def test_get_summary(self):
        """Test complete summary generation."""
        collector = StatisticsCollector()

        # Add some data
        collector.record_mutation("test", duration=1.0, output_hash="hash1", file_size=1000)
        collector.record_crash("test", "crash1")
        collector.record_file_generated()
        collector.record_tag_mutated("PatientName")
        collector.track_iteration("/test.dcm", 5, "high")

        summary = collector.get_summary()

        assert "campaign_duration_seconds" in summary
        assert summary["total_files_generated"] == 1
        assert summary["total_mutations_applied"] == 1
        assert summary["total_crashes_found"] == 1
        assert summary["unique_outputs"] == 1
        assert summary["total_iterations"] == 1
        assert "executions_per_second" in summary
        assert "strategies" in summary
        assert "strategy_rankings" in summary
        assert "tag_coverage" in summary
        assert "severity_statistics" in summary

    def test_get_summary_empty(self):
        """Test summary with no data."""
        collector = StatisticsCollector()

        summary = collector.get_summary()

        assert summary["total_files_generated"] == 0
        assert summary["total_mutations_applied"] == 0
        assert summary["total_crashes_found"] == 0
        assert summary["unique_outputs"] == 0

    def test_print_summary(self, capsys):
        """Test print_summary produces output."""
        collector = StatisticsCollector()

        # Add some test data
        collector.record_mutation("test_strategy", duration=1.0)
        collector.record_crash("test_strategy", "crash1")
        collector.record_tag_mutated("PatientName")
        collector.track_iteration("/test.dcm", 5, "high")

        collector.print_summary()

        captured = capsys.readouterr()
        assert "FUZZING CAMPAIGN STATISTICS" in captured.out
        assert "Campaign Duration" in captured.out
        assert "Total Iterations" in captured.out
        assert "Executions/Second" in captured.out
