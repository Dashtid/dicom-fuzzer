"""Comprehensive tests for statistics.py module to improve coverage.

Target: statistics.py (46% -> 90%+)
Focus areas:
- MutationStatistics methods
- StatisticsCollector tracking
- Iteration tracking
- Strategy ranking
- Summary generation
"""

from __future__ import annotations

from datetime import datetime

from dicom_fuzzer.core.statistics import (
    IterationData,
    MutationStatistics,
    StatisticsCollector,
)


class TestIterationData:
    """Tests for IterationData dataclass."""

    def test_iteration_data_creation(self) -> None:
        """Test creating IterationData."""
        data = IterationData(
            iteration_number=1,
            file_path="/path/to/file.dcm",
            mutations_applied=5,
            severity="high",
        )

        assert data.iteration_number == 1
        assert data.file_path == "/path/to/file.dcm"
        assert data.mutations_applied == 5
        assert data.severity == "high"
        assert isinstance(data.timestamp, datetime)

    def test_iteration_data_default_timestamp(self) -> None:
        """Test that timestamp defaults to now."""
        before = datetime.now()
        data = IterationData(
            iteration_number=1,
            file_path="test.dcm",
            mutations_applied=1,
            severity="low",
        )
        after = datetime.now()

        assert before <= data.timestamp <= after


class TestMutationStatistics:
    """Tests for MutationStatistics dataclass."""

    def test_default_values(self) -> None:
        """Test default initialization."""
        stats = MutationStatistics()

        assert stats.strategy_name == ""
        assert stats.times_used == 0
        assert stats.unique_outputs == 0
        assert stats.crashes_found == 0
        assert stats.validation_failures == 0
        assert stats.total_duration == 0.0
        assert stats.file_sizes == []
        assert stats.total_mutations == 0
        assert stats.total_executions == 0

    def test_effectiveness_score_zero_usage(self) -> None:
        """Test effectiveness score with zero usage."""
        stats = MutationStatistics()
        assert stats.effectiveness_score() == 0.0

    def test_effectiveness_score_with_crashes(self) -> None:
        """Test effectiveness score weighted by crashes."""
        stats = MutationStatistics(
            times_used=10,
            crashes_found=5,
            validation_failures=2,
            unique_outputs=10,
        )

        score = stats.effectiveness_score()
        # Crashes weighted highest (0.6), failures (0.25), diversity (0.15)
        # crash_score = min(5 * 10, 100) / 100 = 0.5
        # failure_score = min(2 * 2, 100) / 100 = 0.04
        # diversity_score = min(10, 100) / 100 = 0.1
        # score = 0.5 * 0.6 + 0.04 * 0.25 + 0.1 * 0.15 = 0.3 + 0.01 + 0.015 = 0.325
        assert 0.0 < score < 1.0

    def test_effectiveness_score_max_crashes(self) -> None:
        """Test effectiveness score capped at max crashes."""
        stats = MutationStatistics(
            times_used=100,
            crashes_found=20,  # More than max 10
            validation_failures=100,  # More than max 50
            unique_outputs=200,  # More than max 100
        )

        score = stats.effectiveness_score()
        # Should cap at 1.0
        assert score == 1.0

    def test_avg_duration_zero_usage(self) -> None:
        """Test average duration with zero usage."""
        stats = MutationStatistics()
        assert stats.avg_duration() == 0.0

    def test_avg_duration_with_usage(self) -> None:
        """Test average duration calculation."""
        stats = MutationStatistics(times_used=10, total_duration=50.0)
        assert stats.avg_duration() == 5.0

    def test_avg_file_size_empty(self) -> None:
        """Test average file size with no files."""
        stats = MutationStatistics()
        assert stats.avg_file_size() == 0

    def test_avg_file_size_with_files(self) -> None:
        """Test average file size calculation."""
        stats = MutationStatistics(file_sizes=[100, 200, 300])
        assert stats.avg_file_size() == 200

    def test_record_mutation(self) -> None:
        """Test recording mutation."""
        stats = MutationStatistics()
        stats.record_mutation("header_fuzzer")

        assert stats.strategy_name == "header_fuzzer"
        assert stats.times_used == 1
        assert stats.total_mutations == 1

    def test_record_execution(self) -> None:
        """Test recording execution."""
        stats = MutationStatistics()
        stats.record_execution(1.5)
        stats.record_execution(2.5)

        assert stats.total_executions == 2
        assert stats.total_duration == 4.0


class TestStatisticsCollector:
    """Tests for StatisticsCollector class."""

    def test_initialization(self) -> None:
        """Test collector initialization."""
        collector = StatisticsCollector()

        assert collector.total_files_generated == 0
        assert collector.total_mutations_applied == 0
        assert collector.total_crashes_found == 0
        assert len(collector.seen_hashes) == 0
        assert len(collector.crash_hashes) == 0
        assert len(collector.mutated_tags) == 0
        assert len(collector.iterations) == 0
        assert collector.total_iterations == 0

    def test_record_mutation_new_strategy(self) -> None:
        """Test recording mutation for new strategy."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer", duration=1.0)

        assert "header_fuzzer" in collector.strategies
        assert collector.strategies["header_fuzzer"].times_used == 1
        assert collector.total_mutations_applied == 1

    def test_record_mutation_with_hash(self) -> None:
        """Test recording mutation with output hash."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer", output_hash="abc123")
        collector.record_mutation("header_fuzzer", output_hash="abc123")  # Duplicate
        collector.record_mutation("header_fuzzer", output_hash="def456")  # New

        assert collector.strategies["header_fuzzer"].unique_outputs == 2
        assert len(collector.seen_hashes) == 2

    def test_record_mutation_with_file_size(self) -> None:
        """Test recording mutation with file size."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer", file_size=1000)
        collector.record_mutation("header_fuzzer", file_size=2000)

        assert collector.strategies["header_fuzzer"].file_sizes == [1000, 2000]

    def test_record_crash_new(self) -> None:
        """Test recording new crash."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer")  # Create strategy first
        collector.record_crash("header_fuzzer", "crash_hash_1")

        assert collector.strategies["header_fuzzer"].crashes_found == 1
        assert collector.total_crashes_found == 1
        assert "crash_hash_1" in collector.crash_hashes

    def test_record_crash_duplicate(self) -> None:
        """Test recording duplicate crash."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer")
        collector.record_crash("header_fuzzer", "crash_hash_1")
        collector.record_crash("header_fuzzer", "crash_hash_1")  # Duplicate

        assert collector.strategies["header_fuzzer"].crashes_found == 1
        assert collector.total_crashes_found == 1

    def test_record_crash_unknown_strategy(self) -> None:
        """Test recording crash for unknown strategy."""
        collector = StatisticsCollector()
        collector.record_crash("unknown", "crash_hash")

        assert collector.total_crashes_found == 0

    def test_record_validation_failure(self) -> None:
        """Test recording validation failure."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer")
        collector.record_validation_failure("header_fuzzer")

        assert collector.strategies["header_fuzzer"].validation_failures == 1

    def test_record_validation_failure_unknown_strategy(self) -> None:
        """Test recording validation failure for unknown strategy."""
        collector = StatisticsCollector()
        collector.record_validation_failure("unknown")
        # Should not raise, just do nothing

    def test_record_file_generated(self) -> None:
        """Test recording file generation."""
        collector = StatisticsCollector()
        collector.record_file_generated()
        collector.record_file_generated()

        assert collector.total_files_generated == 2

    def test_record_tag_mutated(self) -> None:
        """Test recording tag mutation."""
        collector = StatisticsCollector()
        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("PatientID")

        assert collector.mutated_tags["PatientName"] == 2
        assert collector.mutated_tags["PatientID"] == 1

    def test_track_iteration(self) -> None:
        """Test tracking iteration."""
        collector = StatisticsCollector()
        iter_num = collector.track_iteration("/path/to/file.dcm", 5, "high")

        assert iter_num == 1
        assert collector.total_iterations == 1
        assert len(collector.iterations) == 1
        assert collector.iterations[0].mutations_applied == 5
        assert collector.iterations[0].severity == "high"

    def test_track_iteration_severity_stats(self) -> None:
        """Test tracking iteration updates severity stats."""
        collector = StatisticsCollector()
        collector.track_iteration("file1.dcm", 5, "high")
        collector.track_iteration("file2.dcm", 3, "high")
        collector.track_iteration("file3.dcm", 2, "low")

        assert collector.severity_stats["high"]["count"] == 2
        assert collector.severity_stats["high"]["mutations"] == 8
        assert collector.severity_stats["low"]["count"] == 1
        assert collector.severity_stats["low"]["mutations"] == 2

    def test_track_iteration_unknown_severity(self) -> None:
        """Test tracking iteration with empty severity."""
        collector = StatisticsCollector()
        collector.track_iteration("file.dcm", 1, "")

        assert "unknown" in collector.severity_stats
        assert collector.severity_stats["unknown"]["count"] == 1

    def test_get_strategy_ranking_empty(self) -> None:
        """Test getting ranking with no strategies."""
        collector = StatisticsCollector()
        rankings = collector.get_strategy_ranking()

        assert rankings == []

    def test_get_strategy_ranking_sorted(self) -> None:
        """Test strategies are ranked by effectiveness."""
        collector = StatisticsCollector()

        # Add strategies with different effectiveness
        collector.record_mutation("low_effect", duration=1.0)
        collector.record_mutation("high_effect", duration=1.0)

        # Make high_effect more effective
        collector.record_crash("high_effect", "crash1")
        collector.record_crash("high_effect", "crash2")

        rankings = collector.get_strategy_ranking()

        assert len(rankings) == 2
        assert rankings[0][0] == "high_effect"
        assert rankings[0][1] > rankings[1][1]

    def test_get_most_effective_strategy_empty(self) -> None:
        """Test most effective with no strategies."""
        collector = StatisticsCollector()
        result = collector.get_most_effective_strategy()

        assert result is None

    def test_get_most_effective_strategy(self) -> None:
        """Test getting most effective strategy."""
        collector = StatisticsCollector()
        collector.record_mutation("best")
        collector.record_crash("best", "crash1")
        collector.record_mutation("worst")

        result = collector.get_most_effective_strategy()
        assert result == "best"

    def test_get_coverage_report(self) -> None:
        """Test getting coverage report."""
        collector = StatisticsCollector()
        collector.record_tag_mutated("PatientName")
        collector.record_tag_mutated("PatientID")

        report = collector.get_coverage_report()

        assert report == {"PatientName": 1, "PatientID": 1}

    def test_get_summary(self) -> None:
        """Test getting complete summary."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer", duration=1.0, file_size=1000)
        collector.record_file_generated()
        collector.track_iteration("file.dcm", 3, "high")

        summary = collector.get_summary()

        assert "campaign_duration_seconds" in summary
        assert summary["total_files_generated"] == 1
        assert summary["total_mutations_applied"] == 1
        assert summary["total_iterations"] == 1
        assert "executions_per_second" in summary
        assert "strategies" in summary
        assert "header_fuzzer" in summary["strategies"]
        assert "strategy_rankings" in summary
        assert "tag_coverage" in summary
        assert "severity_statistics" in summary

    def test_get_summary_exec_per_second(self) -> None:
        """Test executions per second calculation."""
        collector = StatisticsCollector()
        # Track several iterations
        for i in range(10):
            collector.track_iteration(f"file{i}.dcm", 1, "low")

        summary = collector.get_summary()

        # exec/s should be positive
        assert summary["executions_per_second"] >= 0

    def test_print_summary(self, capsys) -> None:
        """Test printing summary to console."""
        collector = StatisticsCollector()
        collector.record_mutation("header_fuzzer", duration=0.5)
        collector.record_mutation("pixel_fuzzer", duration=1.0)
        collector.record_crash("header_fuzzer", "crash1")
        collector.record_tag_mutated("PatientName")
        collector.track_iteration("file.dcm", 3, "high")

        collector.print_summary()

        captured = capsys.readouterr()
        assert "FUZZING CAMPAIGN STATISTICS" in captured.out
        assert "Campaign Duration:" in captured.out
        assert "Files Generated:" in captured.out
        assert "Crashes Found:" in captured.out
        assert "Strategy Effectiveness Rankings" in captured.out
        assert "header_fuzzer" in captured.out
        assert "Top Mutated Tags" in captured.out

    def test_print_summary_empty(self, capsys) -> None:
        """Test printing summary with no data."""
        collector = StatisticsCollector()
        collector.print_summary()

        captured = capsys.readouterr()
        assert "FUZZING CAMPAIGN STATISTICS" in captured.out
        assert "Crashes Found: 0" in captured.out

    def test_print_summary_severity_distribution(self, capsys) -> None:
        """Test severity distribution in print summary."""
        collector = StatisticsCollector()
        collector.track_iteration("file1.dcm", 10, "high")
        collector.track_iteration("file2.dcm", 5, "moderate")
        collector.track_iteration("file3.dcm", 2, "low")

        collector.print_summary()

        captured = capsys.readouterr()
        assert "Severity Distribution" in captured.out
        assert "High:" in captured.out
        assert "Moderate:" in captured.out
        assert "Low:" in captured.out


class TestStatisticsIntegration:
    """Integration tests for statistics tracking."""

    def test_full_fuzzing_workflow(self) -> None:
        """Test complete fuzzing statistics workflow."""
        collector = StatisticsCollector()

        # Simulate fuzzing campaign
        strategies = ["header", "pixel", "metadata"]

        for i in range(30):
            strategy = strategies[i % len(strategies)]
            collector.record_mutation(
                strategy,
                duration=0.1,
                output_hash=f"hash_{i}",
                file_size=1000 + i * 100,
            )
            collector.record_file_generated()
            collector.track_iteration(
                f"file_{i}.dcm",
                mutations_applied=i % 5 + 1,
                severity=["low", "moderate", "high"][i % 3],
            )

            # Simulate some crashes
            if i % 10 == 0:
                collector.record_crash(strategy, f"crash_{i}")

            # Simulate validation failures
            if i % 7 == 0:
                collector.record_validation_failure(strategy)

            # Track some tags
            collector.record_tag_mutated("PatientName")
            if i % 2 == 0:
                collector.record_tag_mutated("PatientID")

        # Verify comprehensive tracking
        summary = collector.get_summary()

        assert summary["total_files_generated"] == 30
        assert summary["total_mutations_applied"] == 30
        assert summary["total_iterations"] == 30
        assert summary["unique_outputs"] == 30
        assert summary["total_crashes_found"] == 3  # i=0, 10, 20
        assert len(summary["strategies"]) == 3
        assert len(summary["tag_coverage"]) == 2

    def test_strategy_effectiveness_comparison(self) -> None:
        """Test comparing strategy effectiveness."""
        collector = StatisticsCollector()

        # Strategy A: High crash rate
        for _ in range(10):
            collector.record_mutation("strategy_a")
        for i in range(5):
            collector.record_crash("strategy_a", f"crash_a_{i}")

        # Strategy B: Low crash rate
        for _ in range(100):
            collector.record_mutation("strategy_b")
        collector.record_crash("strategy_b", "crash_b_1")

        rankings = collector.get_strategy_ranking()

        # Strategy A should rank higher despite fewer uses
        assert rankings[0][0] == "strategy_a"
        assert rankings[0][1] > rankings[1][1]
