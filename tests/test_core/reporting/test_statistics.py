"""Tests for statistics module."""

import pytest

from dicom_fuzzer.core.reporting.statistics import MutationStatistics


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
