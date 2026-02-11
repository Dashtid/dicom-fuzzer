"""Tests for Campaign Analytics module.

Tests for the CampaignAnalyzer class and related dataclasses that provide
statistical analysis for DICOM fuzzing campaigns.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.core.analytics.campaign_analytics import (
    CampaignAnalyzer,
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)

# =============================================================================
# TestCoverageCorrelation
# =============================================================================


class TestCoverageCorrelation:
    """Tests for CoverageCorrelation dataclass."""

    def test_creation(self) -> None:
        """Test CoverageCorrelation creation with all fields."""
        corr = CoverageCorrelation(
            strategy="test_strategy",
            coverage_increase=50.0,
            unique_paths=75,
            crash_correlation=0.5,
            sample_size=100,
        )

        assert corr.strategy == "test_strategy"
        assert corr.coverage_increase == 50.0
        assert corr.unique_paths == 75
        assert corr.crash_correlation == 0.5
        assert corr.sample_size == 100

    def test_correlation_score_high_values(self) -> None:
        """Test correlation_score with high values."""
        corr = CoverageCorrelation(
            strategy="high_performer",
            coverage_increase=100.0,  # Max contribution
            unique_paths=100,  # Max contribution
            crash_correlation=1.0,  # Max contribution
            sample_size=1000,
        )

        score = corr.correlation_score()
        assert score == 1.0  # Perfect score

    def test_correlation_score_low_values(self) -> None:
        """Test correlation_score with low values."""
        corr = CoverageCorrelation(
            strategy="low_performer",
            coverage_increase=0.0,
            unique_paths=0,
            crash_correlation=0.0,
            sample_size=100,
        )

        score = corr.correlation_score()
        assert score == 0.0

    def test_correlation_score_capped_at_100_paths(self) -> None:
        """Test that unique_paths contribution is capped at 100."""
        corr = CoverageCorrelation(
            strategy="many_paths",
            coverage_increase=0.0,
            unique_paths=500,  # More than 100, should be capped
            crash_correlation=0.0,
            sample_size=100,
        )

        # Score should only use 100/100 = 1.0 for paths
        # 0.3 * 1.0 = 0.3
        score = corr.correlation_score()
        assert score == pytest.approx(0.3, abs=0.01)

    def test_correlation_score_capped_coverage(self) -> None:
        """Test that coverage_increase over 100% is capped."""
        corr = CoverageCorrelation(
            strategy="high_coverage",
            coverage_increase=200.0,  # Over 100%, should be capped
            unique_paths=0,
            crash_correlation=0.0,
            sample_size=100,
        )

        # Score should only use 100/100 = 1.0 for coverage
        # 0.4 * 1.0 = 0.4
        score = corr.correlation_score()
        assert score == pytest.approx(0.4, abs=0.01)


# =============================================================================
# TestTrendAnalysis
# =============================================================================


class TestTrendAnalysis:
    """Tests for TrendAnalysis dataclass."""

    def test_creation(self) -> None:
        """Test TrendAnalysis creation with all fields."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test_campaign",
            start_time=start,
            end_time=end,
            total_duration=end - start,
            crashes_over_time=[],
            coverage_over_time=[],
            mutations_over_time=[],
        )

        assert trend.campaign_name == "test_campaign"
        assert trend.start_time == start
        assert trend.end_time == end
        assert trend.total_duration == timedelta(hours=2)

    def test_crash_discovery_rate_with_crashes(self) -> None:
        """Test crash_discovery_rate calculation."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            crashes_over_time=[
                (datetime(2025, 1, 1, 10, 30, 0), 3),
                (datetime(2025, 1, 1, 11, 30, 0), 5),
            ],
        )

        # 8 crashes over 2 hours = 4 crashes/hour
        rate = trend.crash_discovery_rate()
        assert rate == pytest.approx(4.0, abs=0.01)

    def test_crash_discovery_rate_empty(self) -> None:
        """Test crash_discovery_rate with no crashes."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            crashes_over_time=[],
        )

        rate = trend.crash_discovery_rate()
        assert rate == 0.0

    def test_crash_discovery_rate_zero_duration(self) -> None:
        """Test crash_discovery_rate with zero duration."""
        now = datetime.now()

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=now,
            end_time=now,
            total_duration=timedelta(0),
            crashes_over_time=[(now, 5)],
        )

        rate = trend.crash_discovery_rate()
        assert rate == 0.0

    def test_coverage_growth_rate_with_growth(self) -> None:
        """Test coverage_growth_rate calculation."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            coverage_over_time=[
                (datetime(2025, 1, 1, 10, 0, 0), 10.0),  # Initial
                (datetime(2025, 1, 1, 12, 0, 0), 20.0),  # Final
            ],
        )

        # 10% -> 20% = 100% increase over 2 hours = 50%/hour
        rate = trend.coverage_growth_rate()
        assert rate == pytest.approx(50.0, abs=0.1)

    def test_coverage_growth_rate_insufficient_data(self) -> None:
        """Test coverage_growth_rate with insufficient data."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            coverage_over_time=[(datetime(2025, 1, 1, 10, 0, 0), 10.0)],
        )

        rate = trend.coverage_growth_rate()
        assert rate == 0.0

    def test_coverage_growth_rate_zero_initial(self) -> None:
        """Test coverage_growth_rate with zero initial coverage."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            coverage_over_time=[
                (start, 0.0),  # Zero initial
                (end, 20.0),
            ],
        )

        rate = trend.coverage_growth_rate()
        assert rate == 0.0

    def test_is_plateauing_true(self) -> None:
        """Test is_plateauing returns True with no recent crashes."""
        end = datetime(2025, 1, 1, 12, 0, 0)
        start = end - timedelta(hours=4)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=4),
            crashes_over_time=[
                # All crashes happened more than 1 hour ago
                (end - timedelta(hours=3), 5),
                (end - timedelta(hours=2), 3),
            ],
        )

        # threshold_hours=1.0, min_rate=0.1
        # No crashes in last 1 hour -> plateauing
        assert trend.is_plateauing(threshold_hours=1.0, min_rate=0.1) is True

    def test_is_plateauing_false_recent_crashes(self) -> None:
        """Test is_plateauing returns False with recent crashes."""
        end = datetime(2025, 1, 1, 12, 0, 0)
        start = end - timedelta(hours=4)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=4),
            crashes_over_time=[
                (end - timedelta(minutes=30), 2),  # Recent crash
                (end - timedelta(minutes=10), 1),  # Very recent
            ],
        )

        # 3 crashes in last 1 hour = 3.0/hour > 0.1 min_rate
        assert trend.is_plateauing(threshold_hours=1.0, min_rate=0.1) is False

    def test_is_plateauing_empty_crashes(self) -> None:
        """Test is_plateauing with no crash data."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            crashes_over_time=[],
        )

        assert trend.is_plateauing() is False

    def test_is_plateauing_single_crash(self) -> None:
        """Test is_plateauing with single crash entry."""
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=2),
            crashes_over_time=[(start, 1)],
        )

        assert trend.is_plateauing() is False

    def test_is_plateauing_invalid_threshold(self) -> None:
        """Test is_plateauing with invalid threshold."""
        end = datetime(2025, 1, 1, 12, 0, 0)
        start = end - timedelta(hours=4)

        trend = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=4),
            crashes_over_time=[
                (end - timedelta(hours=1), 5),
            ],
        )

        # threshold_hours <= 0 should return False
        assert trend.is_plateauing(threshold_hours=0, min_rate=0.1) is False
        assert trend.is_plateauing(threshold_hours=-1, min_rate=0.1) is False


# =============================================================================
# TestPerformanceMetrics
# =============================================================================


class TestPerformanceMetrics:
    """Tests for PerformanceMetrics dataclass."""

    def test_creation(self) -> None:
        """Test PerformanceMetrics creation."""
        metrics = PerformanceMetrics(
            mutations_per_second=50.0,
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=75.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=80.0,
        )

        assert metrics.mutations_per_second == 50.0
        assert metrics.peak_memory_mb == 1024.0
        assert metrics.avg_memory_mb == 512.0
        assert metrics.cpu_utilization == 75.0
        assert metrics.disk_io_mb_per_sec == 10.0
        assert metrics.cache_hit_rate == 80.0

    def test_throughput_score_high_values(self) -> None:
        """Test throughput_score with high values."""
        metrics = PerformanceMetrics(
            mutations_per_second=100.0,  # Target
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=100.0,  # Max
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=100.0,  # Max
        )

        # 0.5 * 1.0 + 0.3 * 1.0 + 0.2 * 1.0 = 1.0
        score = metrics.throughput_score()
        assert score == pytest.approx(1.0, abs=0.01)

    def test_throughput_score_low_values(self) -> None:
        """Test throughput_score with low values."""
        metrics = PerformanceMetrics(
            mutations_per_second=10.0,
            peak_memory_mb=512.0,
            avg_memory_mb=256.0,
            cpu_utilization=20.0,
            disk_io_mb_per_sec=1.0,
            cache_hit_rate=10.0,
        )

        # 0.5 * 0.1 + 0.3 * 0.1 + 0.2 * 0.2 = 0.05 + 0.03 + 0.04 = 0.12
        score = metrics.throughput_score()
        assert score == pytest.approx(0.12, abs=0.01)

    def test_throughput_score_capped_mutations(self) -> None:
        """Test throughput_score caps mutation rate at 100."""
        metrics = PerformanceMetrics(
            mutations_per_second=500.0,  # Over 100, capped
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=0.0,
            disk_io_mb_per_sec=0.0,
            cache_hit_rate=0.0,
        )

        # 0.5 * 1.0 + 0.3 * 0.0 + 0.2 * 0.0 = 0.5
        score = metrics.throughput_score()
        assert score == pytest.approx(0.5, abs=0.01)


# =============================================================================
# TestCampaignAnalyzerInit
# =============================================================================


class TestCampaignAnalyzerInit:
    """Tests for CampaignAnalyzer initialization."""

    def test_init_default(self) -> None:
        """Test CampaignAnalyzer initialization with defaults."""
        analyzer = CampaignAnalyzer()

        assert analyzer.campaign_name == "DICOM Fuzzing"
        assert analyzer.coverage_data == {}
        assert analyzer.trend_data is None
        assert analyzer.performance_data is None

    def test_init_custom_name(self) -> None:
        """Test CampaignAnalyzer initialization with custom name."""
        analyzer = CampaignAnalyzer(campaign_name="Custom Campaign")

        assert analyzer.campaign_name == "Custom Campaign"


# =============================================================================
# TestAnalyzeStrategyEffectiveness
# =============================================================================


class TestAnalyzeStrategyEffectiveness:
    """Tests for analyze_strategy_effectiveness method."""

    def test_with_matching_stats(self) -> None:
        """Test analyze_strategy_effectiveness with matching mutation stats."""
        analyzer = CampaignAnalyzer()

        # Mock report
        mock_report = MagicMock()
        mock_report.get_strategy_effectiveness.return_value = {
            "strategy_a": {
                "series_coverage": 80.0,
                "usage_count": 100,
                "avg_mutations_per_series": 5.0,
            },
        }

        # Mock mutation stats
        mock_stat = MagicMock()
        mock_stat.strategy_name = "strategy_a"
        mock_stat.times_used = 100
        mock_stat.crashes_found = 5
        mock_stat.total_duration = 60.0
        mock_stat.effectiveness_score.return_value = 0.8

        result = analyzer.analyze_strategy_effectiveness(mock_report, [mock_stat])

        assert "strategy_a" in result
        assert result["strategy_a"]["effectiveness_score"] == 0.8
        assert result["strategy_a"]["crashes_per_mutation"] == pytest.approx(
            0.05, abs=0.001
        )
        assert result["strategy_a"]["coverage_contribution"] == 80.0
        assert result["strategy_a"]["usage_count"] == 100

    def test_with_no_matching_stats(self) -> None:
        """Test analyze_strategy_effectiveness without matching stats."""
        analyzer = CampaignAnalyzer()

        mock_report = MagicMock()
        mock_report.get_strategy_effectiveness.return_value = {
            "orphan_strategy": {
                "series_coverage": 60.0,
                "usage_count": 50,
                "avg_mutations_per_series": 3.0,
            },
        }

        result = analyzer.analyze_strategy_effectiveness(mock_report, [])

        assert "orphan_strategy" in result
        assert result["orphan_strategy"]["effectiveness_score"] == 0.5  # Default
        assert result["orphan_strategy"]["crashes_per_mutation"] == 0.0

    def test_with_zero_times_used(self) -> None:
        """Test with stats that have zero times_used."""
        analyzer = CampaignAnalyzer()

        mock_report = MagicMock()
        mock_report.get_strategy_effectiveness.return_value = {
            "unused_strategy": {
                "series_coverage": 0.0,
                "usage_count": 0,
                "avg_mutations_per_series": 0.0,
            },
        }

        mock_stat = MagicMock()
        mock_stat.strategy_name = "unused_strategy"
        mock_stat.times_used = 0
        mock_stat.crashes_found = 0
        mock_stat.total_duration = 0.0
        mock_stat.effectiveness_score.return_value = 0.0

        result = analyzer.analyze_strategy_effectiveness(mock_report, [mock_stat])

        assert result["unused_strategy"]["crashes_per_mutation"] == 0.0
        assert result["unused_strategy"]["time_efficiency"] == 0.0


# =============================================================================
# TestCalculateCoverageCorrelation
# =============================================================================


class TestCalculateCoverageCorrelation:
    """Tests for calculate_coverage_correlation method."""

    def test_basic_calculation(self) -> None:
        """Test basic coverage correlation calculation."""
        analyzer = CampaignAnalyzer()

        corr = analyzer.calculate_coverage_correlation(
            strategy="test_strategy",
            coverage_increase=50.0,
            unique_paths=80,
            crashes_found=10,
            mutations_applied=100,
        )

        assert corr.strategy == "test_strategy"
        assert corr.coverage_increase == 50.0
        assert corr.unique_paths == 80
        assert corr.crash_correlation == pytest.approx(0.1, abs=0.001)
        assert corr.sample_size == 100

    def test_caches_result(self) -> None:
        """Test that correlation is cached in coverage_data."""
        analyzer = CampaignAnalyzer()

        corr = analyzer.calculate_coverage_correlation(
            strategy="cached_strategy",
            coverage_increase=30.0,
            unique_paths=50,
            crashes_found=5,
            mutations_applied=50,
        )

        assert "cached_strategy" in analyzer.coverage_data
        assert analyzer.coverage_data["cached_strategy"] == corr

    def test_zero_mutations(self) -> None:
        """Test with zero mutations applied."""
        analyzer = CampaignAnalyzer()

        corr = analyzer.calculate_coverage_correlation(
            strategy="zero_strategy",
            coverage_increase=0.0,
            unique_paths=0,
            crashes_found=0,
            mutations_applied=0,
        )

        assert corr.crash_correlation == 0.0

    def test_high_crash_correlation_capped(self) -> None:
        """Test that crash correlation is capped at 1.0."""
        analyzer = CampaignAnalyzer()

        # More crashes than mutations (shouldn't happen but test cap)
        corr = analyzer.calculate_coverage_correlation(
            strategy="high_crash",
            coverage_increase=100.0,
            unique_paths=100,
            crashes_found=200,
            mutations_applied=100,
        )

        assert corr.crash_correlation == 1.0  # Capped


# =============================================================================
# TestAnalyzeTrends
# =============================================================================


class TestAnalyzeTrends:
    """Tests for analyze_trends method."""

    def test_basic_trend_creation(self) -> None:
        """Test basic trend analysis creation."""
        analyzer = CampaignAnalyzer()

        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        crash_timeline = [(datetime(2025, 1, 1, 11, 0, 0), 3)]
        coverage_timeline = [(start, 10.0), (end, 20.0)]
        mutation_timeline = [(start, 100), (end, 500)]

        trend = analyzer.analyze_trends(
            start_time=start,
            end_time=end,
            crash_timeline=crash_timeline,
            coverage_timeline=coverage_timeline,
            mutation_timeline=mutation_timeline,
        )

        assert trend.campaign_name == analyzer.campaign_name
        assert trend.start_time == start
        assert trend.end_time == end
        assert len(trend.crashes_over_time) == 1

    def test_stores_trend_data(self) -> None:
        """Test that trend data is stored in analyzer."""
        analyzer = CampaignAnalyzer()

        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)

        trend = analyzer.analyze_trends(
            start_time=start,
            end_time=end,
            crash_timeline=[],
            coverage_timeline=[],
            mutation_timeline=[],
        )

        assert analyzer.trend_data is trend


# =============================================================================
# TestProfilePerformance
# =============================================================================


class TestProfilePerformance:
    """Tests for profile_performance method."""

    def test_basic_profiling(self) -> None:
        """Test basic performance profiling."""
        analyzer = CampaignAnalyzer()

        metrics = analyzer.profile_performance(
            mutations_per_second=50.0,
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=75.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=80.0,
        )

        assert metrics.mutations_per_second == 50.0
        assert metrics.peak_memory_mb == 1024.0
        assert metrics.cache_hit_rate == 80.0

    def test_stores_performance_data(self) -> None:
        """Test that performance data is stored in analyzer."""
        analyzer = CampaignAnalyzer()

        metrics = analyzer.profile_performance(
            mutations_per_second=100.0,
            peak_memory_mb=2048.0,
            avg_memory_mb=1024.0,
            cpu_utilization=90.0,
        )

        assert analyzer.performance_data is metrics


# =============================================================================
# TestGenerateRecommendations
# =============================================================================


class TestGenerateRecommendations:
    """Tests for generate_recommendations method."""

    def test_empty_data_default_recommendation(self) -> None:
        """Test recommendations with no data."""
        analyzer = CampaignAnalyzer()

        recommendations = analyzer.generate_recommendations()

        assert len(recommendations) == 1
        assert "[i] No specific recommendations" in recommendations[0]

    def test_coverage_recommendations_best_strategy(self) -> None:
        """Test recommendations include best strategy."""
        analyzer = CampaignAnalyzer()

        # Add coverage data
        analyzer.coverage_data["good_strategy"] = CoverageCorrelation(
            strategy="good_strategy",
            coverage_increase=80.0,
            unique_paths=90,
            crash_correlation=0.8,
            sample_size=100,
        )
        analyzer.coverage_data["bad_strategy"] = CoverageCorrelation(
            strategy="bad_strategy",
            coverage_increase=10.0,
            unique_paths=5,
            crash_correlation=0.1,
            sample_size=50,
        )

        recommendations = analyzer.generate_recommendations()

        # Should recommend good_strategy
        assert any("good_strategy" in rec for rec in recommendations)
        # Should warn about bad_strategy
        assert any("bad_strategy" in rec for rec in recommendations)

    def test_trend_plateau_warning(self) -> None:
        """Test recommendations include plateau warning."""
        analyzer = CampaignAnalyzer()

        end = datetime(2025, 1, 1, 12, 0, 0)
        start = end - timedelta(hours=4)

        # Create trend that is plateauing (requires at least 2 crash entries)
        analyzer.trend_data = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=4),
            crashes_over_time=[
                # All crashes happened early, none in last hour
                (end - timedelta(hours=3), 5),
                (end - timedelta(hours=2), 3),
            ],
        )

        recommendations = analyzer.generate_recommendations()

        assert any("plateauing" in rec.lower() for rec in recommendations)

    def test_trend_high_crash_rate(self) -> None:
        """Test recommendations with high crash rate."""
        analyzer = CampaignAnalyzer()

        end = datetime(2025, 1, 1, 12, 0, 0)
        start = end - timedelta(hours=1)

        analyzer.trend_data = TrendAnalysis(
            campaign_name="test",
            start_time=start,
            end_time=end,
            total_duration=timedelta(hours=1),
            crashes_over_time=[
                (end - timedelta(minutes=30), 5),  # 5 crashes
            ],
        )

        recommendations = analyzer.generate_recommendations()

        assert any("continue fuzzing" in rec.lower() for rec in recommendations)

    def test_performance_low_throughput_warning(self) -> None:
        """Test recommendations with low throughput."""
        analyzer = CampaignAnalyzer()

        analyzer.performance_data = PerformanceMetrics(
            mutations_per_second=10.0,
            peak_memory_mb=512.0,
            avg_memory_mb=256.0,
            cpu_utilization=30.0,
            disk_io_mb_per_sec=1.0,
            cache_hit_rate=20.0,
        )

        recommendations = analyzer.generate_recommendations()

        assert any("throughput" in rec.lower() for rec in recommendations)
        assert any("cache" in rec.lower() for rec in recommendations)
        assert any(
            "cpu" in rec.lower() or "worker" in rec.lower() for rec in recommendations
        )

    def test_performance_high_memory_warning(self) -> None:
        """Test recommendations with high memory usage."""
        analyzer = CampaignAnalyzer()

        analyzer.performance_data = PerformanceMetrics(
            mutations_per_second=100.0,
            peak_memory_mb=3000.0,  # Over 2000MB threshold
            avg_memory_mb=2500.0,
            cpu_utilization=80.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=80.0,
        )

        recommendations = analyzer.generate_recommendations()

        assert any("memory" in rec.lower() for rec in recommendations)


# =============================================================================
# TestExportToJson
# =============================================================================


class TestExportToJson:
    """Tests for export_to_json method."""

    def test_basic_export(self, tmp_path) -> None:
        """Test basic JSON export."""
        analyzer = CampaignAnalyzer(campaign_name="Export Test")

        output_path = tmp_path / "analytics.json"
        result_path = analyzer.export_to_json(output_path)

        assert result_path == output_path
        assert output_path.exists()

        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["campaign_name"] == "Export Test"
        assert "generated_at" in data
        assert "coverage_correlation" in data
        assert "recommendations" in data

    def test_export_with_all_data(self, tmp_path) -> None:
        """Test JSON export with coverage, trend, and performance data."""
        analyzer = CampaignAnalyzer(campaign_name="Full Export")

        # Add coverage data
        analyzer.calculate_coverage_correlation(
            strategy="exported_strategy",
            coverage_increase=50.0,
            unique_paths=75,
            crashes_found=5,
            mutations_applied=100,
        )

        # Add trend data
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 0)
        analyzer.analyze_trends(
            start_time=start,
            end_time=end,
            crash_timeline=[(end, 3)],
            coverage_timeline=[(start, 10.0), (end, 20.0)],
            mutation_timeline=[],
        )

        # Add performance data
        analyzer.profile_performance(
            mutations_per_second=50.0,
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=75.0,
        )

        output_path = tmp_path / "full_analytics.json"
        analyzer.export_to_json(output_path)

        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)

        assert "exported_strategy" in data["coverage_correlation"]
        assert data["trend_analysis"] is not None
        assert data["trend_analysis"]["crash_discovery_rate"] > 0
        assert data["performance_metrics"] is not None
        assert data["performance_metrics"]["mutations_per_second"] == 50.0
