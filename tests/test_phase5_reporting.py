"""
Unit tests for Phase 5 - Enhanced Reporting & Analytics

Tests all Phase 5 components:
- Series3D Reporter (series_reporter.py)
- Campaign Analytics Engine (campaign_analytics.py)
- Visualization Module (visualization.py)
- CLI Tool (generate_3d_report.py)
"""

import json
from datetime import datetime, timedelta

import pytest

# Skip entire module if matplotlib not available (optional dependency for visualization)
pytest.importorskip("matplotlib")

from dicom_fuzzer.analytics.campaign_analytics import (
    CampaignAnalyzer,
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.analytics.visualization import FuzzingVisualizer
from dicom_fuzzer.core.series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)
from dicom_fuzzer.core.statistics import MutationStatistics
from dicom_fuzzer.strategies.series_mutator import (
    SeriesMutationRecord,
    SeriesMutationStrategy,
)


class TestSeriesMutationSummary:
    """Test SeriesMutationSummary dataclass."""

    def test_create_summary(self):
        """Test creating a series mutation summary."""
        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=0,
        )

        assert summary.series_uid == "1.2.840.10008.5.1.4.1.1.2.1"
        assert summary.modality == "CT"
        assert summary.slice_count == 20
        assert summary.total_mutations == 0
        assert len(summary.strategies_used) == 0
        assert len(summary.affected_slices) == 0

    def test_add_mutation(self):
        """Test adding mutations to summary."""
        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=0,
        )

        # Create mock mutation record
        record = SeriesMutationRecord(
            strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
            severity="moderate",
            slice_index=5,
            tag="SliceLocation",
            original_value="10.0",
            mutated_value="15.0",
        )

        summary.add_mutation(record)

        assert summary.total_mutations == 1
        assert (
            SeriesMutationStrategy.SLICE_POSITION_ATTACK.value
            in summary.strategies_used
        )
        assert 5 in summary.affected_slices
        assert "moderate" in summary.severity_distribution

    def test_coverage_percentage(self):
        """Test coverage percentage calculation."""
        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=0,
        )

        # Add mutations to different slices
        for i in range(10):
            record = SeriesMutationRecord(
                strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
                severity="moderate",
                slice_index=i,
                tag="SliceLocation",
                original_value=str(i),
                mutated_value=str(i + 100),
            )
            summary.add_mutation(record)

        coverage = summary.get_coverage_percentage()
        assert coverage == 50.0  # 10/20 = 50%


class TestSeries3DReport:
    """Test Series3DReport dataclass."""

    def test_create_report(self):
        """Test creating a 3D series report."""
        report = Series3DReport(campaign_name="Test Campaign")

        assert report.campaign_name == "Test Campaign"
        assert report.total_series_fuzzed == 0
        assert report.total_mutations_applied == 0
        assert report.total_crashes == 0
        assert len(report.series_summaries) == 0

    def test_add_series_summary(self):
        """Test adding series summaries to report."""
        report = Series3DReport(campaign_name="Test Campaign")

        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=50,
        )

        report.add_series_summary(summary)

        assert report.total_series_fuzzed == 1
        assert report.total_mutations_applied == 50
        assert len(report.series_summaries) == 1

    def test_strategy_effectiveness(self):
        """Test strategy effectiveness calculation."""
        report = Series3DReport(campaign_name="Test Campaign")

        # Create summaries with different strategies
        for i in range(3):
            summary = SeriesMutationSummary(
                series_uid=f"1.2.840.10008.5.1.4.1.1.2.{i}",
                modality="CT",
                slice_count=20,
                total_mutations=0,
            )

            # Add mutations with different strategies
            record1 = SeriesMutationRecord(
                strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
                severity="moderate",
                slice_index=0,
                tag="SliceLocation",
                original_value="0",
                mutated_value="100",
            )
            summary.add_mutation(record1)

            record2 = SeriesMutationRecord(
                strategy=SeriesMutationStrategy.METADATA_CORRUPTION.value,
                severity="moderate",
                slice_index=0,
                tag="PatientName",
                original_value="Test",
                mutated_value="MUTATED",
            )
            summary.add_mutation(record2)

            report.add_series_summary(summary)

        effectiveness = report.get_strategy_effectiveness()

        assert len(effectiveness) == 2
        assert SeriesMutationStrategy.SLICE_POSITION_ATTACK.value in effectiveness
        assert SeriesMutationStrategy.METADATA_CORRUPTION.value in effectiveness

        # Check metrics
        slice_attack_metrics = effectiveness[
            SeriesMutationStrategy.SLICE_POSITION_ATTACK.value
        ]
        assert slice_attack_metrics["usage_count"] == 3
        assert slice_attack_metrics["series_coverage"] == 100.0  # Used in all 3 series


class TestSeries3DReportGenerator:
    """Test Series3DReportGenerator class."""

    def test_create_generator(self, tmp_path):
        """Test creating a report generator."""
        generator = Series3DReportGenerator(output_dir=str(tmp_path))

        assert generator.output_dir == tmp_path
        assert tmp_path.exists()

    def test_generate_html_report(self, tmp_path):
        """Test HTML report generation."""
        generator = Series3DReportGenerator(output_dir=str(tmp_path))

        # Create test report
        report = Series3DReport(campaign_name="Test Campaign")
        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=10,
        )
        report.add_series_summary(summary)

        # Generate HTML
        html_path = generator.generate_html_report(report)

        assert html_path.exists()
        assert html_path.suffix == ".html"

        # Check HTML content
        content = html_path.read_text(encoding="utf-8")
        assert "Test Campaign" in content
        assert "Series Fuzzed" in content
        assert "Total Mutations" in content

    def test_generate_json_report(self, tmp_path):
        """Test JSON report generation."""
        generator = Series3DReportGenerator(output_dir=str(tmp_path))

        # Create test report
        report = Series3DReport(campaign_name="Test Campaign")
        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=10,
        )
        report.add_series_summary(summary)

        # Generate JSON
        json_path = generator.generate_json_report(report)

        assert json_path.exists()
        assert json_path.suffix == ".json"

        # Check JSON content
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["campaign_name"] == "Test Campaign"
        assert data["summary"]["total_series_fuzzed"] == 1
        assert data["summary"]["total_mutations_applied"] == 10
        assert len(data["series_details"]) == 1


class TestCoverageCorrelation:
    """Test CoverageCorrelation dataclass."""

    def test_create_correlation(self):
        """Test creating a coverage correlation."""
        corr = CoverageCorrelation(
            strategy="SLICE_POSITION_ATTACK",
            coverage_increase=25.0,
            unique_paths=50,
            crash_correlation=0.8,
            sample_size=100,
        )

        assert corr.strategy == "SLICE_POSITION_ATTACK"
        assert corr.coverage_increase == 25.0
        assert corr.unique_paths == 50
        assert corr.crash_correlation == 0.8
        assert corr.sample_size == 100

    def test_correlation_score(self):
        """Test correlation score calculation."""
        # High effectiveness
        corr_high = CoverageCorrelation(
            strategy="TEST",
            coverage_increase=80.0,  # High coverage
            unique_paths=100,  # Many paths
            crash_correlation=0.9,  # High crash correlation
            sample_size=100,
        )

        score_high = corr_high.correlation_score()
        assert 0.0 <= score_high <= 1.0
        assert score_high > 0.7  # Should be high

        # Low effectiveness
        corr_low = CoverageCorrelation(
            strategy="TEST",
            coverage_increase=5.0,  # Low coverage
            unique_paths=5,  # Few paths
            crash_correlation=0.1,  # Low crash correlation
            sample_size=100,
        )

        score_low = corr_low.correlation_score()
        assert 0.0 <= score_low <= 1.0
        assert score_low < 0.3  # Should be low


class TestTrendAnalysis:
    """Test TrendAnalysis dataclass."""

    def test_create_trend_analysis(self):
        """Test creating trend analysis."""
        start = datetime.now()
        end = start + timedelta(hours=2)

        trend = TrendAnalysis(
            campaign_name="Test",
            start_time=start,
            end_time=end,
            total_duration=end - start,
        )

        assert trend.campaign_name == "Test"
        assert trend.total_duration == timedelta(hours=2)

    def test_crash_discovery_rate(self):
        """Test crash discovery rate calculation."""
        start = datetime.now()
        end = start + timedelta(hours=2)

        trend = TrendAnalysis(
            campaign_name="Test",
            start_time=start,
            end_time=end,
            total_duration=end - start,
            crashes_over_time=[
                (start + timedelta(minutes=30), 5),
                (start + timedelta(hours=1), 10),
                (start + timedelta(hours=2), 15),
            ],
        )

        rate = trend.crash_discovery_rate()
        assert rate == 15.0  # 30 total crashes / 2 hours = 15/hour

    def test_plateau_detection(self):
        """Test plateau detection."""
        start = datetime.now()
        end = start + timedelta(hours=5)

        # Early phase - not plateauing (steady crash rate)
        trend_active = TrendAnalysis(
            campaign_name="Test",
            start_time=start,
            end_time=end,
            total_duration=end - start,
            crashes_over_time=[(start + timedelta(hours=i), 10) for i in range(5)],
        )

        assert not trend_active.is_plateauing(threshold_hours=2.0, min_rate=0.1)

        # Plateau phase - no recent crashes
        trend_plateau = TrendAnalysis(
            campaign_name="Test",
            start_time=start,
            end_time=end,
            total_duration=end - start,
            crashes_over_time=[
                (start + timedelta(hours=i), 10 if i < 3 else 0) for i in range(5)
            ],
        )

        assert trend_plateau.is_plateauing(threshold_hours=2.0, min_rate=0.1)


class TestPerformanceMetrics:
    """Test PerformanceMetrics dataclass."""

    def test_create_metrics(self):
        """Test creating performance metrics."""
        metrics = PerformanceMetrics(
            mutations_per_second=50.0,
            peak_memory_mb=500.0,
            avg_memory_mb=300.0,
            cpu_utilization=75.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=80.0,
        )

        assert metrics.mutations_per_second == 50.0
        assert metrics.peak_memory_mb == 500.0
        assert metrics.cpu_utilization == 75.0

    def test_throughput_score(self):
        """Test throughput score calculation."""
        # High throughput
        metrics_high = PerformanceMetrics(
            mutations_per_second=100.0,
            peak_memory_mb=500.0,
            avg_memory_mb=300.0,
            cpu_utilization=80.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=90.0,
        )

        score_high = metrics_high.throughput_score()
        assert 0.0 <= score_high <= 1.0
        assert score_high > 0.8  # Should be high

        # Low throughput
        metrics_low = PerformanceMetrics(
            mutations_per_second=10.0,
            peak_memory_mb=500.0,
            avg_memory_mb=300.0,
            cpu_utilization=20.0,
            disk_io_mb_per_sec=1.0,
            cache_hit_rate=30.0,
        )

        score_low = metrics_low.throughput_score()
        assert 0.0 <= score_low <= 1.0
        assert score_low < 0.5  # Should be low


class TestCampaignAnalyzer:
    """Test CampaignAnalyzer class."""

    def test_create_analyzer(self):
        """Test creating a campaign analyzer."""
        analyzer = CampaignAnalyzer(campaign_name="Test Campaign")

        assert analyzer.campaign_name == "Test Campaign"
        assert len(analyzer.coverage_data) == 0

    def test_analyze_strategy_effectiveness(self):
        """Test strategy effectiveness analysis."""
        analyzer = CampaignAnalyzer()

        # Create test report
        report = Series3DReport(campaign_name="Test")
        summary = SeriesMutationSummary(
            series_uid="1.2.840.10008.5.1.4.1.1.2.1",
            modality="CT",
            slice_count=20,
            total_mutations=0,
        )

        # Add mutations
        record = SeriesMutationRecord(
            strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
            severity="moderate",
            slice_index=0,
            tag="SliceLocation",
            original_value="0",
            mutated_value="100",
        )
        summary.add_mutation(record)
        report.add_series_summary(summary)

        # Create mutation statistics
        mutation_stats = [
            MutationStatistics(
                strategy_name=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
                times_used=10,
                crashes_found=2,
                validation_failures=3,
                total_duration=1.0,
            )
        ]

        # Analyze
        effectiveness = analyzer.analyze_strategy_effectiveness(report, mutation_stats)

        assert SeriesMutationStrategy.SLICE_POSITION_ATTACK.value in effectiveness
        metrics = effectiveness[SeriesMutationStrategy.SLICE_POSITION_ATTACK.value]

        assert "effectiveness_score" in metrics
        assert "crashes_per_mutation" in metrics
        assert metrics["crashes_per_mutation"] == 0.2  # 2/10

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        analyzer = CampaignAnalyzer()

        # Add some test data
        analyzer.calculate_coverage_correlation(
            strategy="HIGH_EFFECTIVENESS",
            coverage_increase=50.0,
            unique_paths=100,
            crashes_found=10,
            mutations_applied=100,
        )

        analyzer.calculate_coverage_correlation(
            strategy="LOW_EFFECTIVENESS",
            coverage_increase=5.0,
            unique_paths=5,
            crashes_found=0,
            mutations_applied=100,
        )

        recommendations = analyzer.generate_recommendations()

        assert len(recommendations) > 0
        assert any("HIGH_EFFECTIVENESS" in rec for rec in recommendations)


class TestFuzzingVisualizer:
    """Test FuzzingVisualizer class."""

    def test_create_visualizer(self, tmp_path):
        """Test creating a visualizer."""
        visualizer = FuzzingVisualizer(output_dir=str(tmp_path))

        assert visualizer.output_dir == tmp_path
        assert tmp_path.exists()

    def test_plot_strategy_effectiveness(self, tmp_path):
        """Test strategy effectiveness chart generation."""
        visualizer = FuzzingVisualizer(output_dir=str(tmp_path))

        effectiveness_data = {
            "SLICE_POSITION_ATTACK": {"effectiveness_score": 0.8, "usage_count": 100},
            "METADATA_CORRUPTION": {"effectiveness_score": 0.6, "usage_count": 50},
        }

        # Generate PNG
        png_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )
        assert png_path.exists()
        assert png_path.suffix == ".png"

        # Generate HTML
        html_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="html"
        )
        assert html_path.exists()
        assert html_path.suffix == ".html"

    def test_plot_performance_dashboard(self, tmp_path):
        """Test performance dashboard generation."""
        visualizer = FuzzingVisualizer(output_dir=str(tmp_path))

        metrics = PerformanceMetrics(
            mutations_per_second=50.0,
            peak_memory_mb=500.0,
            avg_memory_mb=300.0,
            cpu_utilization=75.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=80.0,
        )

        # Generate PNG
        png_path = visualizer.plot_performance_dashboard(metrics, output_format="png")
        assert png_path.exists()
        assert png_path.suffix == ".png"

        # Generate HTML
        html_path = visualizer.plot_performance_dashboard(metrics, output_format="html")
        assert html_path.exists()
        assert html_path.suffix == ".html"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
