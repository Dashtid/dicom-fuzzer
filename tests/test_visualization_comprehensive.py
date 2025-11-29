"""Comprehensive Unit Tests for Visualization Module

Tests the FuzzingVisualizer class to improve coverage from 1% to 80%+.
Aligned with actual visualization.py API (v1.3.0).
"""

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

# Skip all tests in this module if matplotlib is not installed
pytest.importorskip("matplotlib")
pytest.importorskip("plotly")

import matplotlib
import matplotlib.pyplot as plt

# Force non-interactive backend for tests
matplotlib.use("Agg")

from dicom_fuzzer.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.analytics.visualization import FuzzingVisualizer


@pytest.fixture
def output_dir(tmp_path):
    """Create temporary output directory for test charts."""
    charts_dir = tmp_path / "charts"
    charts_dir.mkdir(exist_ok=True)
    return str(charts_dir)


@pytest.fixture
def sample_effectiveness_data():
    """Create sample effectiveness data for strategies."""
    return {
        "metadata_fuzzer": {
            "effectiveness_score": 0.85,
            "crashes_per_mutation": 0.15,
            "coverage_contribution": 45.0,
            "time_efficiency": 120.5,
            "usage_count": 150,
            "avg_mutations_per_series": 8.3,
        },
        "pixel_fuzzer": {
            "effectiveness_score": 0.72,
            "crashes_per_mutation": 0.09,
            "coverage_contribution": 30.0,
            "time_efficiency": 98.2,
            "usage_count": 120,
            "avg_mutations_per_series": 5.6,
        },
        "header_fuzzer": {
            "effectiveness_score": 0.68,
            "crashes_per_mutation": 0.07,
            "coverage_contribution": 25.0,
            "time_efficiency": 105.1,
            "usage_count": 100,
            "avg_mutations_per_series": 6.2,
        },
    }


@pytest.fixture
def sample_coverage_correlation():
    """Create sample coverage correlation data."""
    return {
        "metadata_fuzzer": CoverageCorrelation(
            strategy="metadata_fuzzer",
            coverage_increase=45.0,
            unique_paths=85,
            crash_correlation=0.85,
            sample_size=150,
        ),
        "pixel_fuzzer": CoverageCorrelation(
            strategy="pixel_fuzzer",
            coverage_increase=30.0,
            unique_paths=60,
            crash_correlation=0.72,
            sample_size=120,
        ),
        "header_fuzzer": CoverageCorrelation(
            strategy="header_fuzzer",
            coverage_increase=25.0,
            unique_paths=50,
            crash_correlation=0.68,
            sample_size=100,
        ),
    }


@pytest.fixture
def sample_performance_metrics():
    """Create sample performance metrics."""
    return PerformanceMetrics(
        mutations_per_second=150.5,
        peak_memory_mb=512.0,
        avg_memory_mb=256.0,
        cpu_utilization=75.0,
        disk_io_mb_per_sec=10.5,
        cache_hit_rate=85.0,
    )


@pytest.fixture
def sample_trend_analysis():
    """Create sample trend analysis data."""
    now = datetime.now()
    return TrendAnalysis(
        campaign_name="Test Campaign",
        start_time=now - timedelta(hours=10),
        end_time=now,
        total_duration=timedelta(hours=10),
        crashes_over_time=[(now - timedelta(hours=i), i) for i in range(10, 0, -1)],
        coverage_over_time=[
            (now - timedelta(hours=i), 50 + i * 2.0) for i in range(10, 0, -1)
        ],
        mutations_over_time=[(now - timedelta(hours=i), i * 10) for i in range(10, 0, -1)],
    )


class TestFuzzingVisualizerInitialization:
    """Test FuzzingVisualizer initialization."""

    def test_initialization(self, output_dir):
        """Test visualizer initialization."""
        viz = FuzzingVisualizer(output_dir=output_dir)
        assert viz.output_dir == Path(output_dir)
        assert viz.output_dir.exists()
        assert isinstance(viz.colors, dict)
        assert "primary" in viz.colors
        assert "secondary" in viz.colors

    def test_initialization_creates_directory(self, tmp_path):
        """Test that initialization creates the output directory if it doesn't exist."""
        new_dir = tmp_path / "new_charts"
        viz = FuzzingVisualizer(output_dir=str(new_dir))
        assert new_dir.exists()

    def test_color_scheme_defined(self, output_dir):
        """Test that color scheme is properly defined."""
        viz = FuzzingVisualizer(output_dir=output_dir)
        required_colors = ["primary", "secondary", "success", "warning", "danger", "info"]
        for color in required_colors:
            assert color in viz.colors
            assert isinstance(viz.colors[color], str)
            assert viz.colors[color].startswith("#")


class TestStrategyEffectivenessPlots:
    """Test strategy effectiveness plotting methods."""

    @patch("matplotlib.pyplot.savefig")
    def test_plot_strategy_effectiveness_matplotlib_png(
        self, mock_savefig, output_dir, sample_effectiveness_data
    ):
        """Test plotting strategy effectiveness bar chart with Matplotlib (PNG)."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_strategy_effectiveness(sample_effectiveness_data, output_format="png")

        assert chart_path.suffix == ".png"
        assert "strategy_effectiveness" in str(chart_path)
        assert mock_savefig.called
        plt.close("all")

    @patch("matplotlib.pyplot.savefig")
    def test_plot_strategy_effectiveness_matplotlib_svg(
        self, mock_savefig, output_dir, sample_effectiveness_data
    ):
        """Test plotting strategy effectiveness with SVG output."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_strategy_effectiveness(sample_effectiveness_data, output_format="svg")

        assert chart_path.suffix == ".svg"
        assert mock_savefig.called
        plt.close("all")

    @patch("plotly.graph_objects.Figure.write_html")
    def test_plot_strategy_effectiveness_plotly_html(
        self, mock_write_html, output_dir, sample_effectiveness_data
    ):
        """Test plotting strategy effectiveness with Plotly (HTML)."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_strategy_effectiveness(sample_effectiveness_data, output_format="html")

        assert chart_path.suffix == ".html"
        assert "strategy_effectiveness" in str(chart_path)
        assert mock_write_html.called

    @patch("matplotlib.pyplot.savefig")
    def test_plot_empty_strategy_data(self, mock_savefig, output_dir):
        """Test plotting with empty strategy data."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_strategy_effectiveness({}, output_format="png")
        assert chart_path is not None
        assert chart_path.suffix == ".png"
        plt.close("all")

    @patch("matplotlib.pyplot.savefig")
    def test_plot_single_strategy(self, mock_savefig, output_dir):
        """Test plotting with a single strategy."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        strategy_data = {
            "metadata_fuzzer": {"effectiveness_score": 0.75, "usage_count": 100}
        }

        chart_path = viz.plot_strategy_effectiveness(strategy_data, output_format="png")
        assert chart_path is not None
        plt.close("all")


class TestCrashTrendPlots:
    """Test crash trend plotting methods."""

    @patch("matplotlib.pyplot.savefig")
    def test_plot_crash_trend_matplotlib(
        self, mock_savefig, output_dir, sample_trend_analysis
    ):
        """Test plotting crash discovery trend line with Matplotlib."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_crash_trend(sample_trend_analysis, output_format="png")

        assert chart_path.suffix == ".png"
        assert "crash_trend" in str(chart_path)
        assert mock_savefig.called
        plt.close("all")

    @patch("plotly.graph_objects.Figure.write_html")
    def test_plot_crash_trend_plotly(
        self, mock_write_html, output_dir, sample_trend_analysis
    ):
        """Test plotting crash trend with Plotly."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_crash_trend(sample_trend_analysis, output_format="html")

        assert chart_path.suffix == ".html"
        assert "crash_trend" in str(chart_path)
        assert mock_write_html.called

    @patch("matplotlib.pyplot.savefig")
    def test_plot_crash_trend_no_data(self, mock_savefig, output_dir):
        """Test plotting crash trend with no crash data."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        # Create empty trend data
        now = datetime.now()
        empty_trend = TrendAnalysis(
            campaign_name="Empty",
            start_time=now - timedelta(hours=1),
            end_time=now,
            total_duration=timedelta(hours=1),
            crashes_over_time=[],
            coverage_over_time=[],
            mutations_over_time=[],
        )

        chart_path = viz.plot_crash_trend(empty_trend, output_format="png")
        assert chart_path is not None
        assert chart_path.exists() or mock_savefig.called
        plt.close("all")

    @patch("plotly.graph_objects.Figure.write_html")
    def test_plot_crash_trend_no_data_plotly(self, mock_write_html, output_dir):
        """Test plotting crash trend with no data using Plotly."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        now = datetime.now()
        empty_trend = TrendAnalysis(
            campaign_name="Empty",
            start_time=now,
            end_time=now,
            total_duration=timedelta(0),
            crashes_over_time=[],
            coverage_over_time=[],
            mutations_over_time=[],
        )

        chart_path = viz.plot_crash_trend(empty_trend, output_format="html")
        assert chart_path is not None
        assert mock_write_html.called


class TestCoverageHeatmapPlots:
    """Test coverage correlation heatmap plotting methods."""

    @patch("matplotlib.pyplot.savefig")
    def test_plot_coverage_heatmap_matplotlib(
        self, mock_savefig, output_dir, sample_coverage_correlation
    ):
        """Test plotting coverage correlation heatmap with Matplotlib."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_coverage_heatmap(sample_coverage_correlation, output_format="png")

        assert chart_path.suffix == ".png"
        assert "coverage_heatmap" in str(chart_path)
        assert mock_savefig.called
        plt.close("all")

    @patch("plotly.graph_objects.Figure.write_html")
    def test_plot_coverage_heatmap_plotly(
        self, mock_write_html, output_dir, sample_coverage_correlation
    ):
        """Test plotting coverage heatmap with Plotly."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_coverage_heatmap(sample_coverage_correlation, output_format="html")

        assert chart_path.suffix == ".html"
        assert "coverage_heatmap" in str(chart_path)
        assert mock_write_html.called

    @patch("matplotlib.pyplot.savefig")
    def test_plot_coverage_heatmap_single_strategy(self, mock_savefig, output_dir):
        """Test coverage heatmap with single strategy."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        single_correlation = {
            "metadata_fuzzer": CoverageCorrelation(
                strategy="metadata_fuzzer",
                coverage_increase=50.0,
                unique_paths=75,
                crash_correlation=0.80,
                sample_size=100,
            )
        }

        chart_path = viz.plot_coverage_heatmap(single_correlation, output_format="png")
        assert chart_path is not None
        plt.close("all")


class TestPerformanceDashboardPlots:
    """Test performance dashboard plotting methods."""

    @patch("matplotlib.pyplot.savefig")
    def test_plot_performance_dashboard_matplotlib(
        self, mock_savefig, output_dir, sample_performance_metrics
    ):
        """Test plotting performance metrics dashboard with Matplotlib."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_performance_dashboard(
            sample_performance_metrics, output_format="png"
        )

        assert chart_path.suffix == ".png"
        assert "performance_dashboard" in str(chart_path)
        assert mock_savefig.called
        plt.close("all")

    @patch("plotly.graph_objects.Figure.write_html")
    def test_plot_performance_dashboard_plotly(
        self, mock_write_html, output_dir, sample_performance_metrics
    ):
        """Test plotting performance dashboard with Plotly."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart_path = viz.plot_performance_dashboard(
            sample_performance_metrics, output_format="html"
        )

        assert chart_path.suffix == ".html"
        assert "performance_dashboard" in str(chart_path)
        assert mock_write_html.called

    @patch("matplotlib.pyplot.savefig")
    def test_plot_performance_high_throughput(self, mock_savefig, output_dir):
        """Test performance dashboard with high throughput metrics."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        high_perf = PerformanceMetrics(
            mutations_per_second=250.0,
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=95.0,
            disk_io_mb_per_sec=50.0,
            cache_hit_rate=98.0,
        )

        chart_path = viz.plot_performance_dashboard(high_perf, output_format="png")
        assert chart_path is not None
        plt.close("all")

    @patch("matplotlib.pyplot.savefig")
    def test_plot_performance_low_throughput(self, mock_savefig, output_dir):
        """Test performance dashboard with low throughput metrics."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        low_perf = PerformanceMetrics(
            mutations_per_second=10.0,
            peak_memory_mb=128.0,
            avg_memory_mb=64.0,
            cpu_utilization=25.0,
            disk_io_mb_per_sec=1.0,
            cache_hit_rate=40.0,
        )

        chart_path = viz.plot_performance_dashboard(low_perf, output_format="png")
        assert chart_path is not None
        plt.close("all")


class TestHTMLReportGeneration:
    """Test HTML report generation methods."""

    def test_create_summary_report_html(self, output_dir, tmp_path):
        """Test creating HTML snippet embedding all charts."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        # Create dummy chart paths
        strategy_chart = tmp_path / "strategy.png"
        trend_chart = tmp_path / "trend.png"
        coverage_chart = tmp_path / "coverage.png"
        performance_chart = tmp_path / "performance.png"

        html = viz.create_summary_report_html(
            strategy_chart, trend_chart, coverage_chart, performance_chart
        )

        assert "<html" in html or "<div" in html
        assert "strategy.png" in html
        assert "trend.png" in html
        assert "coverage.png" in html
        assert "performance.png" in html
        assert "<style>" in html or "style=" in html

    def test_html_contains_chart_sections(self, output_dir, tmp_path):
        """Test that HTML contains proper chart sections."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart1 = tmp_path / "chart1.png"
        chart2 = tmp_path / "chart2.png"
        chart3 = tmp_path / "chart3.png"
        chart4 = tmp_path / "chart4.png"

        html = viz.create_summary_report_html(chart1, chart2, chart3, chart4)

        assert "Strategy Effectiveness" in html
        assert "Crash Discovery Trend" in html
        assert "Coverage Correlation" in html
        assert "Performance Metrics" in html

    def test_html_responsive_styling(self, output_dir, tmp_path):
        """Test that HTML includes responsive styling."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        chart = tmp_path / "chart.png"
        html = viz.create_summary_report_html(chart, chart, chart, chart)

        # Should include responsive CSS
        assert "max-width: 100%" in html or "max-width:100%" in html


class TestIntegrationScenarios:
    """Test integration scenarios for visualization module."""

    @patch("matplotlib.pyplot.savefig")
    @patch("plotly.graph_objects.Figure.write_html")
    def test_complete_visualization_workflow(
        self,
        mock_plotly,
        mock_matplotlib,
        output_dir,
        sample_effectiveness_data,
        sample_coverage_correlation,
        sample_performance_metrics,
        sample_trend_analysis,
    ):
        """Test complete visualization workflow from data to charts."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        # Generate all chart types
        strategy_png = viz.plot_strategy_effectiveness(
            sample_effectiveness_data, output_format="png"
        )
        strategy_html = viz.plot_strategy_effectiveness(
            sample_effectiveness_data, output_format="html"
        )

        trend_png = viz.plot_crash_trend(sample_trend_analysis, output_format="png")
        trend_html = viz.plot_crash_trend(sample_trend_analysis, output_format="html")

        heatmap_png = viz.plot_coverage_heatmap(
            sample_coverage_correlation, output_format="png"
        )
        heatmap_html = viz.plot_coverage_heatmap(
            sample_coverage_correlation, output_format="html"
        )

        perf_png = viz.plot_performance_dashboard(
            sample_performance_metrics, output_format="png"
        )
        perf_html = viz.plot_performance_dashboard(
            sample_performance_metrics, output_format="html"
        )

        # Verify all charts created
        assert all(
            [
                strategy_png.suffix == ".png",
                strategy_html.suffix == ".html",
                trend_png.suffix == ".png",
                trend_html.suffix == ".html",
                heatmap_png.suffix == ".png",
                heatmap_html.suffix == ".html",
                perf_png.suffix == ".png",
                perf_html.suffix == ".html",
            ]
        )

        plt.close("all")

    @patch("matplotlib.pyplot.savefig")
    def test_large_dataset_handling(self, mock_savefig, output_dir):
        """Test handling of large datasets in visualization."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        # Create large dataset
        large_strategy_data = {
            f"fuzzer_{i}": {
                "effectiveness_score": i / 100.0,
                "usage_count": i * 10,
            }
            for i in range(100)
        }

        # Should handle large dataset without crashing
        chart_path = viz.plot_strategy_effectiveness(
            large_strategy_data, output_format="png"
        )
        assert chart_path is not None
        plt.close("all")

    @patch("matplotlib.pyplot.savefig")
    def test_edge_case_zero_values(self, mock_savefig, output_dir):
        """Test handling of zero values in metrics."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        zero_perf = PerformanceMetrics(
            mutations_per_second=0.0,
            peak_memory_mb=0.0,
            avg_memory_mb=0.0,
            cpu_utilization=0.0,
            disk_io_mb_per_sec=0.0,
            cache_hit_rate=0.0,
        )

        chart_path = viz.plot_performance_dashboard(zero_perf, output_format="png")
        assert chart_path is not None
        plt.close("all")

    @patch("matplotlib.pyplot.savefig")
    def test_special_characters_in_strategy_names(self, mock_savefig, output_dir):
        """Test handling of special characters in strategy names."""
        viz = FuzzingVisualizer(output_dir=output_dir)

        special_data = {
            "fuzzer-with-dash": {"effectiveness_score": 0.5, "usage_count": 10},
            "fuzzer_with_underscore": {"effectiveness_score": 0.6, "usage_count": 20},
            "fuzzer.with.dot": {"effectiveness_score": 0.7, "usage_count": 30},
        }

        chart_path = viz.plot_strategy_effectiveness(special_data, output_format="png")
        assert chart_path is not None
        plt.close("all")
