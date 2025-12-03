"""Tests for visualization module that actually execute the plotting code.

These tests don't mock savefig/write_html to ensure full code coverage.
"""

from datetime import datetime, timedelta

import pytest

# Skip all tests in this module if dependencies are not installed
pytest.importorskip("matplotlib")
pytest.importorskip("plotly")
pytest.importorskip("seaborn")

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

from dicom_fuzzer.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.analytics.visualization import FuzzingVisualizer


@pytest.fixture
def visualizer(tmp_path):
    """Create visualizer with temp output directory."""
    return FuzzingVisualizer(output_dir=str(tmp_path / "charts"))


@pytest.fixture
def effectiveness_data():
    """Sample effectiveness data."""
    return {
        "metadata": {"effectiveness_score": 0.85, "usage_count": 100},
        "header": {"effectiveness_score": 0.72, "usage_count": 80},
        "pixel": {"effectiveness_score": 0.65, "usage_count": 60},
    }


@pytest.fixture
def trend_data():
    """Sample trend analysis data."""
    now = datetime.now()
    return TrendAnalysis(
        campaign_name="Test",
        start_time=now - timedelta(hours=5),
        end_time=now,
        total_duration=timedelta(hours=5),
        crashes_over_time=[(now - timedelta(hours=i), i * 2) for i in range(5, 0, -1)],
        coverage_over_time=[
            (now - timedelta(hours=i), 40 + i * 5) for i in range(5, 0, -1)
        ],
        mutations_over_time=[
            (now - timedelta(hours=i), i * 100) for i in range(5, 0, -1)
        ],
    )


@pytest.fixture
def coverage_correlation():
    """Sample coverage correlation data."""
    return {
        "metadata": CoverageCorrelation(
            strategy="metadata",
            coverage_increase=35.0,
            unique_paths=70,
            crash_correlation=0.75,
            sample_size=100,
        ),
        "header": CoverageCorrelation(
            strategy="header",
            coverage_increase=25.0,
            unique_paths=50,
            crash_correlation=0.65,
            sample_size=80,
        ),
    }


@pytest.fixture
def performance_metrics():
    """Sample performance metrics."""
    return PerformanceMetrics(
        mutations_per_second=120.0,
        peak_memory_mb=512.0,
        avg_memory_mb=256.0,
        cpu_utilization=70.0,
        disk_io_mb_per_sec=15.0,
        cache_hit_rate=80.0,
    )


class TestStrategyEffectivenessActual:
    """Test strategy effectiveness plots without mocking."""

    def test_matplotlib_png_creates_file(self, visualizer, effectiveness_data):
        """Test that matplotlib PNG chart is actually created."""
        path = visualizer.plot_strategy_effectiveness(effectiveness_data, "png")

        assert path.exists()
        assert path.suffix == ".png"
        assert path.stat().st_size > 0
        plt.close("all")

    def test_matplotlib_svg_creates_file(self, visualizer, effectiveness_data):
        """Test that matplotlib SVG chart is actually created."""
        path = visualizer.plot_strategy_effectiveness(effectiveness_data, "svg")

        assert path.exists()
        assert path.suffix == ".svg"
        assert path.stat().st_size > 0
        plt.close("all")

    def test_plotly_html_creates_file(self, visualizer, effectiveness_data):
        """Test that plotly HTML chart is actually created."""
        path = visualizer.plot_strategy_effectiveness(effectiveness_data, "html")

        assert path.exists()
        assert path.suffix == ".html"
        assert path.stat().st_size > 0
        # Verify it's valid HTML (use UTF-8 for Plotly HTML files)
        content = path.read_text(encoding="utf-8")
        assert "<html" in content.lower() or "<div" in content.lower()

    def test_empty_data_matplotlib(self, visualizer):
        """Test empty data produces valid chart."""
        path = visualizer.plot_strategy_effectiveness({}, "png")

        assert path.exists()
        assert path.stat().st_size > 0
        plt.close("all")

    def test_empty_data_plotly(self, visualizer):
        """Test empty data produces valid HTML."""
        path = visualizer.plot_strategy_effectiveness({}, "html")

        assert path.exists()
        assert path.stat().st_size > 0


class TestCrashTrendActual:
    """Test crash trend plots without mocking."""

    def test_matplotlib_png_creates_file(self, visualizer, trend_data):
        """Test that crash trend PNG is created."""
        path = visualizer.plot_crash_trend(trend_data, "png")

        assert path.exists()
        assert path.suffix == ".png"
        assert path.stat().st_size > 0
        plt.close("all")

    def test_plotly_html_creates_file(self, visualizer, trend_data):
        """Test that crash trend HTML is created."""
        path = visualizer.plot_crash_trend(trend_data, "html")

        assert path.exists()
        assert path.suffix == ".html"
        assert path.stat().st_size > 0

    def test_empty_crashes_matplotlib(self, visualizer):
        """Test empty crash data produces valid chart."""
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

        path = visualizer.plot_crash_trend(empty_trend, "png")
        assert path.exists()
        assert path.stat().st_size > 0
        plt.close("all")

    def test_empty_crashes_plotly(self, visualizer):
        """Test empty crash data produces valid HTML."""
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

        path = visualizer.plot_crash_trend(empty_trend, "html")
        assert path.exists()
        assert path.stat().st_size > 0


class TestCoverageHeatmapActual:
    """Test coverage heatmap plots without mocking."""

    def test_matplotlib_png_creates_file(self, visualizer, coverage_correlation):
        """Test that heatmap PNG is created."""
        path = visualizer.plot_coverage_heatmap(coverage_correlation, "png")

        assert path.exists()
        assert path.suffix == ".png"
        assert path.stat().st_size > 0
        plt.close("all")

    def test_plotly_html_creates_file(self, visualizer, coverage_correlation):
        """Test that heatmap HTML is created."""
        path = visualizer.plot_coverage_heatmap(coverage_correlation, "html")

        assert path.exists()
        assert path.suffix == ".html"
        assert path.stat().st_size > 0

    def test_single_strategy(self, visualizer):
        """Test heatmap with single strategy."""
        single = {
            "only_one": CoverageCorrelation(
                strategy="only_one",
                coverage_increase=50.0,
                unique_paths=80,
                crash_correlation=0.9,
                sample_size=50,
            )
        }

        path = visualizer.plot_coverage_heatmap(single, "png")
        assert path.exists()
        plt.close("all")


class TestPerformanceDashboardActual:
    """Test performance dashboard plots without mocking."""

    def test_matplotlib_png_creates_file(self, visualizer, performance_metrics):
        """Test that dashboard PNG is created."""
        path = visualizer.plot_performance_dashboard(performance_metrics, "png")

        assert path.exists()
        assert path.suffix == ".png"
        assert path.stat().st_size > 0
        plt.close("all")

    def test_plotly_html_creates_file(self, visualizer, performance_metrics):
        """Test that dashboard HTML is created."""
        path = visualizer.plot_performance_dashboard(performance_metrics, "html")

        assert path.exists()
        assert path.suffix == ".html"
        assert path.stat().st_size > 0

    def test_zero_metrics(self, visualizer):
        """Test dashboard with zero values."""
        zero_metrics = PerformanceMetrics(
            mutations_per_second=0.0,
            peak_memory_mb=0.0,
            avg_memory_mb=0.0,
            cpu_utilization=0.0,
            disk_io_mb_per_sec=0.0,
            cache_hit_rate=0.0,
        )

        path = visualizer.plot_performance_dashboard(zero_metrics, "png")
        assert path.exists()
        plt.close("all")

    def test_high_metrics(self, visualizer):
        """Test dashboard with high values."""
        high_metrics = PerformanceMetrics(
            mutations_per_second=1000.0,
            peak_memory_mb=8192.0,
            avg_memory_mb=4096.0,
            cpu_utilization=100.0,
            disk_io_mb_per_sec=500.0,
            cache_hit_rate=99.9,
        )

        path = visualizer.plot_performance_dashboard(high_metrics, "png")
        assert path.exists()
        plt.close("all")


class TestHTMLReportActual:
    """Test HTML report generation."""

    def test_summary_report_html_structure(self, visualizer, tmp_path):
        """Test HTML report contains proper structure."""
        # Create dummy chart files
        chart1 = tmp_path / "strategy.png"
        chart2 = tmp_path / "trend.png"
        chart3 = tmp_path / "coverage.png"
        chart4 = tmp_path / "performance.png"

        for chart in [chart1, chart2, chart3, chart4]:
            chart.write_bytes(b"fake image data")

        html = visualizer.create_summary_report_html(chart1, chart2, chart3, chart4)

        # Verify HTML structure
        assert "Strategy Effectiveness" in html
        assert "Crash Discovery Trend" in html
        assert "Coverage Correlation" in html
        assert "Performance Metrics" in html
        assert "strategy.png" in html
        assert "<img" in html

    def test_html_has_responsive_styling(self, visualizer, tmp_path):
        """Test HTML includes responsive CSS."""
        chart = tmp_path / "chart.png"
        chart.write_bytes(b"fake")

        html = visualizer.create_summary_report_html(chart, chart, chart, chart)

        # Check for responsive styling
        assert "max-width" in html


class TestCompleteWorkflow:
    """Test complete visualization workflow."""

    def test_all_charts_generated(
        self,
        visualizer,
        effectiveness_data,
        trend_data,
        coverage_correlation,
        performance_metrics,
    ):
        """Test generating all chart types in sequence."""
        charts = []

        # Generate all charts
        charts.append(visualizer.plot_strategy_effectiveness(effectiveness_data, "png"))
        charts.append(
            visualizer.plot_strategy_effectiveness(effectiveness_data, "html")
        )
        charts.append(visualizer.plot_crash_trend(trend_data, "png"))
        charts.append(visualizer.plot_crash_trend(trend_data, "html"))
        charts.append(visualizer.plot_coverage_heatmap(coverage_correlation, "png"))
        charts.append(visualizer.plot_coverage_heatmap(coverage_correlation, "html"))
        charts.append(visualizer.plot_performance_dashboard(performance_metrics, "png"))
        charts.append(
            visualizer.plot_performance_dashboard(performance_metrics, "html")
        )

        # Verify all charts exist
        for chart in charts:
            assert chart.exists()
            assert chart.stat().st_size > 0

        plt.close("all")

    def test_full_html_report_with_real_charts(
        self,
        visualizer,
        effectiveness_data,
        trend_data,
        coverage_correlation,
        performance_metrics,
    ):
        """Test creating full HTML report with actual generated charts."""
        # Generate real charts
        strategy_chart = visualizer.plot_strategy_effectiveness(
            effectiveness_data, "png"
        )
        trend_chart = visualizer.plot_crash_trend(trend_data, "png")
        coverage_chart = visualizer.plot_coverage_heatmap(coverage_correlation, "png")
        perf_chart = visualizer.plot_performance_dashboard(performance_metrics, "png")

        # Create summary HTML
        html = visualizer.create_summary_report_html(
            strategy_chart, trend_chart, coverage_chart, perf_chart
        )

        # Verify HTML references the actual chart files
        assert strategy_chart.name in html
        assert trend_chart.name in html
        assert coverage_chart.name in html
        assert perf_chart.name in html

        plt.close("all")
