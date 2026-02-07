"""Tests for dicom_fuzzer.analytics.visualization module."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Skip the entire module if plotly is not available
pytest.importorskip("plotly", reason="plotly not installed")

from dicom_fuzzer.core.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.core.analytics.visualization import FuzzingVisualizer


def create_trend_analysis():
    """Create a TrendAnalysis instance for testing."""
    return TrendAnalysis(
        campaign_name="test_campaign",
        start_time=datetime(2024, 1, 1, 10, 0),
        end_time=datetime(2024, 1, 1, 12, 0),
        total_duration=timedelta(hours=2),
    )


def create_coverage_correlation(
    strategy: str = "test_strategy",
    coverage_increase: float = 50.0,
    unique_paths: int = 80,
    crash_correlation: float = 0.7,
    sample_size: int = 100,
):
    """Create a CoverageCorrelation instance for testing."""
    return CoverageCorrelation(
        strategy=strategy,
        coverage_increase=coverage_increase,
        unique_paths=unique_paths,
        crash_correlation=crash_correlation,
        sample_size=sample_size,
    )


def create_performance_metrics(
    mutations_per_second: float = 100.0,
    peak_memory_mb: float = 512.0,
    avg_memory_mb: float = 256.0,
    cpu_utilization: float = 75.0,
    disk_io_mb_per_sec: float = 50.0,
    cache_hit_rate: float = 85.0,
):
    """Create a PerformanceMetrics instance for testing."""
    return PerformanceMetrics(
        mutations_per_second=mutations_per_second,
        peak_memory_mb=peak_memory_mb,
        avg_memory_mb=avg_memory_mb,
        cpu_utilization=cpu_utilization,
        disk_io_mb_per_sec=disk_io_mb_per_sec,
        cache_hit_rate=cache_hit_rate,
    )


class TestFuzzingVisualizerInit:
    """Tests for FuzzingVisualizer initialization."""

    def test_init_creates_output_dir(self, tmp_path):
        """Test that init creates output directory."""
        output_dir = tmp_path / "charts"
        assert not output_dir.exists()

        visualizer = FuzzingVisualizer(str(output_dir))

        assert output_dir.exists()
        assert visualizer.output_dir == output_dir

    def test_init_uses_default_colors(self, tmp_path):
        """Test that default colors are set."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))

        assert "primary" in visualizer.colors
        assert "secondary" in visualizer.colors
        assert "success" in visualizer.colors
        assert "warning" in visualizer.colors
        assert "danger" in visualizer.colors
        assert "info" in visualizer.colors

    def test_init_existing_directory(self, tmp_path):
        """Test init with existing directory."""
        output_dir = tmp_path / "existing"
        output_dir.mkdir()

        visualizer = FuzzingVisualizer(str(output_dir))

        assert visualizer.output_dir == output_dir

    def test_init_nested_directory(self, tmp_path):
        """Test init creates nested directories."""
        output_dir = tmp_path / "level1" / "level2" / "charts"

        visualizer = FuzzingVisualizer(str(output_dir))

        assert output_dir.exists()


class TestPlotStrategyEffectiveness:
    """Tests for strategy effectiveness charts."""

    def test_plot_strategy_effectiveness_png(self, tmp_path):
        """Test PNG strategy effectiveness chart."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        effectiveness_data = {
            "strategy_a": {"effectiveness_score": 0.8, "usage_count": 100},
            "strategy_b": {"effectiveness_score": 0.6, "usage_count": 50},
            "strategy_c": {"effectiveness_score": 0.4, "usage_count": 25},
        }

        output_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )

        assert output_path.exists()
        assert output_path.suffix == ".png"

    def test_plot_strategy_effectiveness_svg(self, tmp_path):
        """Test SVG strategy effectiveness chart."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        effectiveness_data = {
            "strategy_a": {"effectiveness_score": 0.5},
        }

        output_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="svg"
        )

        assert output_path.exists()
        assert output_path.suffix == ".svg"

    def test_plot_strategy_effectiveness_html(self, tmp_path):
        """Test HTML strategy effectiveness chart (Plotly)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        effectiveness_data = {
            "strategy_a": {"effectiveness_score": 0.8, "usage_count": 100},
            "strategy_b": {"effectiveness_score": 0.6, "usage_count": 50},
        }

        output_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="html"
        )

        assert output_path.exists()
        assert output_path.suffix == ".html"

        # Check HTML content
        content = output_path.read_text(encoding="utf-8")
        assert "plotly" in content.lower() or "<div" in content

    def test_plot_strategy_effectiveness_empty_data(self, tmp_path):
        """Test with empty effectiveness data."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        effectiveness_data = {}

        output_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )

        assert output_path.exists()

    def test_plot_strategy_effectiveness_missing_score(self, tmp_path):
        """Test with missing effectiveness score (uses default 0)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        effectiveness_data = {
            "strategy_a": {},  # No effectiveness_score
            "strategy_b": {"effectiveness_score": 0.5},
        }

        output_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )

        assert output_path.exists()


class TestPlotCrashTrend:
    """Tests for crash trend charts."""

    def test_plot_crash_trend_png(self, tmp_path):
        """Test PNG crash trend chart."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = [
            (datetime(2024, 1, 1, 10, 0), 1),
            (datetime(2024, 1, 1, 11, 0), 2),
            (datetime(2024, 1, 1, 12, 0), 3),
        ]

        output_path = visualizer.plot_crash_trend(trend_data, output_format="png")

        assert output_path.exists()
        assert output_path.suffix == ".png"

    def test_plot_crash_trend_svg(self, tmp_path):
        """Test SVG crash trend chart."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = [
            (datetime(2024, 1, 1, 10, 0), 5),
        ]

        output_path = visualizer.plot_crash_trend(trend_data, output_format="svg")

        assert output_path.exists()
        assert output_path.suffix == ".svg"

    def test_plot_crash_trend_html(self, tmp_path):
        """Test HTML crash trend chart (Plotly)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = [
            (datetime(2024, 1, 1, 10, 0), 1),
            (datetime(2024, 1, 1, 11, 0), 2),
        ]

        output_path = visualizer.plot_crash_trend(trend_data, output_format="html")

        assert output_path.exists()
        assert output_path.suffix == ".html"

    def test_plot_crash_trend_empty_data_png(self, tmp_path):
        """Test crash trend chart with no data (PNG)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = []

        output_path = visualizer.plot_crash_trend(trend_data, output_format="png")

        assert output_path.exists()

    def test_plot_crash_trend_empty_data_html(self, tmp_path):
        """Test crash trend chart with no data (HTML)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = []

        output_path = visualizer.plot_crash_trend(trend_data, output_format="html")

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "No crash data available" in content


class TestPlotCoverageHeatmap:
    """Tests for coverage heatmap charts."""

    def test_plot_coverage_heatmap_png(self, tmp_path):
        """Test PNG coverage heatmap."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        coverage_data = {
            "strategy_a": create_coverage_correlation(
                strategy="strategy_a",
                coverage_increase=50.0,
                unique_paths=80,
                crash_correlation=0.7,
            ),
            "strategy_b": create_coverage_correlation(
                strategy="strategy_b",
                coverage_increase=30.0,
                unique_paths=50,
                crash_correlation=0.5,
            ),
        }

        output_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="png"
        )

        assert output_path.exists()
        assert output_path.suffix == ".png"

    def test_plot_coverage_heatmap_svg(self, tmp_path):
        """Test SVG coverage heatmap."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        coverage_data = {
            "strategy_a": create_coverage_correlation(
                strategy="strategy_a",
                coverage_increase=25.0,
                unique_paths=40,
                crash_correlation=0.3,
            ),
        }

        output_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="svg"
        )

        assert output_path.exists()
        assert output_path.suffix == ".svg"

    def test_plot_coverage_heatmap_html(self, tmp_path):
        """Test HTML coverage heatmap (Plotly)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        coverage_data = {
            "strategy_a": create_coverage_correlation(
                strategy="strategy_a",
                coverage_increase=50.0,
                unique_paths=80,
                crash_correlation=0.7,
            ),
            "strategy_b": create_coverage_correlation(
                strategy="strategy_b",
                coverage_increase=30.0,
                unique_paths=50,
                crash_correlation=0.5,
            ),
        }

        output_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="html"
        )

        assert output_path.exists()
        assert output_path.suffix == ".html"

    def test_plot_coverage_heatmap_normalizes_values(self, tmp_path):
        """Test that large values are normalized correctly."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        coverage_data = {
            "strategy_a": create_coverage_correlation(
                strategy="strategy_a",
                coverage_increase=200.0,  # > 100
                unique_paths=500,  # Will be normalized
                crash_correlation=0.9,
            ),
        }

        # Should not raise
        output_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="png"
        )

        assert output_path.exists()


class TestPlotPerformanceDashboard:
    """Tests for performance dashboard charts."""

    def test_plot_performance_dashboard_png(self, tmp_path):
        """Test PNG performance dashboard."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=100.0,
            peak_memory_mb=512.0,
            avg_memory_mb=256.0,
            cpu_utilization=75.0,
            cache_hit_rate=85.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="png"
        )

        assert output_path.exists()
        assert output_path.suffix == ".png"

    def test_plot_performance_dashboard_svg(self, tmp_path):
        """Test SVG performance dashboard."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=50.0,
            peak_memory_mb=256.0,
            avg_memory_mb=128.0,
            cpu_utilization=50.0,
            cache_hit_rate=60.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="svg"
        )

        assert output_path.exists()
        assert output_path.suffix == ".svg"

    def test_plot_performance_dashboard_html(self, tmp_path):
        """Test HTML performance dashboard (Plotly)."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=100.0,
            peak_memory_mb=512.0,
            avg_memory_mb=256.0,
            cpu_utilization=75.0,
            cache_hit_rate=85.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="html"
        )

        assert output_path.exists()
        assert output_path.suffix == ".html"

    def test_plot_performance_dashboard_high_throughput(self, tmp_path):
        """Test dashboard with high throughput score."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=500.0,
            peak_memory_mb=256.0,
            avg_memory_mb=128.0,
            cpu_utilization=90.0,
            cache_hit_rate=95.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="png"
        )

        assert output_path.exists()

    def test_plot_performance_dashboard_low_throughput(self, tmp_path):
        """Test dashboard with low throughput score."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=10.0,
            peak_memory_mb=1024.0,
            avg_memory_mb=800.0,
            cpu_utilization=30.0,
            cache_hit_rate=20.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="png"
        )

        assert output_path.exists()


class TestCreateSummaryReportHtml:
    """Tests for summary report HTML generation."""

    def test_create_summary_report_html(self, tmp_path):
        """Test creating summary report HTML."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))

        # Create mock paths
        strategy_chart = tmp_path / "strategy.png"
        trend_chart = tmp_path / "trend.png"
        coverage_chart = tmp_path / "coverage.png"
        performance_chart = tmp_path / "performance.png"

        html = visualizer.create_summary_report_html(
            strategy_chart_path=strategy_chart,
            trend_chart_path=trend_chart,
            coverage_chart_path=coverage_chart,
            performance_chart_path=performance_chart,
        )

        assert "charts-container" in html
        assert "strategy.png" in html
        assert "trend.png" in html
        assert "coverage.png" in html
        assert "performance.png" in html

    def test_create_summary_report_html_contains_styling(self, tmp_path):
        """Test that HTML contains CSS styling."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))

        html = visualizer.create_summary_report_html(
            strategy_chart_path=Path("a.png"),
            trend_chart_path=Path("b.png"),
            coverage_chart_path=Path("c.png"),
            performance_chart_path=Path("d.png"),
        )

        assert "<style>" in html
        assert ".chart-section" in html

    def test_create_summary_report_html_contains_sections(self, tmp_path):
        """Test that HTML contains all chart sections."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))

        html = visualizer.create_summary_report_html(
            strategy_chart_path=Path("strategy.png"),
            trend_chart_path=Path("trend.png"),
            coverage_chart_path=Path("coverage.png"),
            performance_chart_path=Path("performance.png"),
        )

        assert "Strategy Effectiveness" in html
        assert "Crash Discovery Trend" in html
        assert "Coverage Correlation" in html
        assert "Performance Metrics" in html


class TestVisualizationIntegration:
    """Integration tests for the visualization module."""

    def test_full_visualization_workflow(self, tmp_path):
        """Test creating all chart types in sequence."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))

        # Create strategy effectiveness chart
        effectiveness_data = {
            "mutation_a": {"effectiveness_score": 0.75, "usage_count": 50},
            "mutation_b": {"effectiveness_score": 0.60, "usage_count": 30},
        }
        strategy_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )

        # Create crash trend chart
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = [
            (datetime(2024, 1, 1, 10, 0), 1),
            (datetime(2024, 1, 1, 11, 0), 2),
        ]
        trend_path = visualizer.plot_crash_trend(trend_data, output_format="png")

        # Create coverage heatmap
        coverage_data = {
            "strategy_a": create_coverage_correlation(
                strategy="strategy_a",
                coverage_increase=40.0,
                unique_paths=60,
                crash_correlation=0.6,
            ),
        }
        coverage_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="png"
        )

        # Create performance dashboard
        performance_data = create_performance_metrics(
            mutations_per_second=80.0,
            peak_memory_mb=400.0,
            avg_memory_mb=200.0,
            cpu_utilization=65.0,
            cache_hit_rate=75.0,
        )
        performance_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="png"
        )

        # Create summary HTML
        summary_html = visualizer.create_summary_report_html(
            strategy_chart_path=strategy_path,
            trend_chart_path=trend_path,
            coverage_chart_path=coverage_path,
            performance_chart_path=performance_path,
        )

        # Verify all outputs
        assert strategy_path.exists()
        assert trend_path.exists()
        assert coverage_path.exists()
        assert performance_path.exists()
        assert strategy_path.name in summary_html
        assert trend_path.name in summary_html
        assert coverage_path.name in summary_html
        assert performance_path.name in summary_html

    def test_all_html_outputs(self, tmp_path):
        """Test generating all charts in HTML format."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))

        # Strategy effectiveness
        effectiveness_data = {"strategy_a": {"effectiveness_score": 0.5}}
        strategy_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="html"
        )

        # Crash trend
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = [(datetime(2024, 1, 1), 1)]
        trend_path = visualizer.plot_crash_trend(trend_data, output_format="html")

        # Coverage heatmap
        coverage_data = {
            "strategy_a": create_coverage_correlation(
                strategy="strategy_a",
                coverage_increase=30.0,
                unique_paths=40,
                crash_correlation=0.5,
            )
        }
        coverage_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="html"
        )

        # Performance dashboard
        performance_data = create_performance_metrics(
            mutations_per_second=50.0,
            peak_memory_mb=200.0,
            avg_memory_mb=100.0,
            cpu_utilization=50.0,
            cache_hit_rate=60.0,
        )
        performance_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="html"
        )

        # Verify all HTML files exist
        assert strategy_path.suffix == ".html"
        assert trend_path.suffix == ".html"
        assert coverage_path.suffix == ".html"
        assert performance_path.suffix == ".html"


class TestEdgeCases:
    """Edge case tests for visualization module."""

    def test_single_strategy_heatmap(self, tmp_path):
        """Test heatmap with single strategy."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        coverage_data = {
            "only_strategy": create_coverage_correlation(
                strategy="only_strategy",
                coverage_increase=50.0,
                unique_paths=50,
                crash_correlation=0.5,
            ),
        }

        output_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="png"
        )

        assert output_path.exists()

    def test_many_strategies_chart(self, tmp_path):
        """Test chart with many strategies."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        effectiveness_data = {
            f"strategy_{i}": {"effectiveness_score": i / 20.0, "usage_count": i * 10}
            for i in range(20)
        }

        output_path = visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )

        assert output_path.exists()

    def test_extreme_performance_values(self, tmp_path):
        """Test performance dashboard with extreme values."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=10000.0,
            peak_memory_mb=10000.0,
            avg_memory_mb=5000.0,
            cpu_utilization=100.0,
            cache_hit_rate=100.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="png"
        )

        assert output_path.exists()

    def test_zero_performance_values(self, tmp_path):
        """Test performance dashboard with zero values."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        performance_data = create_performance_metrics(
            mutations_per_second=0.0,
            peak_memory_mb=0.0,
            avg_memory_mb=0.0,
            cpu_utilization=0.0,
            cache_hit_rate=0.0,
        )

        output_path = visualizer.plot_performance_dashboard(
            performance_data, output_format="png"
        )

        assert output_path.exists()

    def test_long_trend_data(self, tmp_path):
        """Test crash trend with many data points."""
        visualizer = FuzzingVisualizer(str(tmp_path / "charts"))
        trend_data = create_trend_analysis()
        trend_data.crashes_over_time = [
            (datetime(2024, 1, 1, i % 24, 0), 1) for i in range(100)
        ]

        output_path = visualizer.plot_crash_trend(trend_data, output_format="png")

        assert output_path.exists()
