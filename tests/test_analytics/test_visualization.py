"""Tests for analytics/visualization.py - Fuzzing Visualization Module.

Tests cover chart generation with Matplotlib and Plotly, output formats,
and HTML summary report generation.
"""

from datetime import datetime
from pathlib import Path

from dicom_fuzzer.analytics.visualization import FuzzingVisualizer


class MockCoverageCorrelation:
    """Mock CoverageCorrelation for testing."""

    def __init__(
        self,
        coverage_increase: float = 25.0,
        unique_paths: int = 50,
        crash_correlation: float = 0.75,
    ):
        self.coverage_increase = coverage_increase
        self.unique_paths = unique_paths
        self.crash_correlation = crash_correlation

    def correlation_score(self) -> float:
        """Calculate mock correlation score."""
        return (
            self.coverage_increase / 100.0 * 0.3
            + min(self.unique_paths / 100.0, 1.0) * 0.3
            + self.crash_correlation * 0.4
        )


class MockTrendAnalysis:
    """Mock TrendAnalysis for testing."""

    def __init__(self, crashes_over_time: list = None):
        self.crashes_over_time = crashes_over_time or []


class MockPerformanceMetrics:
    """Mock PerformanceMetrics for testing."""

    def __init__(
        self,
        mutations_per_second: float = 1500.0,
        peak_memory_mb: float = 512.0,
        avg_memory_mb: float = 256.0,
        cpu_utilization: float = 75.0,
        cache_hit_rate: float = 85.0,
    ):
        self.mutations_per_second = mutations_per_second
        self.peak_memory_mb = peak_memory_mb
        self.avg_memory_mb = avg_memory_mb
        self.cpu_utilization = cpu_utilization
        self.cache_hit_rate = cache_hit_rate

    def throughput_score(self) -> float:
        """Calculate mock throughput score."""
        return min(self.mutations_per_second / 2000.0, 1.0)


class TestFuzzingVisualizerInit:
    """Test FuzzingVisualizer initialization."""

    def test_init_creates_output_dir(self, tmp_path):
        """Test that initialization creates output directory."""
        output_dir = tmp_path / "charts"
        visualizer = FuzzingVisualizer(str(output_dir))

        assert output_dir.exists()
        assert visualizer.output_dir == output_dir

    def test_init_with_existing_dir(self, tmp_path):
        """Test initialization with existing directory."""
        output_dir = tmp_path / "charts"
        output_dir.mkdir()

        visualizer = FuzzingVisualizer(str(output_dir))
        assert visualizer.output_dir == output_dir

    def test_default_colors(self, tmp_path):
        """Test default color scheme is set."""
        visualizer = FuzzingVisualizer(str(tmp_path))

        assert "primary" in visualizer.colors
        assert "success" in visualizer.colors
        assert "danger" in visualizer.colors
        assert visualizer.colors["primary"] == "#667eea"


class TestPlotStrategyEffectiveness:
    """Test plot_strategy_effectiveness method."""

    def test_plot_png_format(self, tmp_path):
        """Test generating PNG format chart."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        data = {
            "bit_flip": {"effectiveness_score": 0.75, "usage_count": 100},
            "byte_swap": {"effectiveness_score": 0.60, "usage_count": 80},
            "random": {"effectiveness_score": 0.45, "usage_count": 150},
        }

        path = visualizer.plot_strategy_effectiveness(data, output_format="png")

        assert path.exists()
        assert path.suffix == ".png"
        assert "strategy_effectiveness" in path.name

    def test_plot_svg_format(self, tmp_path):
        """Test generating SVG format chart."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        data = {
            "mutation_a": {"effectiveness_score": 0.8},
            "mutation_b": {"effectiveness_score": 0.5},
        }

        path = visualizer.plot_strategy_effectiveness(data, output_format="svg")

        assert path.exists()
        assert path.suffix == ".svg"

    def test_plot_html_format(self, tmp_path):
        """Test generating HTML format chart with Plotly."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        data = {
            "strategy_1": {"effectiveness_score": 0.9, "usage_count": 200},
            "strategy_2": {"effectiveness_score": 0.7, "usage_count": 150},
        }

        path = visualizer.plot_strategy_effectiveness(data, output_format="html")

        assert path.exists()
        assert path.suffix == ".html"

    def test_plot_empty_data(self, tmp_path):
        """Test plotting with empty data."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        data = {}

        path = visualizer.plot_strategy_effectiveness(data, output_format="png")
        assert path.exists()

    def test_plot_missing_effectiveness_score(self, tmp_path):
        """Test with missing effectiveness_score uses default."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        data = {
            "strategy": {},  # No effectiveness_score
        }

        path = visualizer.plot_strategy_effectiveness(data, output_format="png")
        assert path.exists()


class TestPlotCrashTrend:
    """Test plot_crash_trend method."""

    def test_plot_crash_trend_png(self, tmp_path):
        """Test crash trend line chart in PNG."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        trend_data = MockTrendAnalysis(
            crashes_over_time=[
                (datetime(2025, 1, 1, 10, 0), 5),
                (datetime(2025, 1, 1, 11, 0), 3),
                (datetime(2025, 1, 1, 12, 0), 7),
            ]
        )

        path = visualizer.plot_crash_trend(trend_data, output_format="png")

        assert path.exists()
        assert "crash_trend" in path.name

    def test_plot_crash_trend_html(self, tmp_path):
        """Test crash trend chart with Plotly."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        trend_data = MockTrendAnalysis(
            crashes_over_time=[
                (datetime(2025, 1, 1, 10, 0), 2),
                (datetime(2025, 1, 1, 11, 0), 4),
            ]
        )

        path = visualizer.plot_crash_trend(trend_data, output_format="html")

        assert path.exists()
        assert path.suffix == ".html"

    def test_plot_crash_trend_empty_data(self, tmp_path):
        """Test crash trend with no data shows empty message."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        trend_data = MockTrendAnalysis(crashes_over_time=[])

        path = visualizer.plot_crash_trend(trend_data, output_format="png")

        assert path.exists()

    def test_plot_crash_trend_empty_data_html(self, tmp_path):
        """Test crash trend HTML with no data."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        trend_data = MockTrendAnalysis(crashes_over_time=[])

        path = visualizer.plot_crash_trend(trend_data, output_format="html")

        assert path.exists()


class TestPlotCoverageHeatmap:
    """Test plot_coverage_heatmap method."""

    def test_plot_coverage_heatmap_png(self, tmp_path):
        """Test coverage heatmap in PNG format."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        coverage_data = {
            "bit_flip": MockCoverageCorrelation(30.0, 60, 0.8),
            "byte_swap": MockCoverageCorrelation(20.0, 40, 0.6),
            "truncate": MockCoverageCorrelation(15.0, 30, 0.5),
        }

        path = visualizer.plot_coverage_heatmap(coverage_data, output_format="png")

        assert path.exists()
        assert "coverage_heatmap" in path.name

    def test_plot_coverage_heatmap_html(self, tmp_path):
        """Test coverage heatmap with Plotly."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        coverage_data = {
            "strategy_a": MockCoverageCorrelation(25.0, 50, 0.75),
            "strategy_b": MockCoverageCorrelation(35.0, 70, 0.85),
        }

        path = visualizer.plot_coverage_heatmap(coverage_data, output_format="html")

        assert path.exists()
        assert path.suffix == ".html"

    def test_plot_coverage_heatmap_svg(self, tmp_path):
        """Test coverage heatmap in SVG format."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        coverage_data = {
            "test_strategy": MockCoverageCorrelation(),
        }

        path = visualizer.plot_coverage_heatmap(coverage_data, output_format="svg")

        assert path.exists()
        assert path.suffix == ".svg"


class TestPlotPerformanceDashboard:
    """Test plot_performance_dashboard method."""

    def test_plot_dashboard_png(self, tmp_path):
        """Test performance dashboard in PNG format."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        perf_data = MockPerformanceMetrics()

        path = visualizer.plot_performance_dashboard(perf_data, output_format="png")

        assert path.exists()
        assert "performance_dashboard" in path.name

    def test_plot_dashboard_html(self, tmp_path):
        """Test performance dashboard with Plotly."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        perf_data = MockPerformanceMetrics(
            mutations_per_second=2000.0,
            peak_memory_mb=1024.0,
            avg_memory_mb=512.0,
            cpu_utilization=90.0,
            cache_hit_rate=95.0,
        )

        path = visualizer.plot_performance_dashboard(perf_data, output_format="html")

        assert path.exists()
        assert path.suffix == ".html"

    def test_plot_dashboard_low_throughput(self, tmp_path):
        """Test dashboard with low throughput score."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        perf_data = MockPerformanceMetrics(
            mutations_per_second=500.0,  # Low throughput
        )

        path = visualizer.plot_performance_dashboard(perf_data, output_format="png")

        assert path.exists()

    def test_plot_dashboard_high_throughput(self, tmp_path):
        """Test dashboard with high throughput score."""
        visualizer = FuzzingVisualizer(str(tmp_path))
        perf_data = MockPerformanceMetrics(
            mutations_per_second=3000.0,  # High throughput
        )

        path = visualizer.plot_performance_dashboard(perf_data, output_format="png")

        assert path.exists()


class TestCreateSummaryReportHtml:
    """Test create_summary_report_html method."""

    def test_create_html_report(self, tmp_path):
        """Test HTML report generation."""
        visualizer = FuzzingVisualizer(str(tmp_path))

        # Create mock chart paths
        strategy_path = tmp_path / "strategy.png"
        trend_path = tmp_path / "trend.png"
        coverage_path = tmp_path / "coverage.png"
        performance_path = tmp_path / "performance.png"

        for p in [strategy_path, trend_path, coverage_path, performance_path]:
            p.write_bytes(b"mock image data")

        html = visualizer.create_summary_report_html(
            strategy_path,
            trend_path,
            coverage_path,
            performance_path,
        )

        assert "charts-container" in html
        assert "Strategy Effectiveness" in html
        assert "Crash Discovery Trend" in html
        assert "Coverage Correlation" in html
        assert "Performance Metrics" in html
        assert strategy_path.name in html

    def test_html_report_contains_styles(self, tmp_path):
        """Test HTML report includes CSS styles."""
        visualizer = FuzzingVisualizer(str(tmp_path))

        html = visualizer.create_summary_report_html(
            Path("a.png"),
            Path("b.png"),
            Path("c.png"),
            Path("d.png"),
        )

        assert "<style>" in html
        assert ".chart-section" in html
        assert "border-radius" in html

    def test_html_report_contains_images(self, tmp_path):
        """Test HTML report references image files."""
        visualizer = FuzzingVisualizer(str(tmp_path))

        strategy = Path("strategy_chart.png")
        trend = Path("trend_chart.png")
        coverage = Path("coverage_chart.png")
        performance = Path("performance_chart.png")

        html = visualizer.create_summary_report_html(
            strategy, trend, coverage, performance
        )

        assert "strategy_chart.png" in html
        assert "trend_chart.png" in html
        assert "coverage_chart.png" in html
        assert "performance_chart.png" in html
        assert "<img src=" in html


class TestIntegration:
    """Integration tests for complete visualization workflows."""

    def test_full_visualization_workflow_matplotlib(self, tmp_path):
        """Test complete visualization workflow with Matplotlib."""
        visualizer = FuzzingVisualizer(str(tmp_path))

        # Strategy effectiveness
        strategy_data = {
            "bit_flip": {"effectiveness_score": 0.8},
            "random": {"effectiveness_score": 0.5},
        }
        strategy_path = visualizer.plot_strategy_effectiveness(
            strategy_data, output_format="png"
        )

        # Crash trend
        trend_data = MockTrendAnalysis(
            crashes_over_time=[
                (datetime(2025, 1, 1, 10, 0), 3),
                (datetime(2025, 1, 1, 11, 0), 5),
            ]
        )
        trend_path = visualizer.plot_crash_trend(trend_data, output_format="png")

        # Coverage heatmap
        coverage_data = {
            "strategy_a": MockCoverageCorrelation(),
        }
        coverage_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="png"
        )

        # Performance dashboard
        perf_data = MockPerformanceMetrics()
        perf_path = visualizer.plot_performance_dashboard(
            perf_data, output_format="png"
        )

        # Generate HTML summary
        html = visualizer.create_summary_report_html(
            strategy_path, trend_path, coverage_path, perf_path
        )

        assert all(
            p.exists() for p in [strategy_path, trend_path, coverage_path, perf_path]
        )
        assert "charts-container" in html

    def test_full_visualization_workflow_plotly(self, tmp_path):
        """Test complete visualization workflow with Plotly."""
        visualizer = FuzzingVisualizer(str(tmp_path))

        # Strategy effectiveness
        strategy_data = {"strategy_1": {"effectiveness_score": 0.9, "usage_count": 100}}
        strategy_path = visualizer.plot_strategy_effectiveness(
            strategy_data, output_format="html"
        )

        # Crash trend
        trend_data = MockTrendAnalysis(
            crashes_over_time=[(datetime(2025, 1, 1, 12, 0), 10)]
        )
        trend_path = visualizer.plot_crash_trend(trend_data, output_format="html")

        # Coverage heatmap
        coverage_data = {"test": MockCoverageCorrelation(50.0, 100, 0.9)}
        coverage_path = visualizer.plot_coverage_heatmap(
            coverage_data, output_format="html"
        )

        # Performance dashboard
        perf_data = MockPerformanceMetrics()
        perf_path = visualizer.plot_performance_dashboard(
            perf_data, output_format="html"
        )

        assert all(
            p.exists() and p.suffix == ".html"
            for p in [strategy_path, trend_path, coverage_path, perf_path]
        )
