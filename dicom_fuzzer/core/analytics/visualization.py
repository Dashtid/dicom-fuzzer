"""Visualization Module - Charts and Graphs for Fuzzing Reports.

Provides unified interface for Matplotlib and Plotly charts.
Delegates to backend-specific renderers based on output format.
"""

from pathlib import Path

from dicom_fuzzer.core.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.core.analytics.matplotlib_charts import MatplotlibChartRenderer
from dicom_fuzzer.core.analytics.plotly_charts import PlotlyChartRenderer


class FuzzingVisualizer:
    """Creates visualizations for fuzzing campaign analytics.

    Unified interface supporting both static (Matplotlib) and interactive (Plotly) charts.
    Automatically delegates to the appropriate renderer based on output format.
    """

    # Default color scheme
    DEFAULT_COLORS = {
        "primary": "#667eea",
        "secondary": "#764ba2",
        "success": "#4CAF50",
        "warning": "#FF9800",
        "danger": "#f44336",
        "info": "#2196F3",
    }

    def __init__(self, output_dir: str = "./artifacts/reports/charts"):
        """Initialize visualizer.

        Args:
            output_dir: Directory to save chart files

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.colors = self.DEFAULT_COLORS.copy()

        # Initialize backend renderers
        self._matplotlib = MatplotlibChartRenderer(self.output_dir, self.colors)
        self._plotly = PlotlyChartRenderer(self.output_dir, self.colors)

    def plot_strategy_effectiveness(
        self,
        effectiveness_data: dict[str, dict[str, float]],
        output_format: str = "png",
    ) -> Path:
        """Create bar chart of mutation strategy effectiveness.

        Args:
            effectiveness_data: Dict mapping strategies to effectiveness metrics
            output_format: Output format ('png', 'svg', 'html')

        Returns:
            Path to saved chart file

        """
        if output_format == "html":
            return self._plotly.plot_strategy_effectiveness(effectiveness_data)
        return self._matplotlib.plot_strategy_effectiveness(
            effectiveness_data, output_format
        )

    def plot_crash_trend(
        self, trend_data: TrendAnalysis, output_format: str = "png"
    ) -> Path:
        """Create line chart of crash discovery over time.

        Args:
            trend_data: TrendAnalysis object with time-series data
            output_format: Output format ('png', 'svg', 'html')

        Returns:
            Path to saved chart file

        """
        if output_format == "html":
            return self._plotly.plot_crash_trend(trend_data)
        return self._matplotlib.plot_crash_trend(trend_data, output_format)

    def plot_coverage_heatmap(
        self, coverage_data: dict[str, CoverageCorrelation], output_format: str = "png"
    ) -> Path:
        """Create heatmap of coverage correlation by strategy.

        Args:
            coverage_data: Dict mapping strategies to CoverageCorrelation
            output_format: Output format ('png', 'svg', 'html')

        Returns:
            Path to saved chart file

        """
        if output_format == "html":
            return self._plotly.plot_coverage_heatmap(coverage_data)
        return self._matplotlib.plot_coverage_heatmap(coverage_data, output_format)

    def plot_performance_dashboard(
        self, performance_data: PerformanceMetrics, output_format: str = "png"
    ) -> Path:
        """Create performance dashboard with multiple metrics.

        Args:
            performance_data: PerformanceMetrics object
            output_format: Output format ('png', 'svg', 'html')

        Returns:
            Path to saved chart file

        """
        if output_format == "html":
            return self._plotly.plot_performance_dashboard(performance_data)
        return self._matplotlib.plot_performance_dashboard(
            performance_data, output_format
        )

    def create_summary_report_html(
        self,
        strategy_chart_path: Path,
        trend_chart_path: Path,
        coverage_chart_path: Path,
        performance_chart_path: Path,
    ) -> str:
        """Create HTML snippet embedding all charts.

        Args:
            strategy_chart_path: Path to strategy effectiveness chart
            trend_chart_path: Path to crash trend chart
            coverage_chart_path: Path to coverage heatmap
            performance_chart_path: Path to performance dashboard

        Returns:
            HTML string with embedded charts

        """
        return f"""
        <div class="charts-container">
            <h2>[+] Visualization Dashboard</h2>

            <div class="chart-section">
                <h3>Strategy Effectiveness</h3>
                <img src="{strategy_chart_path.name}" alt="Strategy Effectiveness" style="max-width: 100%; height: auto;">
            </div>

            <div class="chart-section">
                <h3>Crash Discovery Trend</h3>
                <img src="{trend_chart_path.name}" alt="Crash Trend" style="max-width: 100%; height: auto;">
            </div>

            <div class="chart-section">
                <h3>Coverage Correlation</h3>
                <img src="{coverage_chart_path.name}" alt="Coverage Heatmap" style="max-width: 100%; height: auto;">
            </div>

            <div class="chart-section">
                <h3>Performance Metrics</h3>
                <img src="{performance_chart_path.name}" alt="Performance Dashboard" style="max-width: 100%; height: auto;">
            </div>
        </div>

        <style>
            .charts-container {{
                margin: 30px 0;
            }}

            .chart-section {{
                margin: 30px 0;
                padding: 20px;
                background: #f9f9f9;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}

            .chart-section h3 {{
                color: #667eea;
                margin-top: 0;
                margin-bottom: 15px;
            }}
        </style>
        """
