"""Visualization Module - Charts and Graphs for Fuzzing Reports

This module provides visualization capabilities for fuzzing campaign analytics:
- Matplotlib charts (bar charts, line graphs, pie charts)
- Plotly interactive charts (heatmaps, 3D scatter plots, time series)
- Export formats (PNG, SVG, HTML embeds)
- Responsive design for HTML reports

CONCEPT: Visualizations make complex data accessible:
- Strategy effectiveness bar charts
- Crash discovery trend lines
- Coverage heatmaps
- Performance dashboards

Based on 2025 best practices from data visualization (Plotly Dash, Matplotlib)
and fuzzing tools (AFL++, LibFuzzer coverage visualization).
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for server environments
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import seaborn as sns
from plotly.subplots import make_subplots

from dicom_fuzzer.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.utils.identifiers import generate_timestamp_id

# Seaborn style configuration
sns.set_theme(style="whitegrid")
sns.set_palette("husl")


class FuzzingVisualizer:
    """Creates visualizations for fuzzing campaign analytics.

    Supports both static (Matplotlib) and interactive (Plotly) charts.
    """

    def __init__(self, output_dir: str = "./artifacts/reports/charts"):
        """Initialize visualizer.

        Args:
            output_dir: Directory to save chart files

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Color schemes
        self.colors = {
            "primary": "#667eea",
            "secondary": "#764ba2",
            "success": "#4CAF50",
            "warning": "#FF9800",
            "danger": "#f44336",
            "info": "#2196F3",
        }

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
            return self._plot_strategy_effectiveness_plotly(effectiveness_data)
        else:
            return self._plot_strategy_effectiveness_matplotlib(
                effectiveness_data, output_format
            )

    def _plot_strategy_effectiveness_matplotlib(
        self,
        effectiveness_data: dict[str, dict[str, float]],
        output_format: str = "png",
    ) -> Path:
        """Create strategy effectiveness bar chart with Matplotlib."""
        strategies = list(effectiveness_data.keys())
        scores = [
            data.get("effectiveness_score", 0.0) for data in effectiveness_data.values()
        ]

        # Create figure
        fig, ax = plt.subplots(figsize=(12, 6))

        # Create bar chart
        bars = ax.bar(strategies, scores, color=self.colors["primary"], alpha=0.8)

        # Customize chart
        ax.set_xlabel("Mutation Strategy", fontsize=12, fontweight="bold")
        ax.set_ylabel("Effectiveness Score", fontsize=12, fontweight="bold")
        ax.set_title("Mutation Strategy Effectiveness", fontsize=14, fontweight="bold")
        ax.set_ylim(0, 1.0)
        ax.grid(axis="y", alpha=0.3)

        # Rotate x-axis labels
        plt.xticks(rotation=45, ha="right")

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{height:.2f}",
                ha="center",
                va="bottom",
                fontsize=10,
            )

        plt.tight_layout()

        # Save figure
        timestamp = generate_timestamp_id()
        output_path = (
            self.output_dir / f"strategy_effectiveness_{timestamp}.{output_format}"
        )
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def _plot_strategy_effectiveness_plotly(
        self, effectiveness_data: dict[str, dict[str, float]]
    ) -> Path:
        """Create interactive strategy effectiveness chart with Plotly."""
        strategies = list(effectiveness_data.keys())
        scores = [
            data.get("effectiveness_score", 0.0) for data in effectiveness_data.values()
        ]
        usage_counts = [
            data.get("usage_count", 0) for data in effectiveness_data.values()
        ]

        # Create bar chart
        fig = go.Figure(
            data=[
                go.Bar(
                    x=strategies,
                    y=scores,
                    marker_color=self.colors["primary"],
                    text=[f"{s:.2f}" for s in scores],
                    textposition="outside",
                    hovertemplate=(
                        "<b>%{x}</b><br>"
                        + "Effectiveness: %{y:.2f}<br>"
                        + "Usage Count: %{customdata}<br>"
                        + "<extra></extra>"
                    ),
                    customdata=usage_counts,
                )
            ]
        )

        # Customize layout
        fig.update_layout(
            title="Mutation Strategy Effectiveness",
            xaxis_title="Mutation Strategy",
            yaxis_title="Effectiveness Score",
            yaxis_range=[0, 1.0],
            template="plotly_white",
            font={"size": 12},
            hovermode="x unified",
        )

        # Save HTML
        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"strategy_effectiveness_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

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
            return self._plot_crash_trend_plotly(trend_data)
        else:
            return self._plot_crash_trend_matplotlib(trend_data, output_format)

    def _plot_crash_trend_matplotlib(
        self, trend_data: TrendAnalysis, output_format: str = "png"
    ) -> Path:
        """Create crash trend line chart with Matplotlib."""
        if not trend_data.crashes_over_time:
            # Return empty chart
            fig, ax = plt.subplots(figsize=(12, 6))
            ax.text(
                0.5,
                0.5,
                "No crash data available",
                ha="center",
                va="center",
                fontsize=14,
                color="gray",
            )
            ax.set_xlim(0, 1)
            ax.set_ylim(0, 1)
            ax.axis("off")
            timestamp = generate_timestamp_id()
            output_path = self.output_dir / f"crash_trend_{timestamp}.{output_format}"
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            plt.close()
            return output_path

        # Extract data
        timestamps = [ts for ts, _ in trend_data.crashes_over_time]
        cumulative_crashes = []
        total = 0
        for _, count in trend_data.crashes_over_time:
            total += count
            cumulative_crashes.append(total)

        # Create figure
        fig, ax = plt.subplots(figsize=(12, 6))

        # Plot line - matplotlib handles datetime lists automatically
        ax.plot(
            timestamps,
            cumulative_crashes,
            color=self.colors["danger"],
            linewidth=2,
            marker="o",
            markersize=6,
            label="Cumulative Crashes",
        )

        # Customize chart
        ax.set_xlabel("Time", fontsize=12, fontweight="bold")
        ax.set_ylabel("Cumulative Crashes", fontsize=12, fontweight="bold")
        ax.set_title("Crash Discovery Over Time", fontsize=14, fontweight="bold")
        ax.grid(alpha=0.3)
        ax.legend(fontsize=10)

        # Format x-axis dates
        plt.xticks(rotation=45, ha="right")

        plt.tight_layout()

        # Save figure
        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"crash_trend_{timestamp}.{output_format}"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def _plot_crash_trend_plotly(self, trend_data: TrendAnalysis) -> Path:
        """Create interactive crash trend chart with Plotly."""
        if not trend_data.crashes_over_time:
            # Create empty figure
            fig = go.Figure()
            fig.add_annotation(
                text="No crash data available",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
                font={"size": 14, "color": "gray"},
            )
            timestamp = generate_timestamp_id()
            output_path = self.output_dir / f"crash_trend_{timestamp}.html"
            fig.write_html(str(output_path))
            return output_path

        # Extract data
        timestamps = [ts for ts, _ in trend_data.crashes_over_time]
        cumulative_crashes = []
        total = 0
        for _, count in trend_data.crashes_over_time:
            total += count
            cumulative_crashes.append(total)

        # Create line chart
        fig = go.Figure(
            data=[
                go.Scatter(
                    x=timestamps,
                    y=cumulative_crashes,
                    mode="lines+markers",
                    line={"color": self.colors["danger"], "width": 2},
                    marker={"size": 8},
                    hovertemplate=(
                        "<b>Time:</b> %{x}<br>"
                        + "<b>Cumulative Crashes:</b> %{y}<br>"
                        + "<extra></extra>"
                    ),
                )
            ]
        )

        # Customize layout
        fig.update_layout(
            title="Crash Discovery Over Time",
            xaxis_title="Time",
            yaxis_title="Cumulative Crashes",
            template="plotly_white",
            font={"size": 12},
            hovermode="x unified",
        )

        # Save HTML
        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"crash_trend_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

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
            return self._plot_coverage_heatmap_plotly(coverage_data)
        else:
            return self._plot_coverage_heatmap_matplotlib(coverage_data, output_format)

    def _plot_coverage_heatmap_matplotlib(
        self, coverage_data: dict[str, CoverageCorrelation], output_format: str = "png"
    ) -> Path:
        """Create coverage heatmap with Matplotlib."""
        strategies = list(coverage_data.keys())
        metrics = [
            "Coverage\nIncrease",
            "Unique\nPaths",
            "Crash\nCorrelation",
            "Overall\nScore",
        ]

        # Build data matrix
        data = []
        for strategy in strategies:
            corr = coverage_data[strategy]
            data.append(
                [
                    corr.coverage_increase / 100.0,  # Normalize to 0-1
                    min(corr.unique_paths / 100.0, 1.0),  # Normalize to 0-1
                    corr.crash_correlation,
                    corr.correlation_score(),
                ]
            )

        # Create figure
        fig, ax = plt.subplots(figsize=(10, len(strategies) * 0.8 + 2))

        # Create heatmap
        im = ax.imshow(data, cmap="RdYlGn", aspect="auto", vmin=0, vmax=1)

        # Set ticks
        ax.set_xticks(range(len(metrics)))
        ax.set_yticks(range(len(strategies)))
        ax.set_xticklabels(metrics, fontsize=10)
        ax.set_yticklabels(strategies, fontsize=10)

        # Rotate x-axis labels
        plt.setp(ax.get_xticklabels(), rotation=0, ha="center")

        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label("Score (0-1)", rotation=270, labelpad=20, fontsize=10)

        # Add text annotations
        for i in range(len(strategies)):
            for j in range(len(metrics)):
                ax.text(
                    j,
                    i,
                    f"{data[i][j]:.2f}",
                    ha="center",
                    va="center",
                    color="white" if data[i][j] < 0.5 else "black",
                    fontsize=9,
                )

        ax.set_title(
            "Coverage Correlation Heatmap", fontsize=14, fontweight="bold", pad=20
        )

        plt.tight_layout()

        # Save figure
        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"coverage_heatmap_{timestamp}.{output_format}"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def _plot_coverage_heatmap_plotly(
        self, coverage_data: dict[str, CoverageCorrelation]
    ) -> Path:
        """Create interactive coverage heatmap with Plotly."""
        strategies = list(coverage_data.keys())
        metrics = [
            "Coverage Increase",
            "Unique Paths",
            "Crash Correlation",
            "Overall Score",
        ]

        # Build data matrix
        data = []
        for strategy in strategies:
            corr = coverage_data[strategy]
            data.append(
                [
                    corr.coverage_increase / 100.0,
                    min(corr.unique_paths / 100.0, 1.0),
                    corr.crash_correlation,
                    corr.correlation_score(),
                ]
            )

        # Create heatmap
        fig = go.Figure(
            data=go.Heatmap(
                z=data,
                x=metrics,
                y=strategies,
                colorscale="RdYlGn",
                zmin=0,
                zmax=1,
                hovertemplate=(
                    "<b>Strategy:</b> %{y}<br>"
                    + "<b>Metric:</b> %{x}<br>"
                    + "<b>Score:</b> %{z:.2f}<br>"
                    + "<extra></extra>"
                ),
                colorbar={"title": "Score (0-1)"},
            )
        )

        # Customize layout
        fig.update_layout(
            title="Coverage Correlation Heatmap",
            xaxis_title="Metrics",
            yaxis_title="Mutation Strategy",
            template="plotly_white",
            font={"size": 12},
        )

        # Save HTML
        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"coverage_heatmap_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

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
            return self._plot_performance_dashboard_plotly(performance_data)
        else:
            return self._plot_performance_dashboard_matplotlib(
                performance_data, output_format
            )

    def _plot_performance_dashboard_matplotlib(
        self, performance_data: PerformanceMetrics, output_format: str = "png"
    ) -> Path:
        """Create performance dashboard with Matplotlib."""
        # Create figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("Performance Dashboard", fontsize=16, fontweight="bold")

        # 1. Throughput gauge
        ax1 = axes[0, 0]
        throughput_score = performance_data.throughput_score()
        ax1.barh(
            ["Throughput"],
            [throughput_score],
            color=self.colors["success"]
            if throughput_score > 0.7
            else self.colors["warning"],
        )
        ax1.set_xlim(0, 1)
        ax1.set_xlabel("Score (0-1)")
        ax1.set_title("Overall Throughput Score", fontweight="bold")
        ax1.text(
            throughput_score, 0, f" {throughput_score:.2f}", va="center", fontsize=12
        )

        # 2. Mutations per second
        ax2 = axes[0, 1]
        ax2.bar(
            ["Mutations/sec"],
            [performance_data.mutations_per_second],
            color=self.colors["primary"],
        )
        ax2.set_ylabel("Mutations per Second")
        ax2.set_title("Mutation Throughput", fontweight="bold")
        ax2.text(
            0,
            performance_data.mutations_per_second,
            f"{performance_data.mutations_per_second:.1f}",
            ha="center",
            va="bottom",
            fontsize=12,
        )

        # 3. Memory usage
        ax3 = axes[1, 0]
        memory_metrics = ["Peak", "Average"]
        memory_values = [
            performance_data.peak_memory_mb,
            performance_data.avg_memory_mb,
        ]
        ax3.bar(
            memory_metrics,
            memory_values,
            color=[self.colors["danger"], self.colors["info"]],
        )
        ax3.set_ylabel("Memory (MB)")
        ax3.set_title("Memory Usage", fontweight="bold")
        for i, v in enumerate(memory_values):
            ax3.text(i, v, f"{v:.0f}", ha="center", va="bottom", fontsize=12)

        # 4. CPU and Cache
        ax4 = axes[1, 1]
        utilization_metrics = ["CPU\nUtilization", "Cache\nHit Rate"]
        utilization_values = [
            performance_data.cpu_utilization,
            performance_data.cache_hit_rate,
        ]
        ax4.bar(
            utilization_metrics,
            utilization_values,
            color=[self.colors["secondary"], self.colors["success"]],
        )
        ax4.set_ylabel("Percentage (%)")
        ax4.set_ylim(0, 100)
        ax4.set_title("Utilization Metrics", fontweight="bold")
        for i, v in enumerate(utilization_values):
            ax4.text(i, v, f"{v:.1f}%", ha="center", va="bottom", fontsize=12)

        plt.tight_layout()

        # Save figure
        timestamp = generate_timestamp_id()
        output_path = (
            self.output_dir / f"performance_dashboard_{timestamp}.{output_format}"
        )
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def _plot_performance_dashboard_plotly(
        self, performance_data: PerformanceMetrics
    ) -> Path:
        """Create interactive performance dashboard with Plotly."""
        # Create subplots
        fig = make_subplots(
            rows=2,
            cols=2,
            subplot_titles=(
                "Throughput Score",
                "Mutation Throughput",
                "Memory Usage",
                "Utilization Metrics",
            ),
            specs=[
                [{"type": "indicator"}, {"type": "bar"}],
                [{"type": "bar"}, {"type": "bar"}],
            ],
        )

        # 1. Throughput gauge
        throughput_score = performance_data.throughput_score()
        fig.add_trace(
            go.Indicator(
                mode="gauge+number",
                value=throughput_score,
                domain={"x": [0, 1], "y": [0, 1]},
                gauge={
                    "axis": {"range": [0, 1]},
                    "bar": {
                        "color": self.colors["success"]
                        if throughput_score > 0.7
                        else self.colors["warning"]
                    },
                    "steps": [
                        {"range": [0, 0.5], "color": "lightgray"},
                        {"range": [0.5, 0.7], "color": "gray"},
                        {"range": [0.7, 1], "color": "darkgray"},
                    ],
                    "threshold": {
                        "line": {"color": "red", "width": 4},
                        "thickness": 0.75,
                        "value": 0.9,
                    },
                },
            ),
            row=1,
            col=1,
        )

        # 2. Mutations per second
        fig.add_trace(
            go.Bar(
                x=["Mutations/sec"],
                y=[performance_data.mutations_per_second],
                marker_color=self.colors["primary"],
                text=[f"{performance_data.mutations_per_second:.1f}"],
                textposition="outside",
            ),
            row=1,
            col=2,
        )

        # 3. Memory usage
        fig.add_trace(
            go.Bar(
                x=["Peak", "Average"],
                y=[performance_data.peak_memory_mb, performance_data.avg_memory_mb],
                marker_color=[self.colors["danger"], self.colors["info"]],
                text=[
                    f"{performance_data.peak_memory_mb:.0f}",
                    f"{performance_data.avg_memory_mb:.0f}",
                ],
                textposition="outside",
            ),
            row=2,
            col=1,
        )

        # 4. CPU and Cache
        fig.add_trace(
            go.Bar(
                x=["CPU Utilization", "Cache Hit Rate"],
                y=[performance_data.cpu_utilization, performance_data.cache_hit_rate],
                marker_color=[self.colors["secondary"], self.colors["success"]],
                text=[
                    f"{performance_data.cpu_utilization:.1f}%",
                    f"{performance_data.cache_hit_rate:.1f}%",
                ],
                textposition="outside",
            ),
            row=2,
            col=2,
        )

        # Update layout
        fig.update_layout(
            title_text="Performance Dashboard",
            showlegend=False,
            template="plotly_white",
            font={"size": 12},
            height=800,
        )

        # Update y-axes
        fig.update_yaxes(title_text="Mutations/sec", row=1, col=2)
        fig.update_yaxes(title_text="Memory (MB)", row=2, col=1)
        fig.update_yaxes(title_text="Percentage (%)", range=[0, 100], row=2, col=2)

        # Save HTML
        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"performance_dashboard_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

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
        html = f"""
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

        return html
