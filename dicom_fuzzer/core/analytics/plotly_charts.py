"""Plotly Chart Renderer - Interactive chart generation.

Provides interactive chart generation using Plotly.
Supports HTML output format with hover tooltips and zoom.
"""

from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from dicom_fuzzer.core.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.utils.identifiers import generate_timestamp_id


class PlotlyChartRenderer:
    """Renders interactive charts using Plotly."""

    def __init__(self, output_dir: Path, colors: dict[str, str]):
        """Initialize renderer.

        Args:
            output_dir: Directory to save chart files
            colors: Color scheme dictionary

        """
        self.output_dir = output_dir
        self.colors = colors

    def plot_strategy_effectiveness(
        self, effectiveness_data: dict[str, dict[str, float]]
    ) -> Path:
        """Create interactive strategy effectiveness chart."""
        strategies = list(effectiveness_data.keys())
        scores = [
            data.get("effectiveness_score", 0.0) for data in effectiveness_data.values()
        ]
        usage_counts = [
            data.get("usage_count", 0) for data in effectiveness_data.values()
        ]

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

        fig.update_layout(
            title="Mutation Strategy Effectiveness",
            xaxis_title="Mutation Strategy",
            yaxis_title="Effectiveness Score",
            yaxis_range=[0, 1.0],
            template="plotly_white",
            font={"size": 12},
            hovermode="x unified",
        )

        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"strategy_effectiveness_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

    def plot_crash_trend(self, trend_data: TrendAnalysis) -> Path:
        """Create interactive crash trend chart."""
        if not trend_data.crashes_over_time:
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

        timestamps = [ts for ts, _ in trend_data.crashes_over_time]
        cumulative_crashes = []
        total = 0
        for _, count in trend_data.crashes_over_time:
            total += count
            cumulative_crashes.append(total)

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

        fig.update_layout(
            title="Crash Discovery Over Time",
            xaxis_title="Time",
            yaxis_title="Cumulative Crashes",
            template="plotly_white",
            font={"size": 12},
            hovermode="x unified",
        )

        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"crash_trend_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

    def plot_coverage_heatmap(
        self, coverage_data: dict[str, CoverageCorrelation]
    ) -> Path:
        """Create interactive coverage heatmap."""
        strategies = list(coverage_data.keys())
        metrics = [
            "Coverage Increase",
            "Unique Paths",
            "Crash Correlation",
            "Overall Score",
        ]

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

        fig.update_layout(
            title="Coverage Correlation Heatmap",
            xaxis_title="Metrics",
            yaxis_title="Mutation Strategy",
            template="plotly_white",
            font={"size": 12},
        )

        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"coverage_heatmap_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path

    def plot_performance_dashboard(self, performance_data: PerformanceMetrics) -> Path:
        """Create interactive performance dashboard."""
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

        fig.update_layout(
            title_text="Performance Dashboard",
            showlegend=False,
            template="plotly_white",
            font={"size": 12},
            height=800,
        )

        fig.update_yaxes(title_text="Mutations/sec", row=1, col=2)
        fig.update_yaxes(title_text="Memory (MB)", row=2, col=1)
        fig.update_yaxes(title_text="Percentage (%)", range=[0, 100], row=2, col=2)

        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"performance_dashboard_{timestamp}.html"
        fig.write_html(str(output_path))

        return output_path
