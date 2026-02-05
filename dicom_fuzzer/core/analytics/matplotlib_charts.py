"""Matplotlib Chart Renderer - Static chart generation.

Provides static chart generation using Matplotlib and Seaborn.
Supports PNG and SVG output formats.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for server environments
import matplotlib.pyplot as plt
import seaborn as sns

from dicom_fuzzer.core.analytics.campaign_analytics import (
    CoverageCorrelation,
    PerformanceMetrics,
    TrendAnalysis,
)
from dicom_fuzzer.utils.identifiers import generate_timestamp_id

# Seaborn style configuration
sns.set_theme(style="whitegrid")
sns.set_palette("husl")


class MatplotlibChartRenderer:
    """Renders static charts using Matplotlib and Seaborn."""

    def __init__(self, output_dir: Path, colors: dict[str, str]):
        """Initialize renderer.

        Args:
            output_dir: Directory to save chart files
            colors: Color scheme dictionary

        """
        self.output_dir = output_dir
        self.colors = colors

    def plot_strategy_effectiveness(
        self,
        effectiveness_data: dict[str, dict[str, float]],
        output_format: str = "png",
    ) -> Path:
        """Create strategy effectiveness bar chart."""
        strategies = list(effectiveness_data.keys())
        scores = [
            data.get("effectiveness_score", 0.0) for data in effectiveness_data.values()
        ]

        fig, ax = plt.subplots(figsize=(12, 6))

        bars = ax.bar(strategies, scores, color=self.colors["primary"], alpha=0.8)

        ax.set_xlabel("Mutation Strategy", fontsize=12, fontweight="bold")
        ax.set_ylabel("Effectiveness Score", fontsize=12, fontweight="bold")
        ax.set_title("Mutation Strategy Effectiveness", fontsize=14, fontweight="bold")
        ax.set_ylim(0, 1.0)
        ax.grid(axis="y", alpha=0.3)

        plt.xticks(rotation=45, ha="right")

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

        timestamp = generate_timestamp_id()
        output_path = (
            self.output_dir / f"strategy_effectiveness_{timestamp}.{output_format}"
        )
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def plot_crash_trend(
        self, trend_data: TrendAnalysis, output_format: str = "png"
    ) -> Path:
        """Create crash trend line chart."""
        if not trend_data.crashes_over_time:
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

        timestamps = [ts for ts, _ in trend_data.crashes_over_time]
        cumulative_crashes = []
        total = 0
        for _, count in trend_data.crashes_over_time:
            total += count
            cumulative_crashes.append(total)

        fig, ax = plt.subplots(figsize=(12, 6))

        ax.plot(
            timestamps,
            cumulative_crashes,
            color=self.colors["danger"],
            linewidth=2,
            marker="o",
            markersize=6,
            label="Cumulative Crashes",
        )

        ax.set_xlabel("Time", fontsize=12, fontweight="bold")
        ax.set_ylabel("Cumulative Crashes", fontsize=12, fontweight="bold")
        ax.set_title("Crash Discovery Over Time", fontsize=14, fontweight="bold")
        ax.grid(alpha=0.3)
        ax.legend(fontsize=10)

        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()

        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"crash_trend_{timestamp}.{output_format}"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def plot_coverage_heatmap(
        self, coverage_data: dict[str, CoverageCorrelation], output_format: str = "png"
    ) -> Path:
        """Create coverage heatmap."""
        strategies = list(coverage_data.keys())
        metrics = [
            "Coverage\nIncrease",
            "Unique\nPaths",
            "Crash\nCorrelation",
            "Overall\nScore",
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

        fig, ax = plt.subplots(figsize=(10, len(strategies) * 0.8 + 2))

        im = ax.imshow(data, cmap="RdYlGn", aspect="auto", vmin=0, vmax=1)

        ax.set_xticks(range(len(metrics)))
        ax.set_yticks(range(len(strategies)))
        ax.set_xticklabels(metrics, fontsize=10)
        ax.set_yticklabels(strategies, fontsize=10)

        plt.setp(ax.get_xticklabels(), rotation=0, ha="center")

        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label("Score (0-1)", rotation=270, labelpad=20, fontsize=10)

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

        timestamp = generate_timestamp_id()
        output_path = self.output_dir / f"coverage_heatmap_{timestamp}.{output_format}"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path

    def plot_performance_dashboard(
        self, performance_data: PerformanceMetrics, output_format: str = "png"
    ) -> Path:
        """Create performance dashboard with multiple metrics."""
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

        timestamp = generate_timestamp_id()
        output_path = (
            self.output_dir / f"performance_dashboard_{timestamp}.{output_format}"
        )
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        return output_path
