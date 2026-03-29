"""Series3D Reporter - Enhanced Reporting for 3D DICOM Series Fuzzing.

Provides specialized reporting for 3D series fuzzing campaigns, tracking
multi-slice mutations and spatial integrity issues.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.utils.identifiers import generate_timestamp_id

from .html_templates import REPORT_CSS

if TYPE_CHECKING:
    from dicom_fuzzer.attacks.series.series_mutator import SeriesMutationRecord


@dataclass
class SeriesMutationSummary:
    """Summary of mutations applied to a DICOM series.

    Tracks series-level statistics for reporting and analytics.
    """

    series_uid: str
    modality: str
    slice_count: int
    total_mutations: int
    strategies_used: dict[str, int] = field(default_factory=dict)
    affected_slices: list[int] = field(default_factory=list)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def add_mutation(self, record: SeriesMutationRecord) -> None:
        """Add a mutation record to the summary."""
        self.total_mutations += 1

        # Track strategy usage
        strategy = record.strategy
        self.strategies_used[strategy] = self.strategies_used.get(strategy, 0) + 1

        # Track affected slices
        if (
            record.slice_index is not None
            and record.slice_index not in self.affected_slices
        ):
            self.affected_slices.append(record.slice_index)

        # Track severity distribution
        severity = record.severity
        self.severity_distribution[severity] = (
            self.severity_distribution.get(severity, 0) + 1
        )

    def get_coverage_percentage(self) -> float:
        """Calculate percentage of slices affected by mutations."""
        if self.slice_count == 0:
            return 0.0
        return (len(self.affected_slices) / self.slice_count) * 100


@dataclass
class Series3DReport:
    """Comprehensive report for a 3D series fuzzing campaign.

    Contains summary statistics, mutation details, and crash information.
    """

    campaign_name: str
    series_summaries: list[SeriesMutationSummary] = field(default_factory=list)
    total_series_fuzzed: int = 0
    total_mutations_applied: int = 0
    total_crashes: int = 0
    crash_details: list[dict[str, Any]] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def add_series_summary(self, summary: SeriesMutationSummary) -> None:
        """Add a series mutation summary to the report."""
        self.series_summaries.append(summary)
        self.total_series_fuzzed += 1
        self.total_mutations_applied += summary.total_mutations

    def get_strategy_effectiveness(self) -> dict[str, dict[str, float]]:
        """Calculate effectiveness metrics for each mutation strategy.

        Returns:
            Dictionary mapping strategy names to effectiveness metrics:
            - usage_count: Number of times strategy was used
            - avg_mutations_per_series: Average mutations per series
            - series_coverage: Percentage of series using this strategy

        """
        strategy_stats = {}
        total_series = len(self.series_summaries)

        if total_series == 0:
            return {}

        # Aggregate strategy usage across all series
        for summary in self.series_summaries:
            for strategy, count in summary.strategies_used.items():
                if strategy not in strategy_stats:
                    strategy_stats[strategy] = {
                        "usage_count": 0,
                        "total_mutations": 0,
                        "series_count": 0,
                    }

                strategy_stats[strategy]["usage_count"] += count
                strategy_stats[strategy]["total_mutations"] += count
                strategy_stats[strategy]["series_count"] += 1

        # Calculate effectiveness metrics
        effectiveness = {}
        for strategy, stats in strategy_stats.items():
            effectiveness[strategy] = {
                "usage_count": stats["usage_count"],
                "avg_mutations_per_series": stats["total_mutations"]
                / stats["series_count"],
                "series_coverage": (stats["series_count"] / total_series) * 100,
            }

        return effectiveness


class Series3DReportGenerator:
    """Generates HTML and JSON reports for 3D DICOM series fuzzing campaigns.

    Integrates with existing reporter infrastructure while adding 3D-specific features:
    - Series mutation tracking
    - Spatial visualization (slice positions, orientations)
    - Strategy effectiveness analysis
    - Coverage correlation
    """

    def __init__(self, output_dir: str = "./artifacts/reports"):
        """Initialize Series3D report generator.

        Args:
            output_dir: Directory to save generated reports

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(self, report: Series3DReport) -> Path:
        """Generate comprehensive HTML report for 3D series fuzzing.

        Args:
            report: Series3D report data

        Returns:
            Path to generated HTML report

        """
        html = self._generate_html_header(report.campaign_name)
        html += self._generate_summary_section(report)
        html += self._generate_strategy_effectiveness_section(report)
        html += self._generate_series_details_section(report)
        html += self._generate_crash_section(report)
        html += self._generate_html_footer()

        # Save report
        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"series3d_report_{timestamp}.html"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        return report_path

    def _generate_html_header(self, campaign_name: str) -> str:
        """Generate HTML header with CSS styling."""
        generated_at = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{campaign_name} - 3D Series Fuzzing Report</title>
    <style>
        {REPORT_CSS}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{campaign_name}</h1>
            <p class="subtitle">3D Series Fuzzing Report &mdash; Generated: {generated_at}</p>
        </div>
        <div class="content">
"""

    def _generate_summary_section(self, report: Series3DReport) -> str:
        """Generate summary statistics section."""
        return f"""
        <h2>Campaign Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Series Fuzzed</div>
                <div class="stat-value">{report.total_series_fuzzed}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Mutations</div>
                <div class="stat-value">{report.total_mutations_applied}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Crashes Found</div>
                <div class="stat-value">{report.total_crashes}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Mutations/Series</div>
                <div class="stat-value">{report.total_mutations_applied / max(report.total_series_fuzzed, 1):.1f}</div>
            </div>
        </div>
"""

    def _generate_strategy_effectiveness_section(self, report: Series3DReport) -> str:
        """Generate strategy effectiveness analysis section."""
        effectiveness = report.get_strategy_effectiveness()

        if not effectiveness:
            return "<h2>Strategy Effectiveness</h2><p>No strategy data available.</p>"

        html = "<h2>Strategy Effectiveness</h2>"
        html += "<table><thead><tr>"
        html += "<th>Strategy</th><th>Usage Count</th><th>Avg Mutations/Series</th><th>Series Coverage</th>"
        html += "</tr></thead><tbody>"

        # Sort by usage count (descending)
        sorted_strategies = sorted(
            effectiveness.items(), key=lambda x: x[1]["usage_count"], reverse=True
        )

        for strategy, metrics in sorted_strategies:
            html += "<tr>"
            html += f"<td><strong>{strategy}</strong></td>"
            html += f"<td>{metrics['usage_count']}</td>"
            html += f"<td>{metrics['avg_mutations_per_series']:.2f}</td>"
            html += f"<td>{metrics['series_coverage']:.1f}%</td>"
            html += "</tr>"

        html += "</tbody></table>"
        return html

    def _generate_series_details_section(self, report: Series3DReport) -> str:
        """Generate detailed series information section."""
        html = "<h2>Series Details</h2>"

        if not report.series_summaries:
            return html + "<p>No series data available.</p>"

        html += "<table><thead><tr>"
        html += "<th>Series UID</th><th>Modality</th><th>Slices</th><th>Mutations</th><th>Coverage</th>"
        html += "</tr></thead><tbody>"

        for summary in report.series_summaries:
            coverage = summary.get_coverage_percentage()
            html += "<tr>"
            html += f"<td><code>{summary.series_uid[:20]}...</code></td>"
            html += f"<td>{summary.modality}</td>"
            html += f"<td>{summary.slice_count}</td>"
            html += f"<td>{summary.total_mutations}</td>"
            html += f"<td>{coverage:.1f}%</td>"
            html += "</tr>"

        html += "</tbody></table>"
        return html

    def _generate_crash_section(self, report: Series3DReport) -> str:
        """Generate crash information section."""
        html = f"<h2>Crashes Found ({report.total_crashes})</h2>"

        if report.total_crashes == 0:
            return html + "<p>No crashes detected during this campaign.</p>"

        # Crash details would be populated from crash analyzer integration
        html += "<p>Crash details integration pending...</p>"
        return html

    def _generate_html_footer(self) -> str:
        """Generate HTML footer."""
        return """
        </div>
    </div>
</body>
</html>
"""

    def generate_json_report(self, report: Series3DReport) -> Path:
        """Generate JSON report for machine-readable analysis.

        Args:
            report: Series3D report data

        Returns:
            Path to generated JSON report

        """
        import json

        report_data = {
            "campaign_name": report.campaign_name,
            "generated_at": report.generated_at.isoformat(),
            "summary": {
                "total_series_fuzzed": report.total_series_fuzzed,
                "total_mutations_applied": report.total_mutations_applied,
                "total_crashes": report.total_crashes,
                "avg_mutations_per_series": report.total_mutations_applied
                / max(report.total_series_fuzzed, 1),
            },
            "strategy_effectiveness": report.get_strategy_effectiveness(),
            "series_details": [
                {
                    "series_uid": s.series_uid,
                    "modality": s.modality,
                    "slice_count": s.slice_count,
                    "total_mutations": s.total_mutations,
                    "strategies_used": s.strategies_used,
                    "affected_slices": s.affected_slices,
                    "coverage_percentage": s.get_coverage_percentage(),
                    "timestamp": s.timestamp.isoformat(),
                }
                for s in report.series_summaries
            ],
            "crashes": report.crash_details,
        }

        # Save JSON report
        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"series3d_report_{timestamp}.json"

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return report_path
