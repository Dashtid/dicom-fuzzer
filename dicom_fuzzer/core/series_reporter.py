"""Series3D Reporter - Enhanced Reporting for 3D DICOM Series Fuzzing.

Provides specialized reporting for 3D series fuzzing campaigns, tracking
multi-slice mutations and spatial integrity issues.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dicom_fuzzer.strategies.series_mutator import (
    SeriesMutationRecord,
)
from dicom_fuzzer.utils.identifiers import generate_timestamp_id


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
    timestamp: datetime = field(default_factory=datetime.now)

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
    generated_at: datetime = field(default_factory=datetime.now)

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
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{campaign_name} - 3D Series Fuzzing Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
        }}
        h1 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 2.5em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #764ba2;
            margin-top: 30px;
            margin-bottom: 15px;
            font-size: 1.8em;
        }}
        h3 {{
            color: #555;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 1.3em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-card .label {{
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 5px;
        }}
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-minimal {{ background: #4CAF50; color: white; }}
        .badge-moderate {{ background: #FF9800; color: white; }}
        .badge-aggressive {{ background: #f44336; color: white; }}
        .badge-extreme {{ background: #9C27B0; color: white; }}
        .progress-bar {{
            background: #e0e0e0;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            transition: width 0.3s ease;
        }}
        .timestamp {{
            color: #999;
            font-size: 0.9em;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{campaign_name}</h1>
        <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
"""

    def _generate_summary_section(self, report: Series3DReport) -> str:
        """Generate summary statistics section."""
        return f"""
        <h2>[+] Campaign Summary</h2>
        <div class="summary-grid">
            <div class="stat-card">
                <div class="label">Series Fuzzed</div>
                <div class="value">{report.total_series_fuzzed}</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Mutations</div>
                <div class="value">{report.total_mutations_applied}</div>
            </div>
            <div class="stat-card">
                <div class="label">Crashes Found</div>
                <div class="value">{report.total_crashes}</div>
            </div>
            <div class="stat-card">
                <div class="label">Avg Mutations/Series</div>
                <div class="value">{report.total_mutations_applied / max(report.total_series_fuzzed, 1):.1f}</div>
            </div>
        </div>
"""

    def _generate_strategy_effectiveness_section(self, report: Series3DReport) -> str:
        """Generate strategy effectiveness analysis section."""
        effectiveness = report.get_strategy_effectiveness()

        if not effectiveness:
            return (
                "<h2>[+] Strategy Effectiveness</h2><p>No strategy data available.</p>"
            )

        html = "<h2>[+] Strategy Effectiveness</h2>"
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
        html = "<h2>[+] Series Details</h2>"

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
        html = f"<h2>[!] Crashes Found ({report.total_crashes})</h2>"

        if report.total_crashes == 0:
            return html + "<p>No crashes detected during this campaign.</p>"

        # Crash details would be populated from crash analyzer integration
        html += "<p>Crash details integration pending...</p>"
        return html

    def _generate_html_footer(self) -> str:
        """Generate HTML footer."""
        return """
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
