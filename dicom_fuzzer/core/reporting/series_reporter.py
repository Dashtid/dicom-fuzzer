"""Series3D Reporter - Enhanced Reporting for 3D DICOM Series Fuzzing.

Provides specialized reporting for 3D series fuzzing campaigns, tracking
multi-slice mutations and spatial integrity issues.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.utils.identifiers import generate_timestamp_id

if TYPE_CHECKING:
    from dicom_fuzzer.attacks.series.series_mutator import SeriesMutationRecord


@dataclass
class SeriesMutationSummary:
    """Summary of mutations applied to a DICOM series."""

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
        strategy = record.strategy
        self.strategies_used[strategy] = self.strategies_used.get(strategy, 0) + 1
        if (
            record.slice_index is not None
            and record.slice_index not in self.affected_slices
        ):
            self.affected_slices.append(record.slice_index)
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
    """Comprehensive report for a 3D series fuzzing campaign."""

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
        """Calculate effectiveness metrics for each mutation strategy."""
        strategy_stats: dict[str, dict[str, int]] = {}
        total_series = len(self.series_summaries)
        if total_series == 0:
            return {}

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

        return {
            strategy: {
                "usage_count": float(stats["usage_count"]),
                "avg_mutations_per_series": stats["total_mutations"]
                / stats["series_count"],
                "series_coverage": (stats["series_count"] / total_series) * 100,
            }
            for strategy, stats in strategy_stats.items()
        }


class Series3DReportGenerator:
    """Generates markdown and JSON reports for 3D DICOM series fuzzing campaigns."""

    def __init__(self, output_dir: str = "./artifacts/reports"):
        """Initialize Series3D report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, report: Series3DReport) -> Path:
        """Generate markdown report for 3D series fuzzing."""
        md = self._generate_document(report)
        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"series3d_report_{timestamp}.md"
        report_path.write_text(md, encoding="utf-8")
        return report_path

    # Alias for backward compatibility
    generate_html_report = generate_report

    def _generate_document(self, report: Series3DReport) -> str:
        """Generate the full markdown document."""
        generated_at = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        avg_muts = report.total_mutations_applied / max(report.total_series_fuzzed, 1)

        parts = [
            f"# {report.campaign_name}",
            "",
            f"3D Series Fuzzing Report -- Generated: {generated_at}",
            "",
            "## Campaign Summary",
            "",
            "| Metric | Value |",
            "| ------ | ----- |",
            f"| Series Fuzzed | {report.total_series_fuzzed} |",
            f"| Total Mutations | {report.total_mutations_applied} |",
            f"| Crashes Found | {report.total_crashes} |",
            f"| Avg Mutations/Series | {avg_muts:.1f} |",
            "",
        ]

        parts.append(self._strategy_effectiveness_section(report))
        parts.append(self._series_details_section(report))
        parts.append(self._crash_section(report))

        return "\n".join(parts)

    def _strategy_effectiveness_section(self, report: Series3DReport) -> str:
        """Generate strategy effectiveness analysis."""
        effectiveness = report.get_strategy_effectiveness()
        if not effectiveness:
            return "## Strategy Effectiveness\n\nNo strategy data available.\n"

        lines = [
            "## Strategy Effectiveness",
            "",
            "| Strategy | Usage Count | Avg Mutations/Series | Series Coverage |",
            "| -------- | ----------- | -------------------- | --------------- |",
        ]
        for strategy, metrics in sorted(
            effectiveness.items(), key=lambda x: x[1]["usage_count"], reverse=True
        ):
            lines.append(
                f"| **{strategy}** "
                f"| {int(metrics['usage_count'])} "
                f"| {metrics['avg_mutations_per_series']:.2f} "
                f"| {metrics['series_coverage']:.1f}% |"
            )
        lines.append("")
        return "\n".join(lines)

    def _series_details_section(self, report: Series3DReport) -> str:
        """Generate detailed series information."""
        if not report.series_summaries:
            return "## Series Details\n\nNo series data available.\n"

        lines = [
            "## Series Details",
            "",
            "| Series UID | Modality | Slices | Mutations | Coverage |",
            "| ---------- | -------- | ------ | --------- | -------- |",
        ]
        for s in report.series_summaries:
            coverage = s.get_coverage_percentage()
            lines.append(
                f"| `{s.series_uid[:20]}...` "
                f"| {s.modality} "
                f"| {s.slice_count} "
                f"| {s.total_mutations} "
                f"| {coverage:.1f}% |"
            )
        lines.append("")
        return "\n".join(lines)

    def _crash_section(self, report: Series3DReport) -> str:
        """Generate crash information."""
        lines = [f"## Crashes Found ({report.total_crashes})", ""]
        if report.total_crashes == 0:
            lines.append("No crashes detected during this campaign.")
        else:
            lines.append("Crash details integration pending...")
        lines.append("")
        return "\n".join(lines)

    def generate_json_report(self, report: Series3DReport) -> Path:
        """Generate JSON report for machine-readable analysis."""
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

        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"series3d_report_{timestamp}.json"
        report_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        return report_path
