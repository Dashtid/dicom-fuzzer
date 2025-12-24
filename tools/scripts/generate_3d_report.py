#!/usr/bin/env python3
r"""Generate 3D DICOM Series Fuzzing Reports

This CLI tool generates comprehensive reports for 3D DICOM series fuzzing campaigns,
including HTML reports, JSON exports, and interactive visualizations.

USAGE:
    python scripts/generate_3d_report.py --campaign-name "My Campaign" --output-dir ./reports

FEATURES:
    - HTML reports with beautiful CSS styling
    - JSON exports for CI/CD integration
    - Interactive Plotly charts (strategy effectiveness, crash trends, coverage heatmaps)
    - Static Matplotlib charts (PNG/SVG for print and documentation)
    - Performance analytics and recommendations

Example:
    # Generate report from fuzzing session data
    python scripts/generate_3d_report.py \\
        --campaign-name "Phase 5 Testing" \\
        --series-count 10 \\
        --mutation-count 500 \\
        --output-dir ./reports \\
        --format html,json,charts

SECURITY NOTICE:
This tool is for DEFENSIVE security testing only.
- Use ONLY on systems you own or have permission to test
- Never use on production medical systems
- Ensure test data contains NO patient information

"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.analytics.campaign_analytics import (
    CampaignAnalyzer,
    PerformanceMetrics,
)
from dicom_fuzzer.analytics.visualization import FuzzingVisualizer
from dicom_fuzzer.core.series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)
from dicom_fuzzer.core.statistics import MutationStatistics
from dicom_fuzzer.strategies.series_mutator import SeriesMutationStrategy
from dicom_fuzzer.utils.identifiers import generate_timestamp_id
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class Report3DGenerator:
    """CLI tool for generating 3D series fuzzing reports.

    Integrates all Phase 5 components to create comprehensive reports.
    """

    def __init__(self, output_dir: str = "./artifacts/reports"):
        """Initialize report generator.

        Args:
            output_dir: Directory to save generated reports

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.report_gen = Series3DReportGenerator(str(self.output_dir))
        self.visualizer = FuzzingVisualizer(str(self.output_dir / "charts"))
        self.analyzer = CampaignAnalyzer()

    def create_demo_report(
        self, campaign_name: str, series_count: int = 10, mutation_count: int = 500
    ) -> Series3DReport:
        """Create a demonstration report with synthetic data.

        Args:
            campaign_name: Name of the campaign
            series_count: Number of series to simulate
            mutation_count: Total number of mutations to simulate

        Returns:
            Series3DReport object with demo data

        """
        logger.info(f"Creating demo report: {campaign_name}")
        logger.info(f"  Series: {series_count}, Mutations: {mutation_count}")

        report = Series3DReport(campaign_name=campaign_name)

        # Available strategies
        strategies = [
            SeriesMutationStrategy.METADATA_CORRUPTION.value,
            SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
            SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value,
            SeriesMutationStrategy.GRADIENT_MUTATION.value,
            SeriesMutationStrategy.INCONSISTENCY_INJECTION.value,
        ]

        # Generate series summaries
        import random

        random.seed(42)  # Reproducible demo data

        for i in range(series_count):
            series_uid = f"1.2.840.{10008 + i}.5.1.4.1.1.2.{i}"
            modality = random.choice(["CT", "MR", "PT"])
            slice_count = random.randint(20, 100)

            summary = SeriesMutationSummary(
                series_uid=series_uid,
                modality=modality,
                slice_count=slice_count,
                total_mutations=0,
            )

            # Distribute mutations across strategies
            mutations_for_series = mutation_count // series_count
            for _ in range(mutations_for_series):
                strategy = random.choice(strategies)
                severity = random.choice(["minimal", "moderate", "aggressive"])
                slice_index = random.randint(0, slice_count - 1)

                # Simulate mutation record (simplified)
                class FakeMutationRecord:
                    def __init__(self, strategy, severity, slice_index):
                        self.strategy = strategy
                        self.severity = severity
                        self.slice_index = slice_index

                summary.add_mutation(
                    FakeMutationRecord(strategy, severity, slice_index)
                )

            report.add_series_summary(summary)

        # Simulate crashes (5% crash rate)
        report.total_crashes = int(mutation_count * 0.05)

        logger.info(
            f"[+] Generated report with {report.total_series_fuzzed} series, "
            f"{report.total_mutations_applied} mutations, {report.total_crashes} crashes"
        )

        return report

    def generate_full_report(
        self,
        report: Series3DReport,
        formats: list[str] = None,
        include_analytics: bool = True,
        include_visualizations: bool = True,
    ) -> dict[str, Path]:
        """Generate full report with all requested formats.

        Args:
            report: Series3DReport to generate from
            formats: List of formats ('html', 'json', 'charts')
            include_analytics: Include analytics and recommendations
            include_visualizations: Generate charts

        Returns:
            Dictionary mapping format names to output paths

        """
        if formats is None:
            formats = ["html", "json"]

        output_paths = {}

        # Generate HTML report
        if "html" in formats:
            logger.info("[+] Generating HTML report...")
            html_path = self.report_gen.generate_html_report(report)
            output_paths["html"] = html_path
            logger.info(f"    Saved to: {html_path}")

        # Generate JSON report
        if "json" in formats:
            logger.info("[+] Generating JSON report...")
            json_path = self.report_gen.generate_json_report(report)
            output_paths["json"] = json_path
            logger.info(f"    Saved to: {json_path}")

        # Generate analytics
        if include_analytics:
            logger.info("[+] Generating campaign analytics...")
            analytics_path = self.generate_analytics_report(report)
            output_paths["analytics"] = analytics_path
            logger.info(f"    Saved to: {analytics_path}")

        # Generate visualizations
        if include_visualizations and "charts" in formats:
            logger.info("[+] Generating visualizations...")
            chart_paths = self.generate_visualizations(report)
            output_paths.update(chart_paths)
            logger.info(f"    Generated {len(chart_paths)} charts")

        return output_paths

    def generate_analytics_report(self, report: Series3DReport) -> Path:
        """Generate analytics report with recommendations.

        Args:
            report: Series3DReport to analyze

        Returns:
            Path to analytics JSON file

        """
        # Create synthetic mutation statistics
        mutation_stats = []
        strategy_effectiveness = report.get_strategy_effectiveness()

        for strategy, metrics in strategy_effectiveness.items():
            stat = MutationStatistics(
                strategy_name=strategy,
                times_used=int(metrics["usage_count"]),
                crashes_found=max(
                    1, int(metrics["usage_count"] * 0.05)
                ),  # 5% crash rate
                validation_failures=max(
                    1, int(metrics["usage_count"] * 0.1)
                ),  # 10% failures
                total_duration=metrics["usage_count"] * 0.1,  # 0.1 sec per mutation
            )
            mutation_stats.append(stat)

        # Analyze strategy effectiveness
        effectiveness = self.analyzer.analyze_strategy_effectiveness(
            report, mutation_stats
        )

        # Calculate coverage correlations
        for strategy, metrics in effectiveness.items():
            coverage_increase = metrics["coverage_contribution"] * 0.5  # Demo scaling
            unique_paths = int(metrics["usage_count"] * 0.2)  # Demo scaling
            crashes = int(metrics["usage_count"] * 0.05)

            self.analyzer.calculate_coverage_correlation(
                strategy=strategy,
                coverage_increase=coverage_increase,
                unique_paths=unique_paths,
                crashes_found=crashes,
                mutations_applied=int(metrics["usage_count"]),
            )

        # Generate recommendations
        self.analyzer.generate_recommendations()

        # Export analytics
        timestamp = generate_timestamp_id()
        analytics_path = self.output_dir / f"analytics_{timestamp}.json"

        self.analyzer.export_to_json(analytics_path)

        return analytics_path

    def generate_visualizations(self, report: Series3DReport) -> dict[str, Path]:
        """Generate all visualization charts.

        Args:
            report: Series3DReport to visualize

        Returns:
            Dictionary mapping chart names to paths

        """
        chart_paths = {}

        # Strategy effectiveness chart (both static and interactive)
        effectiveness_data = report.get_strategy_effectiveness()

        # PNG version
        strategy_png = self.visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="png"
        )
        chart_paths["strategy_effectiveness_png"] = strategy_png

        # HTML version
        strategy_html = self.visualizer.plot_strategy_effectiveness(
            effectiveness_data, output_format="html"
        )
        chart_paths["strategy_effectiveness_html"] = strategy_html

        # Coverage heatmap (if coverage data available)
        if self.analyzer.coverage_data:
            coverage_png = self.visualizer.plot_coverage_heatmap(
                self.analyzer.coverage_data, output_format="png"
            )
            chart_paths["coverage_heatmap_png"] = coverage_png

            coverage_html = self.visualizer.plot_coverage_heatmap(
                self.analyzer.coverage_data, output_format="html"
            )
            chart_paths["coverage_heatmap_html"] = coverage_html

        # Performance dashboard (demo data)
        perf_metrics = PerformanceMetrics(
            mutations_per_second=50.0,
            peak_memory_mb=500.0,
            avg_memory_mb=300.0,
            cpu_utilization=75.0,
            disk_io_mb_per_sec=10.0,
            cache_hit_rate=80.0,
        )

        perf_png = self.visualizer.plot_performance_dashboard(
            perf_metrics, output_format="png"
        )
        chart_paths["performance_dashboard_png"] = perf_png

        perf_html = self.visualizer.plot_performance_dashboard(
            perf_metrics, output_format="html"
        )
        chart_paths["performance_dashboard_html"] = perf_html

        return chart_paths


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Generate comprehensive 3D DICOM series fuzzing reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--campaign-name",
        type=str,
        default="3D DICOM Fuzzing Campaign",
        help="Name of the fuzzing campaign",
    )

    parser.add_argument(
        "--series-count",
        type=int,
        default=10,
        help="Number of series to include in demo report (default: 10)",
    )

    parser.add_argument(
        "--mutation-count",
        type=int,
        default=500,
        help="Total number of mutations in demo report (default: 500)",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="./artifacts/reports",
        help="Directory to save generated reports (default: ./reports)",
    )

    parser.add_argument(
        "--format",
        type=str,
        default="html,json,charts",
        help="Output formats: html,json,charts (default: all)",
    )

    parser.add_argument(
        "--no-analytics", action="store_true", help="Disable analytics generation"
    )

    parser.add_argument(
        "--no-visualizations", action="store_true", help="Disable chart generation"
    )

    args = parser.parse_args()

    # Parse formats
    formats = [f.strip() for f in args.format.split(",")]

    # Create report generator
    generator = Report3DGenerator(output_dir=args.output_dir)

    # Generate demo report
    logger.info("=" * 80)
    logger.info("3D DICOM FUZZING REPORT GENERATOR")
    logger.info("=" * 80)

    report = generator.create_demo_report(
        campaign_name=args.campaign_name,
        series_count=args.series_count,
        mutation_count=args.mutation_count,
    )

    # Generate all requested outputs
    output_paths = generator.generate_full_report(
        report,
        formats=formats,
        include_analytics=not args.no_analytics,
        include_visualizations=not args.no_visualizations,
    )

    # Print summary
    logger.info("=" * 80)
    logger.info("REPORT GENERATION COMPLETE")
    logger.info("=" * 80)
    logger.info(f"Campaign: {args.campaign_name}")
    logger.info(f"Series: {report.total_series_fuzzed}")
    logger.info(f"Mutations: {report.total_mutations_applied}")
    logger.info(f"Crashes: {report.total_crashes}")
    logger.info("")
    logger.info("Generated files:")
    for format_name, path in output_paths.items():
        logger.info(f"  {format_name}: {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
