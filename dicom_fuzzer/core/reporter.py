"""Report Generator - HTML and JSON Reports

LEARNING OBJECTIVE: This module demonstrates automated report generation
for fuzzing campaigns, creating both human-readable (HTML) and
machine-readable (JSON) formats.

CONCEPT: Good security tools need clear reporting:
1. HTML for humans - visual, interactive, easy to understand
2. JSON for automation - integrate with CI/CD, ticketing systems
3. Statistics and metrics - understand campaign effectiveness

This enables both manual review and automated processing.
"""

import json
from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer, CrashReport
from dicom_fuzzer.utils.identifiers import generate_timestamp_id


class ReportGenerator:
    """Generates HTML and JSON reports for fuzzing campaigns.

    CONCEPT: Single source of truth for reporting.
    Both HTML and JSON generated from the same data structures.
    """

    def __init__(self, output_dir: str = "./reports"):
        """Initialize report generator.

        Args:
            output_dir: Directory to save reports

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_crash_html_report(
        self, analyzer: CrashAnalyzer, campaign_name: str = "DICOM Fuzzing"
    ) -> Path:
        """Generate HTML report for crash analysis.

        Args:
            analyzer: CrashAnalyzer with crash data
            campaign_name: Name of fuzzing campaign

        Returns:
            Path to generated HTML report

        """
        crashes = analyzer.crashes
        summary = analyzer.get_crash_summary()

        # Generate HTML
        html = self._generate_html_header(campaign_name)
        html += self._generate_summary_section(summary, len(crashes))
        html += self._generate_crash_details_section(crashes)
        html += self._generate_html_footer()

        # Save report
        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"crash_report_{timestamp}.html"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        return report_path

    def generate_crash_json_report(
        self, analyzer: CrashAnalyzer, campaign_name: str = "DICOM Fuzzing"
    ) -> Path:
        """Generate JSON report for crash analysis.

        Args:
            analyzer: CrashAnalyzer with crash data
            campaign_name: Name of fuzzing campaign

        Returns:
            Path to generated JSON report

        """
        crashes = analyzer.crashes
        summary = analyzer.get_crash_summary()

        # Count by severity
        by_severity: dict[str, int] = {}
        for crash in crashes:
            severity = crash.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

        # Build JSON structure
        report_data = {
            "campaign_name": campaign_name,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_crashes": len(crashes),
                "unique_crashes": len({c.crash_hash for c in crashes}),
                "by_type": summary,
                "by_severity": by_severity,
            },
            "crashes": [self._crash_to_dict(crash) for crash in crashes],
        }

        # Save report
        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"crash_report_{timestamp}.json"

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return report_path

    def generate_performance_html_report(
        self, metrics: dict, campaign_name: str = "DICOM Fuzzing"
    ) -> Path:
        """Generate HTML report for performance metrics.

        Args:
            metrics: Performance metrics dictionary
            campaign_name: Name of fuzzing campaign

        Returns:
            Path to generated HTML report

        """
        html = self._generate_html_header(f"{campaign_name} - Performance Report")
        html += self._generate_performance_section(metrics)
        html += self._generate_html_footer()

        # Save report
        timestamp = generate_timestamp_id()
        report_path = self.output_dir / f"performance_report_{timestamp}.html"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        return report_path

    def generate_report(
        self,
        report_data: dict,
        format: str = "json",
        campaign_name: str = "DICOM Fuzzing",
    ) -> Path:
        """Generate a general report (for test compatibility).

        Args:
            report_data: Dictionary with report data
            format: Report format ('json' or 'html')
            campaign_name: Name of fuzzing campaign

        Returns:
            Path to generated report

        """
        timestamp = generate_timestamp_id()

        if format == "json":
            report_path = self.output_dir / f"report_{timestamp}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
        else:  # html
            report_path = self.output_dir / f"report_{timestamp}.html"
            html = self._generate_html_header(campaign_name)
            html += "<div class='section'><h2>Report Data</h2>"
            html += "<table border='1' style='width: 100%; border-collapse: collapse;'>"
            for key, value in report_data.items():
                html += f"<tr><td style='padding: 8px;'><strong>{key}</strong></td><td style='padding: 8px;'>{value}</td></tr>"
            html += "</table></div>"
            html += self._generate_html_footer()
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html)

        return report_path

    def _crash_to_dict(self, crash: CrashReport) -> dict:
        """Convert CrashReport to dictionary."""
        return {
            "crash_type": crash.crash_type.value,
            "severity": crash.severity.value,
            "timestamp": crash.timestamp.isoformat(),
            "test_case_path": crash.test_case_path,
            "crash_hash": crash.crash_hash,
            "exception_type": crash.additional_info.get("exception_type", "Unknown"),
            "exception_message": crash.exception_message,
            "stack_trace": crash.stack_trace,
            "additional_info": crash.additional_info,
        }

    def _generate_html_header(self, title: str) -> str:
        """Generate HTML header with styling."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #2980b9;
        }}
        .metric-label {{
            color: #7f8c8d;
            margin-top: 5px;
        }}
        .crash-item {{
            background: #fff;
            border: 1px solid #ddd;
            border-left: 4px solid #e74c3c;
            margin: 15px 0;
            padding: 15px;
            border-radius: 4px;
        }}
        .crash-critical {{ border-left-color: #c0392b; }}
        .crash-high {{ border-left-color: #e74c3c; }}
        .crash-medium {{ border-left-color: #f39c12; }}
        .crash-low {{ border-left-color: #f1c40f; }}
        .crash-header {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .crash-detail {{
            margin: 5px 0;
            color: #555;
        }}
        .stack-trace {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        .timestamp {{
            color: #95a5a6;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }}
        .badge-critical {{ background: #c0392b; color: white; }}
        .badge-high {{ background: #e74c3c; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #f1c40f; color: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p class="timestamp">Generated: {
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }</p>
"""

    def _generate_html_footer(self) -> str:
        """Generate HTML footer."""
        return """
    </div>
</body>
</html>
"""

    def _generate_summary_section(
        self, summary: dict[str, int], total_crashes: int
    ) -> str:
        """Generate summary section HTML."""
        html = "<h2>Summary</h2>\n<div class='summary-grid'>\n"

        # Total crashes
        html += f"""
        <div class='metric-card'>
            <div class='metric-value'>{total_crashes}</div>
            <div class='metric-label'>Total Crashes</div>
        </div>
"""

        # Crashes by type
        for crash_type, count in summary.items():
            html += f"""
        <div class='metric-card'>
            <div class='metric-value'>{count}</div>
            <div class='metric-label'>{crash_type.replace("_", " ").title()}</div>
        </div>
"""

        html += "</div>\n"
        return html

    def _generate_crash_details_section(self, crashes: list[CrashReport]) -> str:
        """Generate crash details section HTML."""
        if not crashes:
            return "<h2>No crashes found</h2>\n"

        html = "<h2>Crash Details</h2>\n"

        for crash in crashes:
            severity_class = f"crash-{crash.severity.value.lower()}"
            severity_badge = f"badge-{crash.severity.value.lower()}"

            exception_type = crash.additional_info.get("exception_type", "Unknown")
            time_str = crash.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            html += f"""
        <div class='crash-item {severity_class}'>
            <div class='crash-header'>
                <span class='badge {severity_badge}'>
                    {crash.severity.value}
                </span>
                <span class='badge' style='background:#3498db;color:white'>
                    {crash.crash_type.value}
                </span>
                {exception_type}
            </div>
            <div class='crash-detail'>
                <strong>Test Case:</strong> {crash.test_case_path}
            </div>
            <div class='crash-detail'>
                <strong>Time:</strong> {time_str}
            </div>
            <div class='crash-detail'>
                <strong>Hash:</strong> {crash.crash_hash[:16]}...
            </div>
            <div class='crash-detail'>
                <strong>Message:</strong> {crash.exception_message}
            </div>
"""

            if crash.stack_trace:
                html += f"""
            <details>
                <summary><strong>Stack Trace</strong></summary>
                <div class='stack-trace'>{crash.stack_trace[:1000]}</div>
            </details>
"""

            html += "        </div>\n"

        return html

    def _generate_performance_section(self, metrics: dict) -> str:
        """Generate performance metrics section HTML."""
        html = "<h2>Performance Metrics</h2>\n<div class='summary-grid'>\n"

        # Key metrics
        metric_items = [
            ("Files Generated", metrics.get("files_generated", 0)),
            ("Mutations Applied", metrics.get("mutations_applied", 0)),
            (
                "Throughput",
                f"{metrics.get('throughput_per_second', 0):.2f} files/sec",
            ),
            (
                "Avg Time/File",
                f"{metrics.get('avg_time_per_file', 0):.3f}s",
            ),
            ("Peak Memory", f"{metrics.get('peak_memory_mb', 0):.1f} MB"),
            ("Avg CPU", f"{metrics.get('avg_cpu_percent', 0):.1f}%"),
        ]

        for label, value in metric_items:
            html += f"""
        <div class='metric-card'>
            <div class='metric-value'>{value}</div>
            <div class='metric-label'>{label}</div>
        </div>
"""

        html += "</div>\n"

        # Strategy usage
        if metrics.get("strategy_usage"):
            html += "<h3>Strategy Usage</h3>\n"
            html += (
                "<div style='padding:15px; background:#ecf0f1; border-radius:4px;'>\n"
            )
            for strategy, count in metrics["strategy_usage"].items():
                percentage = (
                    (count / metrics.get("mutations_applied", 1)) * 100
                    if metrics.get("mutations_applied")
                    else 0
                )
                html += (
                    f"<div style='margin:5px 0;'>"
                    f"<strong>{strategy}:</strong> {count} "
                    f"({percentage:.1f}%)</div>\n"
                )

            html += "</div>\n"

        return html
