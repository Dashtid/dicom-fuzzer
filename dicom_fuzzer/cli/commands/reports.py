"""Unified Report Generator for DICOM Fuzzer.

Generates comprehensive HTML and JSON reports from fuzzing session data.
Consolidates generate_report.py and create_html_report.py functionality.

Usage:
    dicom-fuzzer report session.json
    dicom-fuzzer report session.json --output custom_report.html
    dicom-fuzzer report session.json --keep-json

For legacy HTML report format, use --legacy flag.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dicom_fuzzer.cli.base import SubcommandBase

# Import matplotlib at module level for test compatibility
_matplotlib: ModuleType | None
try:
    import matplotlib as _mpl

    _ = _mpl.pyplot  # Access pyplot to trigger backend initialization
    _matplotlib = _mpl
except ImportError:
    _matplotlib = None

# Import jinja2 at module level for test compatibility
jinja2: ModuleType | None
try:
    import jinja2 as _jinja2

    jinja2 = _jinja2
except ImportError:
    jinja2 = None

# Import EnhancedReportGenerator at module level for test compatibility
try:
    from dicom_fuzzer.core.reporting.enhanced_reporter import EnhancedReportGenerator
except ImportError:
    EnhancedReportGenerator = None  # type: ignore[misc,assignment]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for report subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer report",
        description="Generate comprehensive HTML reports from fuzzing session data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate HTML report from session JSON
  dicom-fuzzer report session_fuzzing_20241005_143022.json

  # Specify custom output path
  dicom-fuzzer report session.json --output my_report.html

  # Keep JSON alongside HTML
  dicom-fuzzer report session.json --keep-json

  # Use legacy HTML format (hardcoded template)
  dicom-fuzzer report session.json --legacy

The generated HTML report includes:
  - Session summary with statistics
  - Detailed crash forensics
  - Complete mutation history for each crash
  - Reproduction instructions
  - Interactive drill-down views
        """,
    )

    parser.add_argument(
        "session_json",
        type=Path,
        help="Path to session JSON file",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output path for HTML report (auto-generated if not specified)",
    )

    parser.add_argument(
        "--keep-json",
        "-k",
        action="store_true",
        help="Keep JSON file alongside HTML report",
    )

    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Use legacy HTML template format",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


# ============================================================================
# Primary API (Modern - uses EnhancedReportGenerator)
# ============================================================================


def generate_reports(
    session_json_path: Path,
    output_html: Path | None = None,
    keep_json: bool = False,
) -> Path:
    """Generate HTML (and optionally JSON) reports from session data.

    This is the primary API for report generation, using the modern
    EnhancedReportGenerator for rich HTML output.

    Args:
        session_json_path: Path to session JSON file
        output_html: Path for HTML output (auto-generated if None)
        keep_json: Whether to keep the JSON alongside HTML

    Returns:
        Path to the generated HTML report

    """
    print(f"[*] Loading session data from: {session_json_path}")

    # Load session data
    with open(session_json_path, encoding="utf-8") as f:
        session_data = json.load(f)

    # Initialize reporter
    reporter = EnhancedReportGenerator(output_dir="./artifacts/reports")

    # Generate HTML report
    print("[*] Generating HTML report...")
    html_path = reporter.generate_html_report(session_data, output_html)
    print(f"[+] HTML report generated: {html_path}")

    # Print summary
    stats = session_data.get("statistics", {})
    crashes = session_data.get("crashes", [])

    print("\n" + "=" * 60)
    print("REPORT SUMMARY")
    print("=" * 60)
    print(f"Files Fuzzed:      {stats.get('files_fuzzed', 0)}")
    print(f"Mutations Applied: {stats.get('mutations_applied', 0)}")
    print(f"Crashes:           {stats.get('crashes', 0)}")
    print(f"Hangs:             {stats.get('hangs', 0)}")
    print(f"Successes:         {stats.get('successes', 0)}")
    print("=" * 60)

    if crashes:
        print(f"\n[!] {len(crashes)} crash(es) detected - see report for details")
        print("\nCrash Artifacts:")
        for crash in crashes:
            print(f"  - {crash.get('crash_id')}")
            print(f"    Sample: {crash.get('preserved_sample_path')}")
            print(f"    Log:    {crash.get('crash_log_path')}")
            if crash.get("reproduction_command"):
                print(f"    Repro:  {crash['reproduction_command']}")
            print()

    print(f"\n[i] Full report available at: {html_path}")

    if keep_json:
        print(f"[i] JSON data saved at: {session_json_path}")

    return html_path


# ============================================================================
# Legacy API (for backward compatibility with create_html_report.py)
# ============================================================================


def create_html_report(json_path: str, html_path: str | None = None) -> str:
    """Create HTML report from JSON fuzzing results (legacy format).

    This function uses a hardcoded HTML template for backward compatibility.
    For new code, prefer generate_reports() which uses EnhancedReportGenerator.

    Args:
        json_path: Path to JSON report file
        html_path: Output path for HTML (defaults to json_path with .html extension)

    Returns:
        Path to the generated HTML report

    """
    # Read JSON report
    with open(json_path) as f:
        report = json.load(f)

    # Default HTML path
    if html_path is None:
        html_path = json_path.replace(".json", ".html")

    # Get stats
    stats = report["statistics"]
    config = report["configuration"]

    # Calculate total tests
    total_tests = (
        stats.get("viewer_hangs", 0)
        + stats.get("viewer_crashes", 0)
        + stats.get("viewer_success", 0)
    )
    hang_rate = stats.get("hang_rate", 0)

    # Determine alert type
    alert_html = ""
    if hang_rate == 100.0:
        alert_html = """<div class="alert">
            <strong>[!!] CRITICAL SECURITY FINDING:</strong> 100% hang rate detected!
            This indicates a serious Denial of Service (DoS) vulnerability in the DICOM viewer.
        </div>"""
    elif hang_rate >= 50:
        alert_html = f"""<div class="warning">
            <strong>[!] WARNING:</strong> High hang rate ({hang_rate:.1f}%) detected.
            This may indicate a DoS vulnerability.
        </div>"""
    elif total_tests > 0:
        alert_html = f"""<div class="success">
            <strong>[i] INFO:</strong> Hang rate: {hang_rate:.1f}%
        </div>"""

    html_content = _generate_legacy_html(report, stats, config, alert_html, hang_rate)

    # Write HTML report
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report created: {html_path}")
    return html_path


def _generate_legacy_html(
    report: dict[str, Any],
    stats: dict[str, Any],
    config: dict[str, Any],
    alert_html: str,
    hang_rate: float,
) -> str:
    """Generate legacy HTML content."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DICOM Viewer Fuzzing Report</title>
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
            border-radius: 8px;
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
            font-size: 2.5em;
            font-weight: bold;
            color: #2980b9;
        }}
        .metric-label {{
            color: #7f8c8d;
            margin-top: 10px;
            font-size: 0.9em;
        }}
        .alert {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .warning {{ background: #f39c12; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .success {{ background: #27ae60; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .config-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .config-table th, .config-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .config-table th {{
            background: #34495e;
            color: white;
        }}
        .timestamp {{ color: #95a5a6; font-size: 0.9em; }}
        code {{ background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
        .severity-high {{ color: #e74c3c; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DICOM Viewer Security Assessment</h1>
        <p class="timestamp">Generated: {report["timestamp"]}</p>
        {alert_html}
        <h2>Test Configuration</h2>
        <table class="config-table">
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td><strong>Target Application</strong></td><td><code>{config.get("viewer_path", "N/A")}</code></td></tr>
            <tr><td><strong>Input Directory</strong></td><td><code>{config.get("input_dir", "N/A")}</code></td></tr>
            <tr><td><strong>Output Directory</strong></td><td><code>{config.get("output_dir", "N/A")}</code></td></tr>
            <tr><td><strong>Timeout (seconds)</strong></td><td>{config.get("timeout", "N/A")}</td></tr>
        </table>
        <h2>Test Results</h2>
        <div class="summary-grid">
            <div class="metric-card"><div class="metric-value">{stats.get("files_processed", 0)}</div><div class="metric-label">Files Processed</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("files_fuzzed", 0)}</div><div class="metric-label">Files Fuzzed</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("files_generated", 0)}</div><div class="metric-label">Files Generated</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("viewer_crashes", 0)}</div><div class="metric-label">Crashes</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("viewer_hangs", 0)}</div><div class="metric-label">Hangs/Timeouts</div></div>
            <div class="metric-card"><div class="metric-value">{hang_rate:.1f}%</div><div class="metric-label">Hang Rate</div></div>
        </div>
        <h2>Recommendations</h2>
        <ul>
            <li>Investigate hang logs in <code>{config.get("output_dir", "output")}</code></li>
            <li>Test fuzzed files manually to reproduce and debug</li>
            <li>Implement robust input validation for DICOM file parsing</li>
            <li>Add timeout mechanisms in the DICOM parser</li>
        </ul>
        <p class="timestamp">Report generated by DICOM Fuzzer.</p>
    </div>
</body>
</html>
"""


# ============================================================================
# CLI Entry Point
# ============================================================================


class ReportsCommand(SubcommandBase):
    """Report generation subcommand."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand."""
        # Validate input file
        if not args.session_json.exists():
            print(f"[-] Error: File not found: {args.session_json}", file=sys.stderr)
            return 1

        try:
            if args.legacy:
                # Use legacy HTML template
                create_html_report(
                    str(args.session_json),
                    str(args.output) if args.output else None,
                )
            else:
                # Use modern EnhancedReportGenerator
                generate_reports(
                    session_json_path=args.session_json,
                    output_html=args.output,
                    keep_json=args.keep_json,
                )
            return 0

        except json.JSONDecodeError as e:
            print(f"[-] Error: Invalid JSON file: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"[-] Error generating report: {e}", file=sys.stderr)
            if args.verbose:
                import traceback

                traceback.print_exc()
            return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for report subcommand."""
    return ReportsCommand.main(argv)


if __name__ == "__main__":
    sys.exit(main())
