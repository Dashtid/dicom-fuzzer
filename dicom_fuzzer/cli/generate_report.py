#!/usr/bin/env python3
"""Unified Report Generator - Generate Reports from Fuzzing Session Data

This tool generates comprehensive HTML and JSON reports from fuzzing session data.
It supports both new enhanced session format and legacy report formats.

Usage:
    # Generate report from session JSON
    python generate_report.py session_report.json

    # Generate report with custom output path
    python generate_report.py session_report.json --output custom_report.html

    # Generate both HTML and keep JSON
    python generate_report.py session_report.json --keep-json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import matplotlib at module level for test compatibility
# Using types.ModuleType | None for type safety
from types import ModuleType

from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

_matplotlib: ModuleType | None
try:
    import matplotlib as _mpl
    import matplotlib.pyplot as _plt  # noqa: F401 - imported for backend initialization

    _matplotlib = _mpl
    del _plt  # Clean up namespace, only needed for side effect
except ImportError:
    _matplotlib = None


def generate_reports(
    session_json_path: Path,
    output_html: Path | None = None,
    keep_json: bool = False,
) -> Path:
    """Generate HTML (and optionally JSON) reports from session data.

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


def main() -> None:
    """Generate comprehensive HTML reports from fuzzing session data."""
    parser = argparse.ArgumentParser(
        description="Generate comprehensive HTML reports from fuzzing session data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate HTML report from session JSON
  python generate_report.py reports/json/session_fuzzing_20241005_143022.json

  # Specify custom output path
  python generate_report.py session.json --output my_report.html

  # Keep JSON alongside HTML
  python generate_report.py session.json --keep-json

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

    args = parser.parse_args()

    # Validate input file
    if not args.session_json.exists():
        print(f"[-] Error: File not found: {args.session_json}", file=sys.stderr)
        sys.exit(1)

    try:
        # Generate reports
        generate_reports(
            session_json_path=args.session_json,
            output_html=args.output,
            keep_json=args.keep_json,
        )

    except json.JSONDecodeError as e:
        print(f"[-] Error: Invalid JSON file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error generating report: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


# Additional functions for test compatibility


def generate_json_report(data: dict[str, Any], output_file: str) -> None:
    """Generate JSON report from campaign data.

    Args:
        data: Campaign data dictionary
        output_file: Output file path for JSON report

    """
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def generate_csv_report(crashes: list[dict[str, Any]], output_file: str) -> None:
    """Generate CSV report from crash data.

    Args:
        crashes: List of crash dictionaries
        output_file: Output file path for CSV report

    """
    import csv

    if crashes:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=crashes[0].keys())
            writer.writeheader()
            writer.writerows(crashes)


def generate_coverage_chart(coverage_data: dict[str, Any], output_file: str) -> None:
    """Generate coverage chart from coverage timeline data.

    Args:
        coverage_data: Dictionary mapping iterations to coverage values
        output_file: Output file path for chart image

    """
    if _matplotlib is not None:
        iterations = list(coverage_data.keys())
        coverage = list(coverage_data.values())

        _matplotlib.pyplot.figure(figsize=(10, 6))
        _matplotlib.pyplot.plot(iterations, coverage)
        _matplotlib.pyplot.xlabel("Iteration")
        _matplotlib.pyplot.ylabel("Coverage")
        _matplotlib.pyplot.title("Coverage Over Time")
        _matplotlib.pyplot.savefig(output_file)
        _matplotlib.pyplot.close()
    else:
        # Fallback: create empty file if matplotlib not available
        Path(output_file).touch()


def generate_markdown_report(data: dict[str, Any], output_file: str) -> None:
    """Generate Markdown report from campaign data.

    Args:
        data: Campaign data dictionary with title, summary, findings
        output_file: Output file path for markdown report

    """
    lines = [f"# {data['title']}", ""]

    if "summary" in data:
        lines.append("## Summary")
        for key, value in data["summary"].items():
            lines.append(f"- **{key}**: {value}")
        lines.append("")

    if "findings" in data:
        lines.append("## Findings")
        for finding in data["findings"]:
            lines.append(f"- **{finding['severity']}**: {finding['description']}")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
