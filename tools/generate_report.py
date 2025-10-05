#!/usr/bin/env python3
"""
Unified Report Generator - Generate Reports from Fuzzing Session Data

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

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.enhanced_reporter import EnhancedReportGenerator  # noqa: E402


def generate_reports(
    session_json_path: Path,
    output_html: Path = None,
    keep_json: bool = False,
):
    """
    Generate HTML (and optionally JSON) reports from session data.

    Args:
        session_json_path: Path to session JSON file
        output_html: Path for HTML output (auto-generated if None)
        keep_json: Whether to keep the JSON alongside HTML
    """
    print(f"📊 Loading session data from: {session_json_path}")

    # Load session data
    with open(session_json_path, "r", encoding="utf-8") as f:
        session_data = json.load(f)

    # Initialize reporter
    reporter = EnhancedReportGenerator(output_dir="./reports")

    # Generate HTML report
    print("🎨 Generating HTML report...")
    html_path = reporter.generate_html_report(session_data, output_html)
    print(f"✅ HTML report generated: {html_path}")

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
        print(f"\n⚠️  {len(crashes)} crash(es) detected - see report for details")
        print("\nCrash Artifacts:")
        for crash in crashes:
            print(f"  • {crash.get('crash_id')}")
            print(f"    Sample: {crash.get('preserved_sample_path')}")
            print(f"    Log:    {crash.get('crash_log_path')}")
            if crash.get("reproduction_command"):
                print(f"    Repro:  {crash['reproduction_command']}")
            print()

    print(f"\n📄 Full report available at: {html_path}")

    if keep_json:
        print(f"📄 JSON data saved at: {session_json_path}")

    return html_path


def main():
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
        print(f"❌ Error: File not found: {args.session_json}", file=sys.stderr)
        sys.exit(1)

    try:
        # Generate reports
        generate_reports(
            session_json_path=args.session_json,
            output_html=args.output,
            keep_json=args.keep_json,
        )

    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error generating report: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
