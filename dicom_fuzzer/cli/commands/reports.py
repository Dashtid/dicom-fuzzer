"""Report subcommand for DICOM Fuzzer.

Thin CLI wrapper around dicom_fuzzer.core.reporting.report_utils.
Report generation logic lives in core/reporting/ — this module is
the CLI entry point only.

Usage:
    dicom-fuzzer report session.json
    dicom-fuzzer report session.json --output custom_report.html
    dicom-fuzzer report session.json --keep-json
    dicom-fuzzer report session.json --legacy
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import ModuleType

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.core.reporting.report_utils import (
    create_html_report,
    generate_reports,
)

# Imported at module level so existing mock patch targets continue to resolve:
#   "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
#   "dicom_fuzzer.cli.commands.reports._matplotlib"
#   "dicom_fuzzer.cli.commands.reports.jinja2"
_matplotlib: ModuleType | None
try:
    import matplotlib as _mpl

    _ = _mpl.pyplot
    _matplotlib = _mpl
except ImportError:
    _matplotlib = None

jinja2: ModuleType | None
try:
    import jinja2 as _jinja2

    jinja2 = _jinja2
except ImportError:
    jinja2 = None

try:
    from dicom_fuzzer.core.reporting.enhanced_reporter import EnhancedReportGenerator
except ImportError:
    EnhancedReportGenerator = None  # type: ignore[misc,assignment]

__all__ = [
    "ReportsCommand",
    "create_html_report",
    "generate_reports",
    "main",
]


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


class ReportsCommand(SubcommandBase):
    """Report generation subcommand."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand."""
        if not args.session_json.exists():
            print(f"[-] Error: File not found: {args.session_json}", file=sys.stderr)
            return 1

        try:
            if args.legacy:
                create_html_report(
                    str(args.session_json),
                    str(args.output) if args.output else None,
                )
            else:
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
