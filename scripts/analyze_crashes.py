#!/usr/bin/env python3
"""Standalone Crash Analysis Tool

Batch analyze crashes from a fuzzing campaign and generate triage reports.

USAGE:
    python scripts/analyze_crashes.py ./crashes --output triage.csv
    python scripts/analyze_crashes.py ./crashes --json --output triage.json
    python scripts/analyze_crashes.py ./crashes --html --output triage.html

FEATURES:
    - Batch crash triage (severity, exploitability, priority)
    - CSV/JSON/HTML output formats
    - Sort by priority score
    - Filter by severity level
"""

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.core.crash_triage import CrashTriageEngine
from dicom_fuzzer.core.fuzzing_session import CrashRecord

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class CrashAnalyzer:
    """Batch crash analyzer with triage support."""

    def __init__(self, crash_dir: Path):
        """Initialize crash analyzer.

        Args:
            crash_dir: Directory containing crash samples

        """
        self.crash_dir = Path(crash_dir)
        self.triage_engine = CrashTriageEngine()
        self.results: list[dict] = []

    def analyze_crashes(self, file_pattern: str = "*.dcm") -> list[dict]:
        """Analyze all crashes in directory.

        Args:
            file_pattern: Glob pattern for crash files

        Returns:
            List of crash analysis results

        """
        crash_files = list(self.crash_dir.glob(file_pattern))

        if not crash_files:
            logger.warning(
                f"No crash files found in {self.crash_dir} with pattern {file_pattern}"
            )
            return []

        logger.info(f"Found {len(crash_files)} crash files to analyze")

        for crash_file in crash_files:
            try:
                # Create minimal CrashRecord for triage
                # In real scenario, we'd load more context from crash logs
                crash_record = CrashRecord(
                    crash_id=crash_file.stem,
                    fuzzed_file_id=crash_file.stem,
                    fuzzed_file_path=str(crash_file),
                    crash_type="unknown",  # Would be loaded from log
                    return_code=None,  # Would be loaded from log
                    exception_type=None,
                    exception_message=None,
                    stack_trace="",  # Would be loaded from .log file
                    timestamp="",
                )

                # Check for accompanying .log file
                log_file = crash_file.with_suffix(".log")
                if log_file.exists():
                    crash_record.stack_trace = log_file.read_text(
                        encoding="utf-8", errors="ignore"
                    )

                # Perform triage
                triage = self.triage_engine.triage_crash(crash_record)

                # Store result
                self.results.append(
                    {
                        "crash_file": str(crash_file),
                        "crash_id": crash_record.crash_id,
                        "severity": triage.severity.value,
                        "exploitability": triage.exploitability.value,
                        "priority_score": triage.priority_score,
                        "indicators": triage.indicators,
                        "recommendations": triage.recommendations,
                        "tags": triage.tags,
                        "summary": triage.summary,
                    }
                )

                logger.info(
                    f"  [{triage.severity.value.upper()}] {crash_file.name} - Priority: {triage.priority_score:.1f}/100"
                )

            except Exception as e:
                logger.error(f"Failed to analyze {crash_file}: {e}")

        # Sort by priority score (highest first)
        self.results.sort(key=lambda r: r["priority_score"], reverse=True)

        return self.results

    def export_csv(self, output_path: Path):
        """Export results to CSV."""
        if not self.results:
            logger.warning("No results to export")
            return

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "priority_score",
                "severity",
                "exploitability",
                "crash_id",
                "crash_file",
                "summary",
                "indicators",
                "recommendations",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in self.results:
                # Convert lists to strings for CSV
                result_copy = result.copy()
                result_copy["indicators"] = "; ".join(result["indicators"])
                result_copy["recommendations"] = "; ".join(result["recommendations"])
                writer.writerow(result_copy)

        logger.info(f"CSV report saved to: {output_path}")

    def export_json(self, output_path: Path):
        """Export results to JSON."""
        if not self.results:
            logger.warning("No results to export")
            return

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "total_crashes": len(self.results),
                    "critical_crashes": len(
                        [r for r in self.results if r["severity"] == "critical"]
                    ),
                    "high_severity_crashes": len(
                        [r for r in self.results if r["severity"] == "high"]
                    ),
                    "crashes": self.results,
                },
                f,
                indent=2,
            )

        logger.info(f"JSON report saved to: {output_path}")

    def export_html(self, output_path: Path):
        """Export results to HTML."""
        if not self.results:
            logger.warning("No results to export")
            return

        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Crash Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .critical {{ background-color: #d32f2f; color: white; }}
        .high {{ background-color: #f57c00; color: white; }}
        .medium {{ background-color: #fbc02d; color: black; }}
        .low {{ background-color: #1976d2; color: white; }}
        .info {{ background-color: #757575; color: white; }}
        .exploitable {{ background-color: #c62828; color: white; }}
        .probably-exploitable {{ background-color: #e64a19; color: white; }}
        .probably-not-exploitable {{ background-color: #558b2f; color: white; }}
        .unknown {{ background-color: #9e9e9e; color: white; }}
        h1 {{ color: #333; }}
        .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Crash Analysis Report</h1>

    <div class="stats">
        <strong>Total Crashes:</strong> {total_crashes}<br>
        <strong>Critical:</strong> {critical_count}<br>
        <strong>High:</strong> {high_count}<br>
        <strong>Analysis Date:</strong> {date}
    </div>

    <table>
        <tr>
            <th>Priority</th>
            <th>Crash ID</th>
            <th>Severity</th>
            <th>Exploitability</th>
            <th>Summary</th>
            <th>Indicators</th>
        </tr>
""".format(
            total_crashes=len(self.results),
            critical_count=len(
                [r for r in self.results if r["severity"] == "critical"]
            ),
            high_count=len([r for r in self.results if r["severity"] == "high"]),
            date=Path().absolute(),
        )

        for result in self.results:
            indicators_html = "<br>".join(
                f"• {ind}" for ind in result["indicators"][:3]
            )  # First 3
            html += f"""
        <tr>
            <td><strong>{result["priority_score"]:.1f}/100</strong></td>
            <td><code>{result["crash_id"]}</code></td>
            <td><span class="badge {result["severity"]}">{result["severity"].upper()}</span></td>
            <td><span class="badge {result["exploitability"].replace("_", "-")}">{result["exploitability"].replace("_", " ").title()}</span></td>
            <td>{result["summary"]}</td>
            <td>{indicators_html}</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved to: {output_path}")

    def print_summary(self):
        """Print summary to console."""
        if not self.results:
            logger.warning("No crashes analyzed")
            return

        print("\n" + "=" * 80)
        print("CRASH ANALYSIS SUMMARY")
        print("=" * 80)
        print(f"Total Crashes: {len(self.results)}")
        print()

        severity_counts = {}
        for result in self.results:
            severity = result["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print("Severity Distribution:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper():15s} {count:5d}")

        print()
        print("Top 5 Critical Crashes:")
        for i, result in enumerate(self.results[:5], 1):
            print(
                f"  {i}. [{result['severity'].upper()}] {result['crash_id']} - Priority: {result['priority_score']:.1f}/100"
            )
            print(f"     {result['summary']}")

        print("=" * 80)


def main():
    """Analyze crashes from fuzzing campaign with automated triage."""
    parser = argparse.ArgumentParser(
        description="Analyze crashes from fuzzing campaign with automated triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "crash_dir", type=Path, help="Directory containing crash samples"
    )
    parser.add_argument("--output", "-o", type=Path, help="Output file path")
    parser.add_argument(
        "--format",
        choices=["csv", "json", "html"],
        default="csv",
        help="Output format (default: csv)",
    )
    parser.add_argument(
        "--pattern",
        type=str,
        default="*.dcm",
        help="File pattern to match crash files (default: *.dcm)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter to show only crashes at or above this severity",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate crash directory
    if not args.crash_dir.exists():
        logger.error(f"Crash directory does not exist: {args.crash_dir}")
        sys.exit(1)

    try:
        # Analyze crashes
        analyzer = CrashAnalyzer(args.crash_dir)
        results = analyzer.analyze_crashes(file_pattern=args.pattern)

        if not results:
            logger.error("No crashes found to analyze")
            sys.exit(1)

        # Filter by severity if requested
        if args.min_severity:
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            min_level = severity_order[args.min_severity]
            analyzer.results = [
                r
                for r in analyzer.results
                if severity_order.get(r["severity"], 999) <= min_level
            ]
            logger.info(
                f"Filtered to {len(analyzer.results)} crashes at {args.min_severity}+ severity"
            )

        # Export results
        if args.output:
            if args.format == "csv":
                analyzer.export_csv(args.output)
            elif args.format == "json":
                analyzer.export_json(args.output)
            elif args.format == "html":
                analyzer.export_html(args.output)

        # Print summary
        analyzer.print_summary()

        sys.exit(0)

    except KeyboardInterrupt:
        logger.warning("\nAnalysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
