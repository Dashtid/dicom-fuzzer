"""FDA Compliance Report CLI for DICOM Fuzzer.

Generate FDA-compliant fuzz testing reports for premarket submissions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dicom_fuzzer.reporting.fda_compliance import FDAComplianceReporter


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for FDA report CLI."""
    parser = argparse.ArgumentParser(
        description="Generate FDA-compliant fuzz testing reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report from fuzzing results JSON
  dicom-fuzzer fda-report --input fuzzing_results.json -o report.md

  # Generate report with organization info
  dicom-fuzzer fda-report --input results.json \\
    --organization "Medical Corp" \\
    --device "DICOM Viewer" \\
    --version "2.0.0" \\
    -o fda_report.md

  # Generate sample report template
  dicom-fuzzer fda-report --sample -o sample_report.md

  # Output both markdown and JSON
  dicom-fuzzer fda-report --input results.json \\
    -o report.md --json report.json
        """,
    )

    # Input options
    input_group = parser.add_argument_group("input options")
    input_group.add_argument(
        "--input",
        "-i",
        type=str,
        metavar="FILE",
        help="Input fuzzing results JSON file",
    )
    input_group.add_argument(
        "--sample",
        action="store_true",
        help="Generate a sample report template",
    )

    # Device information
    device_group = parser.add_argument_group("device information")
    device_group.add_argument(
        "--organization",
        type=str,
        default="",
        help="Organization name for report",
    )
    device_group.add_argument(
        "--device",
        type=str,
        default="",
        help="Device under test name",
    )
    device_group.add_argument(
        "--version",
        type=str,
        default="",
        help="Device version",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        default="fda_report.md",
        metavar="FILE",
        help="Output markdown report file (default: fda_report.md)",
    )
    output_group.add_argument(
        "--json",
        type=str,
        metavar="FILE",
        help="Also output JSON report to specified file",
    )
    output_group.add_argument(
        "--stdout",
        action="store_true",
        help="Print report to stdout instead of file",
    )

    return parser


def load_fuzzing_results(path: Path) -> dict[str, Any]:
    """Load fuzzing results from JSON file."""
    with open(path) as f:
        result: dict[str, Any] = json.load(f)
        return result


def create_reporter_from_results(
    results: dict[str, Any],
    organization: str = "",
    device_name: str = "",
    device_version: str = "",
) -> FDAComplianceReporter:
    """Create FDA reporter from fuzzing results."""
    reporter = FDAComplianceReporter(
        organization=organization,
        device_name=device_name,
        device_version=device_version,
    )

    # Extract fuzzing parameters
    params = results.get("parameters", results.get("config", {}))
    reporter.set_fuzzing_parameters(
        iterations=params.get("iterations", params.get("total_iterations", 0)),
        duration_seconds=params.get("duration", params.get("duration_seconds", 0)),
        timeout_per_test=params.get("timeout", params.get("timeout_per_test", 1.0)),
        parallel_workers=params.get("workers", params.get("parallel_workers", 1)),
        mutation_strategies=params.get(
            "strategies", params.get("mutation_strategies", [])
        ),
        coverage_guided=params.get("coverage_guided", True),
        dicom_aware=params.get("dicom_aware", True),
        seed_corpus_size=params.get("seed_corpus_size", 0),
        final_corpus_size=params.get("final_corpus_size", params.get("corpus_size", 0)),
    )

    # Extract coverage metrics
    coverage = results.get("coverage", {})
    reporter.set_test_coverage(
        total_test_cases=coverage.get("total_test_cases", params.get("iterations", 0)),
        unique_code_paths=coverage.get(
            "unique_code_paths", coverage.get("unique_paths", 0)
        ),
        branch_coverage_percent=coverage.get(
            "branch_coverage_percent", coverage.get("coverage", 0)
        ),
        mutation_types_tested=coverage.get("mutation_types", []),
        attack_categories_tested=coverage.get("attack_categories", []),
        cve_patterns_tested=coverage.get("cve_patterns", []),
    )

    # Extract results
    stats = results.get("results", results.get("statistics", {}))
    reporter.set_results(
        crashes_detected=stats.get("crashes", stats.get("crashes_detected", 0)),
        hangs_detected=stats.get("hangs", stats.get("hangs_detected", 0)),
        total_execution_time=stats.get(
            "execution_time", stats.get("total_execution_time", 0)
        ),
        tests_per_second=stats.get("tests_per_second", stats.get("throughput", 0)),
        memory_peak_mb=stats.get("memory_peak_mb", stats.get("peak_memory", 0)),
    )

    # Extract findings
    findings = results.get("findings", results.get("vulnerabilities", []))
    for i, finding in enumerate(findings):
        reporter.add_finding(
            finding_id=finding.get("id", f"FINDING-{i + 1}"),
            category=finding.get("category", finding.get("type", "unknown")),
            severity=finding.get("severity", "medium"),
            description=finding.get("description", ""),
            test_case_file=finding.get("test_case", finding.get("file", "")),
            reproduction_steps=finding.get("reproduction", finding.get("steps", "")),
            cwe_id=finding.get("cwe_id", finding.get("cwe")),
            cvss_score=finding.get("cvss_score", finding.get("cvss")),
            remediation=finding.get("remediation", finding.get("fix")),
        )

    return reporter


def create_sample_reporter(
    organization: str = "",
    device_name: str = "",
    device_version: str = "",
) -> FDAComplianceReporter:
    """Create a sample FDA reporter with template data."""
    from dicom_fuzzer.reporting.fda_compliance import create_sample_report

    reporter = create_sample_report()

    # Override with provided values
    if organization:
        reporter.report.organization = organization
    if device_name:
        reporter.report.device_name = device_name
    if device_version:
        reporter.report.device_version = device_version

    return reporter


def main(args: list[str] | None = None) -> int:
    """Main entry point for FDA report CLI."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    # Validate input
    if not parsed.input and not parsed.sample:
        parser.error("Either --input or --sample is required")

    # Create reporter
    if parsed.sample:
        reporter = create_sample_reporter(
            organization=parsed.organization,
            device_name=parsed.device,
            device_version=parsed.version,
        )
        print("[i] Generating sample FDA compliance report template...")
    else:
        input_path = Path(parsed.input)
        if not input_path.exists():
            print(f"[-] FAIL: Input file not found: {input_path}")
            return 1

        try:
            results = load_fuzzing_results(input_path)
        except json.JSONDecodeError as e:
            print(f"[-] FAIL: Invalid JSON in input file: {e}")
            return 1

        reporter = create_reporter_from_results(
            results,
            organization=parsed.organization,
            device_name=parsed.device,
            device_version=parsed.version,
        )
        print(f"[i] Loaded fuzzing results from {input_path}")

    # Evaluate compliance
    reporter.evaluate_compliance()

    # Generate output
    markdown_report = reporter.generate_markdown()

    if parsed.stdout:
        print(markdown_report)
    else:
        output_path = Path(parsed.output)
        reporter.save_markdown(output_path)
        print(f"[+] Markdown report saved to: {output_path}")

    # Optional JSON output
    if parsed.json:
        json_path = Path(parsed.json)
        reporter.save_json(json_path)
        print(f"[+] JSON report saved to: {json_path}")

    # Print compliance summary
    if reporter.report.meets_fda_requirements:
        print("[+] FDA Compliance: PASS")
    else:
        print("[!] FDA Compliance: NEEDS ATTENTION")
        for note in reporter.report.compliance_notes:
            if note.startswith("[!]"):
                print(f"    {note}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
