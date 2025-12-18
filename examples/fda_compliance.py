#!/usr/bin/env python3
"""Example: FDA Compliance Reporting

This example demonstrates generating FDA-compliant fuzz testing reports.
"""

from pathlib import Path

from dicom_fuzzer.reporting.fda_compliance import (
    FDAComplianceReporter,
    create_sample_report,
)


def main() -> None:
    """Run FDA compliance example."""
    print("=" * 60)
    print("  DICOM Fuzzer - FDA Compliance Reporting Example")
    print("=" * 60)

    output_dir = Path("./artifacts/reports/fda")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Option 1: Generate sample report template
    print("\n[i] Generating sample FDA compliance report...")
    reporter = create_sample_report()
    reporter.report.organization = "Example Medical Corp"
    reporter.report.device_name = "DICOM Viewer Pro"
    reporter.report.device_version = "2.5.0"

    # Evaluate compliance
    is_compliant = reporter.evaluate_compliance()

    # Save reports
    md_path = output_dir / "sample_fda_report.md"
    json_path = output_dir / "sample_fda_report.json"

    reporter.save_markdown(md_path)
    reporter.save_json(json_path)

    print(f"[+] Markdown report: {md_path}")
    print(f"[+] JSON report: {json_path}")

    # Print compliance status
    print("\n[i] Compliance Assessment:")
    print("-" * 60)
    for note in reporter.report.compliance_notes:
        print(f"  {note}")

    print(
        f"\n[{'+' if is_compliant else '!'}] Overall: "
        f"{'COMPLIANT' if is_compliant else 'NEEDS ATTENTION'}"
    )

    # Option 2: Create custom report from fuzzing results
    print("\n[i] Creating custom report...")
    custom_reporter = FDAComplianceReporter(
        organization="Your Company",
        device_name="Your Device",
        device_version="1.0.0",
    )

    # Set fuzzing parameters
    custom_reporter.set_fuzzing_parameters(
        iterations=100000,
        duration_seconds=28800,  # 8 hours
        timeout_per_test=1.0,
        parallel_workers=4,
        mutation_strategies=["metadata", "header", "pixel", "structure"],
        coverage_guided=True,
        dicom_aware=True,
        seed_corpus_size=50,
        final_corpus_size=1500,
    )

    # Set coverage metrics
    custom_reporter.set_test_coverage(
        total_test_cases=100000,
        unique_code_paths=2500,
        branch_coverage_percent=78.5,
        mutation_types_tested=["bit_flip", "byte_insert", "havoc", "dicom_tag"],
        attack_categories_tested=[
            "buffer_overflow",
            "format_string",
            "integer_overflow",
            "path_traversal",
        ],
        cve_patterns_tested=[
            "CVE-2022-2119",
            "CVE-2022-2120",
            "CVE-2024-22100",
        ],
    )

    # Set results
    custom_reporter.set_results(
        crashes_detected=0,
        hangs_detected=2,
        total_execution_time=28800,
        tests_per_second=3.47,
        memory_peak_mb=512,
    )

    # Evaluate and save
    custom_reporter.evaluate_compliance()
    custom_path = output_dir / "custom_fda_report.md"
    custom_reporter.save_markdown(custom_path)
    print(f"[+] Custom report: {custom_path}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
