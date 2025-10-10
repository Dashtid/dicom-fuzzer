#!/usr/bin/env python3
"""
DICOM Fuzzing Campaign Demo

Demonstrates end-to-end fuzzing with configuration management,
performance profiling, crash analysis, and reporting.
"""

import sys
from pathlib import Path

from dicom_fuzzer.core.config import get_settings
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.profiler import PerformanceProfiler
from dicom_fuzzer.core.reporter import ReportGenerator
from dicom_fuzzer.core.statistics import StatisticsCollector
from dicom_fuzzer.core.validator import DicomValidator


def main():
    """Run a demonstration fuzzing campaign."""
    print("=" * 80)
    print("DICOM-Fuzzer - End-to-End Demonstration")
    print("=" * 80)
    print()

    # Load configuration
    print("[CONFIG] Loading configuration...")
    settings = get_settings()
    print(settings.get_summary())

    # Find sample DICOM file
    sample_files = list(
        settings.paths.input_dir.glob(settings.paths.dicom_file_pattern)
    )
    if not sample_files:
        print(f"[ERROR] No DICOM files found in {settings.paths.input_dir}")
        pattern = settings.paths.dicom_file_pattern
        print(f"   Please add sample DICOM files matching {pattern}")
        return 1

    sample_file = sample_files[0]
    print(f"[OK] Found sample file: {sample_file.name}")
    print()

    # Initialize components
    print("[SETUP] Initializing fuzzing components...")
    parser = DicomParser(str(sample_file))
    fuzzer = DICOMGenerator(output_dir=str(settings.paths.output_dir))
    validator = DicomValidator(strict_mode=settings.security.strict_validation)
    crash_analyzer = CrashAnalyzer(crash_dir=str(settings.paths.crash_dir))
    stats_collector = StatisticsCollector()
    reporter = ReportGenerator(output_dir=str(settings.paths.report_dir))

    # Create output directory
    settings.paths.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"   Output dir: {settings.paths.output_dir}")
    print(f"   Crash dir: {settings.paths.crash_dir}")
    print(f"   Report dir: {settings.paths.report_dir}")
    print()

    # Run fuzzing campaign
    print("[START] Starting fuzzing campaign...")
    num_files = min(10, settings.fuzzing.max_files_per_campaign)
    print(f"   Generating {num_files} test files...")
    print()

    with PerformanceProfiler() as profiler:
        try:
            # Generate batch of fuzzed files
            fuzzed_files = fuzzer.generate_batch(
                parser.dataset,
                count=10,
                strategies=["metadata", "header", "pixel", "structure"],
            )

            for i, fuzzed_file in enumerate(fuzzed_files, 1):
                try:
                    # Use filename to determine strategy
                    strategy_name = "mixed"
                    stats_collector.record_mutation(strategy_name)
                    profiler.record_file_generated(strategy_name)

                    # Validate
                    fuzzed_dataset = DicomParser(fuzzed_file).dataset
                    validation_result = validator.validate(fuzzed_dataset)
                    profiler.record_validation()

                    if not validation_result:
                        stats_collector.record_validation_failure(strategy_name)
                        print(f"   [{i}/10] [WARN]  Validation failed")
                    else:
                        print(f"   [{i}/10] [OK] Generated: {Path(fuzzed_file).name}")

                except Exception as e:
                    # Record crash
                    crash_report = crash_analyzer.record_crash(e, f"test_{i}")
                    if crash_report:
                        stats_collector.record_crash("mixed", crash_report.crash_hash)
                        profiler.record_crash()
                        print(f"   [{i}/10] [CRASH] CRASH: {type(e).__name__}")

        except Exception as e:
            print(f"   [ERROR] Batch generation failed: {e}")

    print()
    print("=" * 80)
    print("[RESULTS] Campaign Results")
    print("=" * 80)
    print()

    # Print performance metrics
    print("[PERF] Performance Metrics:")
    print(profiler.get_progress_report())
    print()

    # Print statistics
    print("[STATS] Mutation Statistics:")
    print(stats_collector.get_summary())
    print()

    # Print crash summary
    if crash_analyzer.crashes:
        print("[ANALYSIS] Crash Analysis:")
        print(crash_analyzer.generate_report())
        print()

    # Generate reports
    print("[REPORT] Generating reports...")
    try:
        # Performance report
        perf_report = reporter.generate_performance_html_report(
            profiler.get_summary(),
            campaign_name="DICOM Fuzzing Demo",
        )
        print(f"   [OK] Performance report: {perf_report}")

        # Crash report (if any crashes)
        if crash_analyzer.crashes:
            crash_html = reporter.generate_crash_html_report(
                crash_analyzer,
                campaign_name="DICOM Fuzzing Demo",
            )
            crash_json = reporter.generate_crash_json_report(
                crash_analyzer,
                campaign_name="DICOM Fuzzing Demo",
            )
            print(f"   [OK] Crash HTML report: {crash_html}")
            print(f"   [OK] Crash JSON report: {crash_json}")
    except Exception as e:
        print(f"   [WARN]  Report generation failed: {e}")

    print()
    print("=" * 80)
    print("[DONE] Demo Complete!")
    print("=" * 80)
    print()
    print(f"Generated files: {settings.paths.output_dir}")
    print(f"Crash reports: {settings.paths.crash_dir}")
    print(f"HTML reports: {settings.paths.report_dir}")
    print()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[STOP]  Campaign interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n[ERROR] Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
