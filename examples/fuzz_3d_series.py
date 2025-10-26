#!/usr/bin/env python3
"""
Example: Fuzzing 3D DICOM Series

This example demonstrates how to use the Series3DMutator and SeriesWriter
to fuzz complete 3D DICOM series (multi-slice volumes).

KEY CONCEPTS:
- Series Detection: Groups DICOM slices by SeriesInstanceUID
- Series-Level Fuzzing: Targets vulnerabilities in 3D volume loading
- 5 Mutation Strategies: Metadata, Position, Boundary, Gradient, Inconsistency
- Metadata Tracking: Full mutation records for debugging and analysis

USAGE:
    python examples/fuzz_3d_series.py --input ./test_data/dicom_samples --output ./fuzzed_series

    # Specific strategy
    python examples/fuzz_3d_series.py --input ./test_data --strategy slice_position_attack

    # Aggressive fuzzing
    python examples/fuzz_3d_series.py --input ./test_data --severity aggressive --count 20

SECURITY NOTE:
Based on CVE-2025-35975, CVE-2025-36521, CVE-2025-5943, this fuzzer targets
series-level parsing vulnerabilities that single-file fuzzing cannot reach.
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.core.series_detector import SeriesDetector
from dicom_fuzzer.core.series_validator import SeriesValidator
from dicom_fuzzer.core.series_writer import SeriesWriter
from dicom_fuzzer.strategies.series_mutator import (
    Series3DMutator,
    SeriesMutationStrategy,
)
from dicom_fuzzer.utils.logger import configure_logging, get_logger

logger = get_logger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Fuzz 3D DICOM series with specialized mutation strategies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Basic fuzzing:
    python %(prog)s --input ./test_data/dicom_samples --output ./fuzzed_series

  Specific strategy:
    python %(prog)s --input ./test_data --strategy metadata_corruption

  Aggressive fuzzing:
    python %(prog)s --input ./test_data --severity aggressive --count 20

  Target specific series:
    python %(prog)s --input ./test_data --series-uid 1.2.840.113619.2.55.3.123456

MUTATION STRATEGIES:
  metadata_corruption     - Invalid UIDs, missing tags, type confusion
  slice_position_attack   - Randomized positions, extreme values (NaN, Inf)
  boundary_slice_targeting - First/last/middle slice corruption
  gradient_mutation       - Progressive corruption (clean to heavily mutated)
  inconsistency_injection - Mixed modalities, conflicting metadata

SECURITY RESEARCH:
  CVE-2025-35975: Out-of-bounds write (CVSS 8.8)
  CVE-2025-36521: Out-of-bounds read (CVSS 8.6)
  CVE-2025-5943: Memory corruption in DICOM parser (CVSS 8.6)

PUBLIC DICOM TEST DATASETS:
  - NEMA DICOM samples: https://www.dicomstandard.org/
  - TCIA (The Cancer Imaging Archive): https://www.cancerimagingarchive.net/
""",
    )

    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input directory containing DICOM files",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./fuzzed_series"),
        help="Output directory for fuzzed series (default: ./fuzzed_series)",
    )

    parser.add_argument(
        "--strategy",
        type=str,
        choices=[s.value for s in SeriesMutationStrategy],
        help="Mutation strategy (random if not specified)",
    )

    parser.add_argument(
        "--severity",
        type=str,
        choices=["minimal", "moderate", "aggressive", "extreme"],
        default="moderate",
        help="Mutation severity level (default: moderate)",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of mutations per series (default: 5, or severity-based if 0)",
    )

    parser.add_argument(
        "--series-uid",
        type=str,
        help="Target specific SeriesInstanceUID (fuzzes all series if not specified)",
    )

    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate series before and after fuzzing",
    )

    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducibility",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    return parser.parse_args()


def main():
    """Main fuzzing workflow."""
    args = parse_args()

    # Setup logging
    configure_logging(log_level=args.log_level)

    logger.info("=" * 60)
    logger.info("3D DICOM SERIES FUZZER")
    logger.info("=" * 60)
    logger.info(f"Input Directory: {args.input}")
    logger.info(f"Output Directory: {args.output}")
    logger.info(f"Strategy: {args.strategy or 'random'}")
    logger.info(f"Severity: {args.severity}")
    logger.info(
        f"Mutations per Series: {args.count if args.count > 0 else 'severity-based'}"
    )
    logger.info(f"Random Seed: {args.seed or 'none'}")
    logger.info("")

    # Validate input directory
    if not args.input.exists():
        logger.error(f"Input directory not found: {args.input}")
        logger.info("")
        logger.info("Please provide DICOM test files. Public datasets:")
        logger.info("  - NEMA: https://www.dicomstandard.org/")
        logger.info("  - TCIA: https://www.cancerimagingarchive.net/")
        return 1

    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)

    # Step 1: Detect series
    logger.info("STEP 1: Detecting DICOM series...")
    detector = SeriesDetector()

    try:
        series_list = detector.detect_series_in_directory(
            args.input, recursive=True, validate=args.validate
        )
    except Exception as e:
        logger.error(f"Failed to detect series: {e}")
        return 1

    if not series_list:
        logger.warning("No DICOM series found in input directory")
        return 1

    # Show series summary
    summary = detector.get_series_summary(series_list)
    logger.info(f"Found {summary['total_series']} series:")
    logger.info(f"  Total Slices: {summary['total_slices']}")
    logger.info(f"  Modalities: {summary['modalities']}")
    logger.info(f"  Multi-slice Series: {summary['multislice_series']}")
    logger.info(f"  Single-slice Series: {summary['single_slice_series']}")
    logger.info("")

    # Filter by series UID if specified
    if args.series_uid:
        series_list = [s for s in series_list if s.series_uid == args.series_uid]
        if not series_list:
            logger.error(f"Series UID not found: {args.series_uid}")
            return 1
        logger.info(f"Targeting specific series: {args.series_uid[:32]}...")
        logger.info("")

    # Step 2: Validate original series (if requested)
    validator = None
    if args.validate:
        logger.info("STEP 2: Validating original series...")
        validator = SeriesValidator(strict=False)

        for series in series_list:
            report = validator.validate_series(series)
            if report.has_errors():
                logger.warning(
                    f"Series {series.series_uid[:16]}... has validation errors "
                    f"({len(report.issues)} issues)"
                )
                for issue in report.issues[:3]:
                    logger.warning(f"  [{issue.severity.value}] {issue.message}")
        logger.info("")

    # Step 3: Initialize mutator and writer
    logger.info("STEP 3: Initializing fuzzer...")
    mutator = Series3DMutator(severity=args.severity, seed=args.seed)
    writer = SeriesWriter(args.output)
    logger.info("")

    # Step 4: Fuzz each series
    logger.info("STEP 4: Fuzzing series...")
    total_fuzzed = 0
    total_mutations = 0

    for i, series in enumerate(series_list, start=1):
        logger.info(f"[{i}/{len(series_list)}] Fuzzing {series.modality} series...")
        logger.info(f"  Series UID: {series.series_uid[:32]}...")
        logger.info(f"  Slice Count: {series.slice_count}")

        try:
            # Mutate series
            mutation_count = args.count if args.count > 0 else None
            fuzzed_datasets, records = mutator.mutate_series(
                series, strategy=args.strategy, mutation_count=mutation_count
            )

            logger.info(f"  Applied {len(records)} mutations")

            # Show sample mutations
            for record in records[:3]:
                logger.info(
                    f"    - {record.strategy}: {record.tag} "
                    f"(slice {record.slice_index}, severity={record.severity})"
                )
            if len(records) > 3:
                logger.info(f"    ... and {len(records) - 3} more")

            # Write fuzzed series
            metadata = writer.write_series(
                series,
                fuzzed_datasets,
                mutation_strategy=args.strategy or "random",
                mutations_applied=[r.to_dict() for r in records],
                original_series=series,
            )

            logger.info(f"  Wrote to: {metadata.output_directory.name}/")
            logger.info(f"  Total Size: {metadata.total_size_bytes:,} bytes")

            total_fuzzed += 1
            total_mutations += len(records)

        except Exception as e:
            logger.error(f"  Failed to fuzz series: {e}")
            continue

        logger.info("")

    # Step 5: Summary
    logger.info("=" * 60)
    logger.info("FUZZING COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Series Fuzzed: {total_fuzzed}/{len(series_list)}")
    logger.info(f"Total Mutations: {total_mutations}")
    logger.info(f"Average Mutations per Series: {total_mutations / total_fuzzed:.1f}")
    logger.info(f"Output Directory: {args.output}")
    logger.info("")

    # Step 6: Show next steps
    logger.info("NEXT STEPS:")
    logger.info("  1. Test fuzzed series with your DICOM viewer:")
    logger.info(f"     viewer {args.output}/series_*/slice_*.dcm")
    logger.info("")
    logger.info("  2. Review mutation metadata:")
    logger.info(f"     cat {args.output}/series_*/metadata.json")
    logger.info("")
    logger.info("  3. Run reproduction scripts:")
    logger.info(f"     python {args.output}/series_*/reproduce.py")
    logger.info("")

    return 0


if __name__ == "__main__":
    sys.exit(main())
