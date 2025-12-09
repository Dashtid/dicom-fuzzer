"""Samples Subcommand for DICOM Fuzzer.

Provides functionality to generate or download sample DICOM files for testing.
"""

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.core.synthetic import SyntheticDicomGenerator

# Public DICOM sample sources
SAMPLE_SOURCES = {
    "rubo": {
        "name": "Rubo Medical Imaging",
        "url": "https://www.rubomedical.com/dicom_files/",
        "description": "Free sample DICOM files for testing",
    },
    "osirix": {
        "name": "OsiriX DICOM Sample Images",
        "url": "https://www.osirix-viewer.com/resources/dicom-image-library/",
        "description": "Large collection of DICOM datasets from various modalities",
    },
    "dicom_library": {
        "name": "DICOM Library",
        "url": "https://www.dicomlibrary.com/",
        "description": "Free DICOM image sharing and anonymization service",
    },
    "tcia": {
        "name": "The Cancer Imaging Archive (TCIA)",
        "url": "https://www.cancerimagingarchive.net/",
        "description": "Large public archive of cancer imaging data (requires registration)",
    },
    "medpix": {
        "name": "MedPix",
        "url": "https://medpix.nlm.nih.gov/",
        "description": "NIH database of medical images (requires registration)",
    },
}

# Supported modalities for generation
SUPPORTED_MODALITIES = ["CT", "MR", "US", "CR", "DX", "PT", "NM", "XA", "RF", "SC"]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for samples subcommand."""
    parser = argparse.ArgumentParser(
        description="Generate or list sample DICOM files for fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 10 synthetic CT images
  dicom-fuzzer samples --generate -c 10 -m CT -o ./samples

  # Generate a series of 20 MR slices
  dicom-fuzzer samples --generate --series -c 20 -m MR -o ./samples

  # Generate mixed modalities
  dicom-fuzzer samples --generate -c 50 -o ./samples

  # List download sources
  dicom-fuzzer samples --list-sources
        """,
    )

    # Action arguments (mutually exclusive)
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--generate",
        action="store_true",
        help="Generate synthetic DICOM files (no PHI)",
    )
    action_group.add_argument(
        "--list-sources",
        action="store_true",
        help="List public sources for downloading real DICOM samples",
    )

    # Generation options
    gen_group = parser.add_argument_group("generation options")
    gen_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=10,
        metavar="N",
        help="Number of files to generate (default: 10)",
    )
    gen_group.add_argument(
        "-o",
        "--output",
        type=str,
        default="./samples",
        metavar="DIR",
        help="Output directory (default: ./samples)",
    )
    gen_group.add_argument(
        "-m",
        "--modality",
        type=str,
        choices=SUPPORTED_MODALITIES,
        metavar="MOD",
        help="Modality to generate (CT, MR, US, CR, DX, PT, NM, XA, RF, SC). "
        "If not specified, generates random modalities.",
    )
    gen_group.add_argument(
        "--series",
        action="store_true",
        help="Generate files as a consistent series (same patient/study/series UIDs)",
    )
    gen_group.add_argument(
        "--rows",
        type=int,
        default=256,
        metavar="N",
        help="Image rows (default: 256)",
    )
    gen_group.add_argument(
        "--columns",
        type=int,
        default=256,
        metavar="N",
        help="Image columns (default: 256)",
    )
    gen_group.add_argument(
        "--seed",
        type=int,
        metavar="N",
        help="Random seed for reproducible generation",
    )
    gen_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_generate(args: argparse.Namespace) -> int:
    """Generate synthetic DICOM files."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Synthetic Sample Generation")
    print("=" * 70)
    print(f"  Output:     {output_dir}")
    print(f"  Count:      {args.count}")
    print(f"  Modality:   {args.modality or 'random'}")
    print(f"  Image size: {args.rows}x{args.columns}")
    if args.series:
        print("  Mode:       Series (consistent UIDs)")
    if args.seed is not None:
        print(f"  Seed:       {args.seed}")
    print("=" * 70 + "\n")

    generator = SyntheticDicomGenerator(output_dir, seed=args.seed)

    try:
        if args.series:
            # Generate as a series
            modality = args.modality or "CT"
            files = generator.generate_series(
                count=args.count,
                modality=modality,
                rows=args.rows,
                columns=args.columns,
            )
        else:
            # Generate individual files
            files = generator.generate_batch(
                count=args.count,
                modality=args.modality,
                rows=args.rows,
                columns=args.columns,
            )

        print(f"[+] Generated {len(files)} synthetic DICOM files")

        if args.verbose:
            print("\nGenerated files:")
            for f in files[:10]:
                print(f"  - {f.name}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")

        print(f"\nOutput directory: {output_dir}")
        print("\nNote: All data is synthetic - no PHI concerns.")
        return 0

    except Exception as e:
        print(f"[ERROR] Generation failed: {e}")
        return 1


def run_list_sources(args: argparse.Namespace) -> int:
    """List public DICOM sample sources."""
    print("\n" + "=" * 70)
    print("  Public DICOM Sample Sources")
    print("=" * 70)
    print()

    for key, source in SAMPLE_SOURCES.items():
        print(f"  [{key}] {source['name']}")
        print(f"    URL: {source['url']}")
        print(f"    {source['description']}")
        print()

    print("=" * 70)
    print("\nNote: Most sources provide anonymized clinical data.")
    print("Always verify licensing and comply with data usage terms.")
    print("For fuzzing, synthetic data (--generate) avoids compliance concerns.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for samples subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.generate:
        return run_generate(args)
    elif args.list_sources:
        return run_list_sources(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
