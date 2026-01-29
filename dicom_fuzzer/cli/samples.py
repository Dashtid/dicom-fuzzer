"""Samples Subcommand for DICOM Fuzzer.

Provides functionality to generate synthetic DICOM files for testing.

For CVE replication, use the dedicated 'cve' subcommand:
    dicom-fuzzer cve --help
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
        description="Generate synthetic DICOM files for fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 10 synthetic CT images
  dicom-fuzzer samples --generate -c 10 -m CT -o ./samples

  # Generate a series of 20 MR slices
  dicom-fuzzer samples --generate --series -c 20 -m MR -o ./samples

  # List download sources
  dicom-fuzzer samples --list-sources

  # Strip pixel data for corpus optimization
  dicom-fuzzer samples --strip-pixel-data ./corpus -o ./optimized

For CVE replication files, use the dedicated 'cve' subcommand:
  dicom-fuzzer cve --help
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
    action_group.add_argument(
        "--strip-pixel-data",
        type=str,
        metavar="PATH",
        help="Strip PixelData from DICOM files for corpus optimization",
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
        default="./artifacts/samples",
        metavar="DIR",
        help="Output directory (default: ./artifacts/samples)",
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


def run_strip_pixel_data(args: argparse.Namespace) -> int:
    """Strip PixelData from DICOM files for corpus optimization."""
    input_path = Path(args.strip_pixel_data)

    if not input_path.exists():
        print(f"[-] Path not found: {input_path}")
        return 1

    print("\n" + "=" * 70)
    print("  DICOM Corpus Optimizer - Strip PixelData")
    print("=" * 70)
    print(f"  Input:  {input_path}")
    print(f"  Output: {args.output}")
    print("  [i] Stripping PixelData, OverlayData, WaveformData")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.utils.corpus_minimization import (
            optimize_corpus,
            strip_pixel_data,
        )

        output_dir = Path(args.output)

        if input_path.is_file():
            # Single file
            output_file = output_dir / input_path.name
            output_dir.mkdir(parents=True, exist_ok=True)

            success, bytes_saved = strip_pixel_data(input_path, output_file)
            if success:
                original_size = input_path.stat().st_size
                new_size = output_file.stat().st_size
                reduction = (
                    100 * bytes_saved / original_size if original_size > 0 else 0
                )
                print(f"  [+] {input_path.name}")
                print(f"      Original: {original_size / 1024:.1f} KB")
                print(f"      Stripped: {new_size / 1024:.1f} KB")
                print(f"      Saved:    {bytes_saved / 1024:.1f} KB ({reduction:.1f}%)")
            else:
                print(f"  [-] Failed to process: {input_path.name}")
                return 1
        else:
            # Directory
            stats = optimize_corpus(
                corpus_dir=input_path,
                output_dir=output_dir,
                strip_pixels=True,
                strip_overlays=True,
                strip_waveforms=True,
                dry_run=False,
            )

            print(f"  [+] Files processed:   {stats['files_processed']}")
            print(f"  [+] Files optimized:   {stats['files_optimized']}")
            print(f"  [-] Files skipped:     {stats['files_skipped']}")
            print(f"  Original size:         {stats['original_size_mb']:.2f} MB")
            print(f"  Optimized size:        {stats['optimized_size_mb']:.2f} MB")
            print(
                f"  Space saved:           {stats['bytes_saved'] / (1024 * 1024):.2f} MB"
            )
            print(f"  Reduction:             {stats['reduction_percent']:.1f}%")

        print(f"\n[+] Output: {output_dir}")
        print("\n[i] Optimized corpus is ready for faster fuzzing.")
        print("    Use with AFL++/libFuzzer for improved throughput.")
        return 0

    except Exception as e:
        print(f"[-] Optimization failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for samples subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.generate:
        return run_generate(args)
    elif args.list_sources:
        return run_list_sources(args)
    elif args.strip_pixel_data:
        return run_strip_pixel_data(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
