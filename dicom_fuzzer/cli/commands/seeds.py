"""Generate Seeds Subcommand for DICOM Fuzzer.

Two operating modes:

1. Mutation mode (default) — takes an existing DICOM file and generates
   mutated variants for use as AFL/WinAFL seed corpus.

2. Synthetic mode (--synthetic) — creates minimal valid DICOM files from
   scratch for SOP classes rarely found in real corpora (SEG, RTSS, PDF).
   Use this when you have no seed files for the modality-specific fuzzers.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.core.engine import DICOMGenerator

_SYNTHETIC_CHOICES = ("seg", "rtss", "pdf")


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for generate-seeds subcommand."""
    parser = argparse.ArgumentParser(
        description="Generate DICOM seed files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mutate an existing file into 100 seed variants
  dicom-fuzzer seeds input.dcm -n 100 -o ./seeds

  # Generate 10 synthetic Segmentation seeds from scratch
  dicom-fuzzer seeds --synthetic seg -n 10 -o ./seeds/seg

  # Generate 10 synthetic RT Structure Set seeds from scratch
  dicom-fuzzer seeds --synthetic rtss -n 10 -o ./seeds/rtss

  # Generate 10 synthetic Encapsulated PDF seeds from scratch
  dicom-fuzzer seeds --synthetic pdf -n 10 -o ./seeds/pdf
""",
    )

    parser.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Path to source DICOM file (required unless --synthetic is used)",
    )

    parser.add_argument(
        "--synthetic",
        choices=_SYNTHETIC_CHOICES,
        metavar="MODALITY",
        default=None,
        help=(
            "Generate synthetic seeds from scratch instead of mutating an input file. "
            "Choices: seg (Segmentation), rtss (RT Structure Set), pdf (Encapsulated PDF)."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        default="./artifacts/seeds",
        help="Output directory (default ./artifacts/seeds)",
    )

    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=100,
        help="Number of seed files to generate (default: 100)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="INT",
        help="Random seed for reproducible generation. Auto-generated if not set.",
    )

    return parser


def _run_synthetic(modality: str, count: int, output: str) -> int:
    """Generate synthetic seed files for the given modality.

    Args:
        modality: One of ``"seg"``, ``"rtss"``, ``"pdf"``.
        count: Number of files to generate.
        output: Output directory path string.

    Returns:
        Exit code (0 = success).

    """
    from dicom_fuzzer.core.corpus.synthetic_seeds import SEED_FACTORIES, save_seed

    factory = SEED_FACTORIES[modality]
    output_dir = Path(output)
    generated = []

    for i in range(count):
        dataset = factory()
        filename = f"{modality}_seed_{i + 1:04d}.dcm"
        path = save_seed(dataset, output_dir, filename)
        generated.append(path)

    print(
        f"[+] Generated {len(generated)} synthetic {modality.upper()} seeds in {output}"
    )
    return 0


class SeedsCommand(SubcommandBase):
    """Generate DICOM seed files subcommand."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand."""
        if args.synthetic:
            return _run_synthetic(args.synthetic, args.count, args.output)

        # Mutation mode — input file is required
        if not args.input:
            print("[-] input file is required unless --synthetic is specified")
            cls.build_parser().print_usage()
            return 1

        input_path = Path(args.input)
        if not input_path.exists():
            print(f"[-] File not found: {input_path}")
            return 1

        generator = DICOMGenerator(
            output_dir=args.output, seed=getattr(args, "seed", None)
        )
        results = generator.generate_batch(str(input_path), count=args.count)
        print(f"[+] Generated {len(results)} seed files in {args.output}")
        return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for generate-seeds subcommand."""
    return SeedsCommand.main(argv)


if __name__ == "__main__":
    sys.exit(main())
