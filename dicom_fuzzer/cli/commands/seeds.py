"""Generate Seeds Subcommand for DICOM Fuzzer.

Generates mutated DICOM files to disk without sending them to a target.
Useful as seed corpus for coverage-guided fuzzers (AFL/WinAFL).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.core.engine import DICOMGenerator


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for generate-seeds subcommand."""
    parser = argparse.ArgumentParser(
        description="Generate mutated DICOM seed files",
    )

    parser.add_argument(
        "input",
        help="Path to source DICOM file",
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


class SeedsCommand(SubcommandBase):
    """Generate mutated DICOM seed files subcommand."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand."""
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
