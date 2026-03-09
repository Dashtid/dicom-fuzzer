"""Generate Seeds Subcommand for DICOM Fuzzer.

Generates mutated DICOM files to disk without sending them to a target.
Useful as seed corpus for coverage-guided fuzzers (AFL/WinAFL).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

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

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for generate-seeds subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] File not found: {input_path}")
        return 1
    generator = DICOMGenerator(output_dir=args.output)
    results = generator.generate_batch(str(input_path), count=args.count)
    print(f"[+] Generated {len(results)} seed files in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
