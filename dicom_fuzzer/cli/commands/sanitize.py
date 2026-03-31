"""Sanitize Subcommand -- strip PHI from DICOM seed files.

Usage::

    dicom-fuzzer sanitize <seed-dir> [-o DIR] [--keep-private] [--keep-uids]
                                     [--date-offset DAYS] [-r] [--dry-run] [-v]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.utils.sanitizer import sanitize_directory


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for the sanitize subcommand."""
    parser = argparse.ArgumentParser(
        description="Strip PHI from DICOM seed files before fuzzing",
    )

    parser.add_argument(
        "seed_dir",
        help="Directory containing DICOM seed files",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="DIR",
        help="Output directory (default: <seed-dir>_sanitized)",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Scan subdirectories recursively",
    )
    parser.add_argument(
        "--keep-private",
        action="store_true",
        dest="keep_private",
        help="Retain private (odd-group) tags (removed by default)",
    )
    parser.add_argument(
        "--keep-uids",
        action="store_true",
        dest="keep_uids",
        help="Do not regenerate UIDs (useful for multi-file studies)",
    )
    parser.add_argument(
        "--date-offset",
        type=int,
        default=None,
        metavar="DAYS",
        dest="date_offset",
        help="Fixed date shift in days (default: random 30-3650)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Report what would be sanitized without writing files",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-file progress",
    )

    return parser


class SanitizeCommand(SubcommandBase):
    """Strip PHI from DICOM seed files subcommand."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand."""
        seed_dir = Path(args.seed_dir)
        if not seed_dir.is_dir():
            print(f"[-] Directory not found: {seed_dir}")
            return 1

        output_dir = Path(args.output) if args.output else Path(f"{seed_dir}_sanitized")

        # Count files for dry-run / progress
        pattern = "**/*.dcm" if args.recursive else "*.dcm"
        dicom_pattern = "**/*.dicom" if args.recursive else "*.dicom"
        files = list(seed_dir.glob(pattern)) + list(seed_dir.glob(dicom_pattern))

        if not files:
            print(f"[-] No DICOM files found in {seed_dir}")
            return 1

        if args.dry_run:
            print(f"[i] Dry run: {len(files)} DICOM files would be sanitized")
            print(f"[i] Output: {output_dir}")
            return 0

        stats = sanitize_directory(
            seed_dir,
            output_dir,
            keep_private=args.keep_private,
            keep_uids=args.keep_uids,
            date_offset_days=args.date_offset,
            recursive=args.recursive,
        )

        print(
            f"[+] Sanitized {stats['succeeded']}/{stats['processed']} "
            f"files in {output_dir}"
        )
        if stats["failed"]:
            print(f"[!] {stats['failed']} file(s) failed")

        return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for sanitize subcommand."""
    return SanitizeCommand.main(argv)


if __name__ == "__main__":
    sys.exit(main())
