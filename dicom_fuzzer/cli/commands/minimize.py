"""Minimize subcommand - reduce a crashing DICOM file to its smallest form.

Runs delta debugging on the file's DICOM elements: keep removing elements
that aren't needed to trigger the crash, then write a minimal .dcm that
still produces the same target exit code.

Usage:
    dicom-fuzzer minimize <crashing.dcm> -t <target.exe> --expect-rc 1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.core.crash.minimizer import (
    MinimizationError,
    MinimizeResult,
    minimize_dicom,
)

__all__ = ["MinimizeCommand", "main"]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for minimize subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer minimize",
        description=(
            "Reduce a crashing DICOM file to the smallest subset of "
            "elements that still triggers the same exit code."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dicom-fuzzer minimize crash.dcm -t harness.exe --expect-rc 1
  dicom-fuzzer minimize crash.dcm -t harness.exe --expect-rc 1 \\
    --output minimal.dcm --timeout 5 --max-trials 200
        """,
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Crashing DICOM file to minimize",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=Path,
        required=True,
        help="Path to target executable (the harness)",
    )

    parser.add_argument(
        "--expect-rc",
        type=int,
        required=True,
        dest="expected_rc",
        help="Exit code that defines 'still crashes the same way'",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-trial subprocess timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--max-trials",
        type=int,
        default=500,
        dest="max_trials",
        help="Hard cap on subprocess invocations (default: 500)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output path for minimized .dcm (default: <input>.minimized.dcm)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print full traceback on error",
    )

    return parser


def _print_summary(result: MinimizeResult, output_path: Path) -> None:
    """Print a human-readable summary of the minimization."""
    pct = int(result.reduction_ratio * 100)
    print()
    print(f"[+] Minimized: {output_path}")
    print(
        f"    Elements:   {result.original_element_count} -> "
        f"{result.minimized_element_count} ({pct}% reduction)"
    )
    print(
        f"    File size:  {result.original_byte_size} -> "
        f"{result.minimized_byte_size} bytes"
    )
    print(f"    Trials:     {result.trial_count}")


class MinimizeCommand(SubcommandBase):
    """Minimize a crashing DICOM file."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the minimize subcommand."""
        if not args.input.exists():
            print(f"[-] Input file not found: {args.input}", file=sys.stderr)
            return 1
        if not args.target.exists():
            print(f"[-] Target executable not found: {args.target}", file=sys.stderr)
            return 1

        output_path = args.output or args.input.with_suffix(".minimized.dcm")
        print(f"[i] Minimizing {args.input}")
        print(f"    Target:     {args.target}")
        print(f"    Expect rc:  {args.expected_rc}")
        print(f"    Output:     {output_path}")

        try:
            result = minimize_dicom(
                crashing_path=args.input,
                target_exe=args.target,
                expected_returncode=args.expected_rc,
                timeout=args.timeout,
                max_trials=args.max_trials,
                output_path=output_path,
            )
        except MinimizationError as e:
            print(f"[-] {e}", file=sys.stderr)
            return 2

        _print_summary(result, output_path)
        return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for minimize subcommand."""
    return MinimizeCommand.main(argv)


if __name__ == "__main__":
    sys.exit(main())
