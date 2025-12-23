"""Target Subcommand for DICOM Fuzzer.

Auto-detect target characteristics and configure optimal fuzzing parameters.

Usage:
    dicom-fuzzer target --executable ./app.exe --corpus ./seeds
    dicom-fuzzer target --executable ./app.exe --json > config.json

"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for target subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer target",
        description="Calibrate fuzzing parameters for a target application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Calibrate target with corpus
  dicom-fuzzer target --executable ./app.exe --corpus ./seeds

  # Output JSON for automation
  dicom-fuzzer target --executable ./app.exe --json

  # Verbose output for debugging
  dicom-fuzzer target --executable ./app.exe -v

Calibration Phases:
  1. Target Detection - Classify as CLI/GUI application
  2. Timeout Calibration - Calculate optimal timeout based on execution speed
  3. Crash Detection - Validate crash detection is working
  4. Corpus Validation - Quick-test corpus for problematic seeds
        """,
    )

    parser.add_argument(
        "--executable",
        "-e",
        type=str,
        required=True,
        metavar="PATH",
        help="Path to target executable",
    )

    parser.add_argument(
        "--corpus",
        "-c",
        type=str,
        metavar="DIR",
        help="Path to seed corpus directory",
    )

    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output results as JSON (for automation)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output with per-run details",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for target subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    target_path = Path(args.executable)
    if not target_path.exists():
        print(f"[-] Target not found: {target_path}", file=sys.stderr)
        return 1

    corpus_path = Path(args.corpus) if args.corpus else None
    if corpus_path and not corpus_path.exists():
        print(f"[-] Corpus not found: {corpus_path}", file=sys.stderr)
        return 1

    if not args.json:
        print("\n" + "=" * 70)
        print("  DICOM Fuzzer - Target Calibration")
        print("=" * 70)
        print(f"  Target: {target_path}")
        if corpus_path:
            print(f"  Corpus: {corpus_path}")
        print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.core.target_calibrator import calibrate_target

        result = calibrate_target(
            target=target_path,
            corpus=corpus_path,
            verbose=args.verbose,
        )

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            result.print_summary()

        return 0

    except FileNotFoundError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[-] Calibration failed: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
