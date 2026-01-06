"""Calibration Mutation Subcommand for DICOM Fuzzer.

Measurement and calibration fuzzing targeting viewer calculations and measurements.

NOTE: This CLI module provides a simplified interface to the core calibration fuzzer.
For advanced usage, import dicom_fuzzer.strategies.calibration_fuzzer directly.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for calibrate subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer calibrate",
        description="Calibration and measurement mutation for DICOM images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz calibration parameters in a DICOM file
  dicom-fuzzer calibrate --input image.dcm --category pixel-spacing -o ./output

  # List calibration categories
  dicom-fuzzer calibrate --list-categories

  # Fuzz Hounsfield unit rescale with extreme severity
  dicom-fuzzer calibrate --input ct.dcm --category hounsfield --severity extreme

For advanced usage, use the Python API:
  from dicom_fuzzer.strategies.calibration_fuzzer import CalibrationFuzzer
        """,
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--input",
        type=str,
        metavar="FILE",
        help="Input DICOM file to mutate",
    )
    action_group.add_argument(
        "--list-categories",
        action="store_true",
        help="List available calibration mutation categories",
    )

    mutation_group = parser.add_argument_group("mutation options")
    mutation_group.add_argument(
        "--category",
        type=str,
        choices=[
            "pixel-spacing",
            "hounsfield",
            "window-level",
            "slice-thickness",
            "all",
        ],
        default="all",
        help="Calibration category (default: all)",
    )
    mutation_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=10,
        metavar="N",
        help="Number of mutations (default: 10)",
    )
    mutation_group.add_argument(
        "--severity",
        type=str,
        choices=["minimal", "moderate", "aggressive", "extreme"],
        default="moderate",
        help="Mutation severity (default: moderate)",
    )

    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        default="./artifacts/calibrate",
        help="Output directory for mutated files (default: ./artifacts/calibrate)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_list_categories() -> int:
    """List available calibration categories."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Calibration Mutation Categories")
    print("=" * 70 + "\n")

    categories = [
        (
            "pixel-spacing",
            "PixelSpacing/ImagerPixelSpacing attacks",
            [
                "mismatch - PixelSpacing vs ImagerPixelSpacing conflict",
                "zero - Zero pixel spacing (division by zero)",
                "negative - Negative pixel spacing values",
                "extreme - Extreme scaling factors",
                "nan - NaN/Inf values",
                "inconsistent - Non-square pixels",
            ],
        ),
        (
            "hounsfield",
            "RescaleSlope/Intercept HU manipulation",
            [
                "zero_slope - RescaleSlope = 0 (division by zero)",
                "negative_slope - Negative rescale slope",
                "extreme_large - Very large slope values",
                "nan_slope - NaN rescale slope",
                "inf_intercept - Infinite intercept",
                "hu_overflow - Values causing HU overflow",
            ],
        ),
        (
            "window-level",
            "WindowCenter/WindowWidth display attacks",
            [
                "zero_width - WindowWidth = 0",
                "negative_width - Negative window width",
                "extreme_center - Extreme center values",
                "nan_values - NaN window parameters",
                "multiple_conflict - Conflicting window presets",
            ],
        ),
        (
            "slice-thickness",
            "SliceThickness calibration attacks",
            [
                "zero - SliceThickness = 0",
                "negative - Negative thickness",
                "mismatch - Thickness vs actual spacing mismatch",
            ],
        ),
    ]

    for name, description, attacks in categories:
        print(f"  {name}")
        print(f"    {description}")
        print("    Attack types:")
        for attack in attacks:
            print(f"      - {attack}")
        print()

    print("[i] Use --category <name> to select a specific category")
    return 0


def _apply_category_mutations(
    ds_copy: Dataset,
    categories: list[str],
    category_methods: dict,
    verbose: bool,
) -> Dataset:
    """Apply mutations for specified categories."""
    for category in categories:
        method = category_methods[category]
        try:
            fuzzed_ds, records = method(ds_copy)
            ds_copy = fuzzed_ds
            if verbose:
                for record in records:
                    print(
                        f"  [{category}] {record.attack_type}: {record.original_value} -> {record.mutated_value}"
                    )
        except Exception as e:
            if verbose:
                print(f"  [!] {category} skipped: {e}")
    return ds_copy


def run_calibration_mutation(args: argparse.Namespace) -> int:
    """Execute calibration mutation."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Calibration Mutation")
    print("=" * 70)
    print(f"  Input:    {args.input}")
    print(f"  Category: {args.category}")
    print(f"  Severity: {args.severity}")
    print(f"  Count:    {args.count}")
    print(f"  Output:   {args.output}")
    print("=" * 70 + "\n")

    try:
        import pydicom

        from dicom_fuzzer.strategies.calibration_fuzzer import CalibrationFuzzer

        input_path = Path(args.input)
        output_path = Path(args.output)

        if not input_path.exists():
            print(f"[-] Input file not found: {input_path}")
            return 1

        output_path.mkdir(parents=True, exist_ok=True)

        print("[i] Loading DICOM file...")
        dataset = pydicom.dcmread(str(input_path))
        print(
            f"[+] Loaded: {dataset.PatientName if hasattr(dataset, 'PatientName') else 'Unknown'}"
        )

        fuzzer = CalibrationFuzzer(severity=args.severity)
        category_methods = {
            "pixel-spacing": fuzzer.fuzz_pixel_spacing,
            "hounsfield": fuzzer.fuzz_hounsfield_rescale,
            "window-level": fuzzer.fuzz_window_level,
            "slice-thickness": fuzzer.fuzz_slice_thickness,
        }

        categories = (
            list(category_methods.keys()) if args.category == "all" else [args.category]
        )

        generated = 0
        for i in range(args.count):
            ds_copy = dataset.copy()
            ds_copy = _apply_category_mutations(
                ds_copy, categories, category_methods, args.verbose
            )
            output_file = output_path / f"calibration_{i:04d}.dcm"
            pydicom.dcmwrite(str(output_file), ds_copy)
            generated += 1

        print(f"\n[+] Generated {generated} mutated files in: {output_path}")
        return 0

    except ImportError as e:
        print(f"[-] Module not available: {e}")
        print("[i] Ensure dicom_fuzzer.strategies.calibration_fuzzer is installed")
        return 1
    except Exception as e:
        print(f"[-] Failed: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for calibrate subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.list_categories:
        return run_list_categories()
    elif args.input:
        return run_calibration_mutation(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
