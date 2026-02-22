"""Study-Level Mutation Subcommand for DICOM Fuzzer.

Study-level fuzzing targeting cross-series relationships and study-wide consistency.

NOTE: This CLI module provides a simplified interface to the core study mutator.
For advanced usage, import dicom_fuzzer.attacks.series.study_mutator directly.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Any


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for study subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer study",
        description="Study-level DICOM mutation for cross-series attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mutate study with cross-series reference attacks
  dicom-fuzzer study --study ./study_dir --strategy cross-series -o ./output

  # Output each series to its own folder (for individual testing)
  dicom-fuzzer study --study ./study_dir --per-series -o ./fuzzed_series

  # List available strategies
  dicom-fuzzer study --list-strategies

  # Apply aggressive patient consistency attacks
  dicom-fuzzer study --study ./study --strategy patient-consistency --severity aggressive

For advanced usage, use the Python API:
  from dicom_fuzzer.attacks.series.study_mutator import StudyMutator, StudyMutationStrategy
        """,
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--study",
        type=str,
        metavar="DIR",
        help="Path to study directory containing DICOM series",
    )
    action_group.add_argument(
        "--list-strategies",
        action="store_true",
        help="List available study mutation strategies",
    )

    mutation_group = parser.add_argument_group("mutation options")
    mutation_group.add_argument(
        "--strategy",
        type=str,
        choices=[
            "cross-series",
            "frame-of-reference",
            "patient-consistency",
            "study-metadata",
            "mixed-modality",
            "all",
        ],
        default="all",
        help="Mutation strategy (default: all)",
    )
    mutation_group.add_argument(
        "--severity",
        type=str,
        choices=["minimal", "moderate", "aggressive", "extreme"],
        default="moderate",
        help="Mutation severity (default: moderate)",
    )
    mutation_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=5,
        metavar="N",
        help="Number of mutations to apply (default: 5)",
    )
    mutation_group.add_argument(
        "--per-series",
        action="store_true",
        help="Output each mutated series to its own folder (for individual testing)",
    )

    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        default="./artifacts/study",
        help="Output directory for mutated study (default: ./artifacts/study)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_list_strategies() -> int:
    """List available study mutation strategies."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Study Mutation Strategies")
    print("=" * 70 + "\n")

    strategies = [
        ("cross-series", "Cross-series reference attacks (ReferencedSeriesSequence)"),
        ("frame-of-reference", "FrameOfReferenceUID manipulation for registration"),
        ("patient-consistency", "Patient demographic conflicts across series"),
        ("study-metadata", "Study-level metadata corruption"),
        ("mixed-modality", "Mixed modality study injection"),
        ("all", "Apply all strategies"),
    ]

    print("Available strategies:\n")
    for name, description in strategies:
        print(f"  {name:22} - {description}")

    print("\n[i] Use --strategy <name> to select a specific strategy")
    return 0


def _save_mutated_study(output_path: Path, fuzzed_study: list[Any]) -> None:
    """Save mutated study datasets to output directory (all series together)."""
    for idx, datasets in enumerate(fuzzed_study):
        series_dir = output_path / f"series_{idx:03d}"
        series_dir.mkdir(parents=True, exist_ok=True)
        for ds_idx, ds in enumerate(datasets):
            ds.save_as(str(series_dir / f"slice_{ds_idx:04d}.dcm"))


def _save_per_series(
    output_path: Path, fuzzed_study: list[Any], series_names: list[str]
) -> list[Path]:
    """Save each mutated series to its own folder for individual testing.

    Args:
        output_path: Base output directory
        fuzzed_study: List of series datasets
        series_names: Original series folder names for naming output folders

    Returns:
        List of paths to created series folders

    """
    created_folders = []
    for idx, datasets in enumerate(fuzzed_study):
        # Use original series name if available, otherwise use index
        if idx < len(series_names) and series_names[idx]:
            folder_name = f"{idx:03d}_{series_names[idx]}"
        else:
            folder_name = f"series_{idx:03d}"

        series_dir = output_path / folder_name
        series_dir.mkdir(parents=True, exist_ok=True)

        for ds_idx, ds in enumerate(datasets):
            ds.save_as(str(series_dir / f"slice_{ds_idx:04d}.dcm"))

        created_folders.append(series_dir)

    return created_folders


def run_study_mutation(args: argparse.Namespace) -> int:
    """Execute study mutation."""
    per_series = getattr(args, "per_series", False)

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Study-Level Mutation")
    print("=" * 70)
    print(f"  Study:    {args.study}")
    print(f"  Strategy: {args.strategy}")
    print(f"  Severity: {args.severity}")
    print(f"  Count:    {args.count}")
    print(f"  Output:   {args.output}")
    if per_series:
        print("  Mode:     per-series (one folder per series)")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.attacks.series.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        study_path = Path(args.study)
        output_path = Path(args.output)

        if not study_path.exists():
            print(f"[-] Study directory not found: {study_path}")
            return 1

        output_path.mkdir(parents=True, exist_ok=True)

        print("[i] Loading study...")
        mutator = StudyMutator(severity=args.severity)
        study = mutator.load_study(study_path)
        print(f"[+] Loaded study with {len(study.series_list)} series")

        strategy_map = {
            "cross-series": StudyMutationStrategy.CROSS_SERIES_REFERENCE,
            "frame-of-reference": StudyMutationStrategy.FRAME_OF_REFERENCE,
            "patient-consistency": StudyMutationStrategy.PATIENT_CONSISTENCY,
            "study-metadata": StudyMutationStrategy.STUDY_METADATA,
            "mixed-modality": StudyMutationStrategy.MIXED_MODALITY_STUDY,
        }
        strategies = (
            list(strategy_map.values())
            if args.strategy == "all"
            else [strategy_map[args.strategy]]
        )

        total_records = []
        fuzzed_study = None
        for strategy in strategies:
            print(f"[i] Applying {strategy.value}...")
            fuzzed_study, records = mutator.mutate_study(
                study, strategy=strategy, mutation_count=args.count
            )
            total_records.extend(records)
            if args.verbose:
                for record in records:
                    print(
                        f"    - {record.strategy}: {record.tag} -> {record.mutated_value}"
                    )

        print(f"\n[+] Applied {len(total_records)} mutations")
        print("[i] Saving mutated study...")
        assert fuzzed_study is not None, "No strategies applied"

        if per_series:
            # Extract series folder names from original paths
            series_names = []
            for series in study.series_list:
                if series.slices:
                    # Get parent folder name of first slice
                    parent_name = Path(series.slices[0]).parent.name
                    series_names.append(parent_name)
                else:
                    series_names.append("")

            created_folders = _save_per_series(output_path, fuzzed_study, series_names)
            print(f"\n[+] Created {len(created_folders)} series folders:")
            for folder in created_folders:
                print(f"    - {folder}")
        else:
            _save_mutated_study(output_path, fuzzed_study)
            print(f"\n[+] Mutated study saved to: {output_path}")

        return 0

    except ImportError as e:
        print(f"[-] Module not available: {e}")
        print("[i] Ensure dicom_fuzzer.attacks.series.study_mutator is installed")
        return 1
    except Exception as e:
        print(f"[-] Failed: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for study subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.list_strategies:
        return run_list_strategies()
    elif args.study:
        return run_study_mutation(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
