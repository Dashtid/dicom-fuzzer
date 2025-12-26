"""Corpus Subcommand for DICOM Fuzzer.

Corpus management utilities including:
- Corpus analysis and statistics
- Hash-based deduplication
- Corpus merging
- Study-level crash minimization

NOTE: This CLI module provides basic corpus utilities.
For advanced minimization, import dicom_fuzzer.core.corpus_minimizer directly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for corpus subcommand."""
    parser = argparse.ArgumentParser(
        description="DICOM fuzzing corpus management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze corpus statistics
  dicom-fuzzer corpus --analyze ./corpus

  # Deduplicate by content hash
  dicom-fuzzer corpus --dedup ./corpus -o ./unique

  # Merge multiple corpora
  dicom-fuzzer corpus --merge ./fuzzer1/corpus ./fuzzer2/corpus -o ./merged

  # Minimize crashing study to find trigger slice
  dicom-fuzzer corpus --minimize-study ./crash_study --target ./viewer.exe -o ./minimized

  # Generate mutated study corpus for fuzzing campaigns
  dicom-fuzzer corpus --generate-study ./multi_series_study -o ./corpus \\
      --count 50 --strategy all --severity aggressive

For advanced minimization, use the Python API:
  from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer
  from dicom_fuzzer.core.study_minimizer import StudyMinimizer
        """,
    )

    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--analyze",
        type=str,
        metavar="DIR",
        help="Analyze corpus and show statistics",
    )
    action_group.add_argument(
        "--dedup",
        type=str,
        metavar="DIR",
        help="Deduplicate corpus by content hash",
    )
    action_group.add_argument(
        "--merge",
        nargs="+",
        metavar="DIR",
        help="Merge multiple corpora into one",
    )
    action_group.add_argument(
        "--minimize-study",
        type=str,
        metavar="DIR",
        help="Minimize a crashing 3D study to find trigger slice(s)",
    )
    action_group.add_argument(
        "--generate-study",
        type=str,
        metavar="DIR",
        help="Generate mutated study corpus from source study directory",
    )

    # Target options (for minimize-study)
    target_group = parser.add_argument_group("target options (for --minimize-study)")
    target_group.add_argument(
        "-t",
        "--target",
        type=str,
        metavar="EXE",
        help="Target executable to test with",
    )
    target_group.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout per test in seconds (default: 30)",
    )
    target_group.add_argument(
        "--max-iterations",
        type=int,
        default=100,
        help="Maximum minimization iterations (default: 100)",
    )

    # Generation options (for --generate-study)
    gen_group = parser.add_argument_group("generation options (for --generate-study)")
    gen_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=50,
        metavar="N",
        help="Number of mutated studies to generate (default: 50)",
    )
    gen_group.add_argument(
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
    gen_group.add_argument(
        "--severity",
        type=str,
        choices=["minimal", "moderate", "aggressive", "extreme"],
        default="aggressive",
        help="Mutation severity (default: aggressive)",
    )
    gen_group.add_argument(
        "--mutations-per-study",
        type=int,
        default=5,
        metavar="N",
        help="Number of mutations per study (default: 5)",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        help="Output directory",
    )
    output_group.add_argument(
        "--format",
        type=str,
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_analyze(args: argparse.Namespace) -> int:
    """Analyze corpus and show statistics."""
    corpus_dir = Path(args.analyze)

    if not corpus_dir.exists():
        print(f"[-] Directory not found: {corpus_dir}")
        return 1

    print("\n" + "=" * 70)
    print("  Corpus Analysis")
    print("=" * 70)
    print(f"  Directory: {corpus_dir}")
    print("=" * 70 + "\n")

    try:
        # Collect basic statistics
        files = list(corpus_dir.glob("*.dcm")) + list(corpus_dir.glob("*.dicom"))
        if not files:
            files = [f for f in corpus_dir.glob("*") if f.is_file()]

        total_size = sum(f.stat().st_size for f in files if f.is_file())
        sizes = [f.stat().st_size for f in files if f.is_file()]

        # Compute statistics as typed local variables
        avg_size = int(sum(sizes) / len(sizes)) if sizes else 0
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        total_mb = total_size / (1024 * 1024)

        stats = {
            "directory": str(corpus_dir),
            "total_files": len(files),
            "total_size_bytes": total_size,
            "total_size_mb": total_mb,
            "avg_size_bytes": avg_size,
            "min_size_bytes": min_size,
            "max_size_bytes": max_size,
        }

        if args.format == "json":
            print(json.dumps(stats, indent=2))
        else:
            avg_kb = avg_size / 1024
            max_kb = max_size / 1024
            print(f"  Total files:    {len(files)}")
            print(f"  Total size:     {total_mb:.2f} MB")
            print(f"  Average size:   {avg_kb:.2f} KB")
            print(f"  Min size:       {min_size} bytes")
            print(f"  Max size:       {max_kb:.2f} KB")

            # Size distribution
            print("\n  Size Distribution:")
            buckets = [
                (1024, "<1KB"),
                (10240, "1-10KB"),
                (102400, "10-100KB"),
                (1048576, "100KB-1MB"),
                (float("inf"), ">1MB"),
            ]
            prev = 0.0
            for limit, label in buckets:
                count = sum(1 for s in sizes if prev <= s < limit)
                bar = "#" * (count * 40 // max(len(sizes), 1))
                print(f"    {label:12} {count:5} {bar}")
                prev = limit

        return 0

    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        return 1


def run_dedup(args: argparse.Namespace) -> int:
    """Deduplicate corpus by content hash."""
    input_dir = Path(args.dedup)

    if not input_dir.exists():
        print(f"[-] Directory not found: {input_dir}")
        return 1

    output_dir = (
        Path(args.output)
        if args.output
        else input_dir.parent / f"{input_dir.name}_unique"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  Corpus Deduplication")
    print("=" * 70)
    print(f"  Input:  {input_dir}")
    print(f"  Output: {output_dir}")
    print("=" * 70 + "\n")

    try:
        files = list(input_dir.glob("*"))
        seen_hashes: set[str] = set()
        unique_count = 0
        dup_count = 0

        print("[i] Computing hashes...")
        for f in files:
            if not f.is_file():
                continue

            file_hash = hashlib.sha256(f.read_bytes()).hexdigest()

            if file_hash not in seen_hashes:
                seen_hashes.add(file_hash)
                shutil.copy2(f, output_dir / f.name)
                unique_count += 1
            else:
                dup_count += 1
                if args.verbose:
                    print(f"  [DUP] {f.name}")

        print("\n[+] Deduplication complete")
        print(f"    Original:   {len(files)}")
        print(f"    Unique:     {unique_count}")
        print(f"    Duplicates: {dup_count}")
        print(f"\n[+] Output: {output_dir}")

        return 0

    except Exception as e:
        print(f"[-] Deduplication failed: {e}")
        return 1


def run_merge(args: argparse.Namespace) -> int:
    """Merge multiple corpora into one."""
    if not args.output:
        print("[-] --output is required for merge")
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  Corpus Merge")
    print("=" * 70)
    print(f"  Sources: {len(args.merge)}")
    print(f"  Output:  {output_dir}")
    print("=" * 70 + "\n")

    try:
        seen_hashes: set[str] = set()
        total_files = 0
        merged_files = 0

        for source in args.merge:
            source_dir = Path(source)
            if not source_dir.exists():
                print(f"  [!] Skipping missing: {source}")
                continue

            print(f"[i] Processing {source}...")
            for f in source_dir.glob("*"):
                if not f.is_file():
                    continue

                total_files += 1
                file_hash = hashlib.sha256(f.read_bytes()).hexdigest()

                if file_hash not in seen_hashes:
                    seen_hashes.add(file_hash)
                    # Use hash prefix to avoid name collisions
                    new_name = f"{file_hash[:8]}_{f.name}"
                    shutil.copy2(f, output_dir / new_name)
                    merged_files += 1

        print("\n[+] Merge complete")
        print(f"    Total processed: {total_files}")
        print(f"    Merged (unique): {merged_files}")
        print(f"\n[+] Output: {output_dir}")

        return 0

    except Exception as e:
        print(f"[-] Merge failed: {e}")
        return 1


def run_minimize_study(args: argparse.Namespace) -> int:
    """Minimize a crashing 3D study to find trigger slice(s)."""
    from dicom_fuzzer.core.study_minimizer import (
        MinimizationConfig,
        StudyMinimizer,
        create_crash_test_from_runner,
    )
    from dicom_fuzzer.core.target_runner import TargetRunner

    study_dir = Path(args.minimize_study)

    if not study_dir.exists():
        print(f"[-] Study directory not found: {study_dir}")
        return 1

    if not args.target:
        print("[-] --target is required for --minimize-study")
        return 1

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"[-] Target executable not found: {target_path}")
        return 1

    output_dir = (
        Path(args.output)
        if args.output
        else study_dir.parent / f"{study_dir.name}_minimized"
    )

    print("\n" + "=" * 70)
    print("  Study Minimization")
    print("=" * 70)
    print(f"  Study:   {study_dir}")
    print(f"  Target:  {target_path}")
    print(f"  Output:  {output_dir}")
    print(f"  Timeout: {args.timeout}s")
    print("=" * 70 + "\n")

    try:
        # Initialize target runner
        print("[i] Initializing target runner...")
        runner = TargetRunner(
            target_executable=str(target_path),
            timeout=args.timeout,
            crash_dir=str(output_dir / "crashes"),
        )

        # Create crash test function
        crash_test = create_crash_test_from_runner(runner)

        # Configure minimizer
        config = MinimizationConfig(
            max_iterations=args.max_iterations,
            timeout_per_test=args.timeout,
            verify_final_result=True,
        )

        # Run minimization
        print("[i] Starting minimization...")
        minimizer = StudyMinimizer(crash_test, config)
        result = minimizer.minimize(study_dir, output_dir)

        # Print results
        print("\n" + "=" * 70)
        print("  Minimization Results")
        print("=" * 70)
        print(f"  Original slices:  {result.original_slice_count}")
        print(f"  Minimal slices:   {result.minimal_slice_count}")
        print(f"  Reduction:        {(1 - result.reduction_ratio) * 100:.1f}%")
        print(f"  Iterations:       {result.iterations}")
        print(f"  Time:             {result.minimization_time_seconds:.1f}s")
        print(f"  Crash reproducible: {'Yes' if result.crash_reproducible else 'No'}")

        if result.trigger_slice:
            print(f"\n  [+] TRIGGER SLICE FOUND: {result.trigger_slice.name}")
            print("      This single slice triggers the crash!")
        elif result.minimal_slice_count > 1:
            print(
                f"\n  [i] Multi-slice bug: requires {result.minimal_slice_count} slices"
            )

        if result.notes:
            print("\n  Notes:")
            for note in result.notes:
                print(f"    - {note}")

        print(f"\n[+] Minimized study saved to: {output_dir}")
        print("=" * 70 + "\n")

        return 0

    except FileNotFoundError as e:
        print(f"[-] File not found: {e}")
        return 1
    except Exception as e:
        print(f"[-] Minimization failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_generate_study(args: argparse.Namespace) -> int:
    """Generate mutated study corpus from a source study.

    Creates multiple mutated versions of a source study using study-level
    mutation strategies and saves them to a corpus for fuzzing campaigns.
    """
    import tempfile

    from dicom_fuzzer.core.study_corpus import StudyCorpusManager
    from dicom_fuzzer.strategies.study_mutator import (
        StudyMutationStrategy,
        StudyMutator,
    )

    source_dir = Path(args.generate_study)

    if not source_dir.exists():
        print(f"[-] Source study not found: {source_dir}")
        return 1

    if not args.output:
        print("[-] --output is required for --generate-study")
        return 1

    output_dir = Path(args.output)

    print("\n" + "=" * 70)
    print("  Study Corpus Generation")
    print("=" * 70)
    print(f"  Source:     {source_dir}")
    print(f"  Output:     {output_dir}")
    print(f"  Count:      {args.count}")
    print(f"  Strategy:   {args.strategy}")
    print(f"  Severity:   {args.severity}")
    print(f"  Mutations:  {args.mutations_per_study} per study")
    print("=" * 70 + "\n")

    try:
        # Map CLI strategy names to enum values
        strategy_map = {
            "cross-series": StudyMutationStrategy.CROSS_SERIES_REFERENCE,
            "frame-of-reference": StudyMutationStrategy.FRAME_OF_REFERENCE,
            "patient-consistency": StudyMutationStrategy.PATIENT_CONSISTENCY,
            "study-metadata": StudyMutationStrategy.STUDY_METADATA,
            "mixed-modality": StudyMutationStrategy.MIXED_MODALITY_STUDY,
        }

        if args.strategy == "all":
            strategies = list(StudyMutationStrategy)
        else:
            strategies = [strategy_map[args.strategy]]

        # Initialize mutator and corpus manager
        mutator = StudyMutator(severity=args.severity)
        corpus = StudyCorpusManager(output_dir)

        # Load source study
        print("[i] Loading source study...")
        source_study = mutator.load_study(source_dir)
        print(
            f"[+] Loaded: {source_study.series_count} series, "
            f"{source_study.get_total_slices()} slices"
        )

        # Generate mutated studies
        print(f"\n[i] Generating {args.count} mutated studies...")
        generated = 0
        errors = 0

        for i in range(args.count):
            strategy = strategies[i % len(strategies)]

            try:
                # Reload study for fresh mutation each time
                study = mutator.load_study(source_dir)

                # Apply mutations
                mutated_datasets, records = mutator.mutate_study(
                    study,
                    strategy=strategy,
                    mutation_count=args.mutations_per_study,
                )

                # Save mutated study to temp directory
                with tempfile.TemporaryDirectory(prefix="gen_study_") as temp_dir:
                    temp_path = Path(temp_dir)
                    study_dir = temp_path / f"study_{i:04d}"
                    study_dir.mkdir()

                    # Save each series
                    for series_idx, datasets in enumerate(mutated_datasets):
                        series_dir = study_dir / f"series_{series_idx:03d}"
                        series_dir.mkdir(parents=True, exist_ok=True)
                        for ds_idx, ds in enumerate(datasets):
                            ds.save_as(str(series_dir / f"slice_{ds_idx:04d}.dcm"))

                    # Add to corpus (copies files)
                    entry = corpus.add_study(study_dir, copy_to_corpus=True)

                    # Record mutations
                    for record in records:
                        mutation_desc = f"{record.strategy}:{record.tag}"
                        corpus.record_mutation(entry.study_id, mutation_desc)

                generated += 1

                if args.verbose:
                    print(
                        f"  [{i + 1}/{args.count}] {strategy.value} - "
                        f"{len(records)} mutations"
                    )
                elif (i + 1) % 10 == 0:
                    print(f"  Progress: {i + 1}/{args.count}")

            except Exception as e:
                errors += 1
                if args.verbose:
                    print(f"  [-] Error at {i + 1}: {e}")

        # Save corpus index
        corpus.save_index()

        # Summary
        print("\n" + "=" * 70)
        print("  Generation Complete")
        print("=" * 70)
        print(f"  Generated:  {generated} studies")
        print(f"  Errors:     {errors}")
        print(f"  Corpus:     {output_dir}")
        print(f"  Index:      {corpus.index_path}")

        stats = corpus.get_statistics()
        print(f"\n  Total slices: {stats['total_slices']}")
        print(f"  Modalities:   {stats['modality_distribution']}")
        print("=" * 70 + "\n")

        return 0

    except Exception as e:
        print(f"[-] Generation failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for corpus subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.analyze:
        return run_analyze(args)
    elif args.dedup:
        return run_dedup(args)
    elif args.merge:
        return run_merge(args)
    elif args.minimize_study:
        return run_minimize_study(args)
    elif args.generate_study:
        return run_generate_study(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
