"""Corpus Subcommand for DICOM Fuzzer.

Corpus management utilities including:
- Corpus analysis and statistics
- Hash-based deduplication
- Corpus merging

NOTE: This CLI module provides basic corpus utilities.
For advanced minimization, import dicom_fuzzer.core.corpus_minimizer directly.
"""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path


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

For advanced minimization, use the Python API:
  from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer
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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
