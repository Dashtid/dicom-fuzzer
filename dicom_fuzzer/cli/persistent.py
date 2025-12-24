"""Persistent Subcommand for DICOM Fuzzer.

AFL-style persistent mode fuzzing for high-performance DICOM parser testing.

NOTE: This CLI module provides a simplified interface to the core persistent fuzzer.
For advanced usage, import dicom_fuzzer.core.persistent_fuzzer directly.
"""

import argparse
import sys
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for persistent subcommand."""
    parser = argparse.ArgumentParser(
        description="AFL-style persistent mode DICOM fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic persistent fuzzing with pydicom
  dicom-fuzzer persistent --corpus ./seeds --target pydicom

  # High-performance fuzzing with MOpt
  dicom-fuzzer persistent --corpus ./seeds --target pydicom --mopt

  # List available power schedules
  dicom-fuzzer persistent --list-schedules

For advanced testing, use the Python API:
  from dicom_fuzzer.core.persistent_fuzzer import PersistentFuzzer
        """,
    )

    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--corpus",
        type=str,
        metavar="DIR",
        help="Seed corpus directory",
    )
    action_group.add_argument(
        "--list-schedules",
        action="store_true",
        help="List available power schedules",
    )

    # Target options
    target_group = parser.add_argument_group("target options")
    target_group.add_argument(
        "--target",
        type=str,
        choices=["pydicom"],
        default="pydicom",
        help="Target parser (default: pydicom)",
    )
    target_group.add_argument(
        "--timeout",
        type=int,
        default=1000,
        metavar="MS",
        help="Execution timeout per input in milliseconds (default: 1000)",
    )

    # Fuzzing options
    fuzz_group = parser.add_argument_group("fuzzing options")
    fuzz_group.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=1000,
        metavar="N",
        help="Number of iterations (default: 1000)",
    )
    fuzz_group.add_argument(
        "--mopt",
        action="store_true",
        help="Enable MOpt adaptive mutation scheduling",
    )
    fuzz_group.add_argument(
        "--schedule",
        type=str,
        choices=["fast", "explore", "exploit"],
        default="fast",
        help="Power schedule algorithm (default: fast)",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        default="./persistent_output",
        metavar="DIR",
        help="Output directory (default: ./persistent_output)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_fuzz(args: argparse.Namespace) -> int:
    """Run persistent mode fuzzing."""
    corpus_dir = Path(args.corpus)

    if not corpus_dir.exists():
        print(f"[-] Corpus directory not found: {corpus_dir}")
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Persistent Mode")
    print("=" * 70)
    print(f"  Corpus:     {corpus_dir}")
    print(f"  Target:     {args.target}")
    print(f"  Iterations: {args.iterations}")
    print(f"  Schedule:   {args.schedule}")
    print(f"  MOpt:       {'Enabled' if args.mopt else 'Disabled'}")
    print(f"  Output:     {output_dir}")
    print("=" * 70 + "\n")

    try:
        from io import BytesIO

        import pydicom

        from dicom_fuzzer.core.persistent_fuzzer import (
            PersistentFuzzer,
            PersistentFuzzerConfig,
        )

        # Define target function for pydicom
        def pydicom_target(data: bytes) -> bool:
            try:
                pydicom.dcmread(BytesIO(data))
                return True
            except Exception:
                return False

        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            max_iterations=args.iterations,
            exec_timeout_ms=args.timeout,
            use_mopt=args.mopt,
        )

        fuzzer = PersistentFuzzer(target_func=pydicom_target, config=config)

        print("[i] Loading corpus...")
        fuzzer.load_corpus()

        print(f"[i] Starting fuzzing ({args.iterations} iterations)...")
        try:
            fuzzer.run()

            stats = fuzzer.get_statistics()
            print("\n[+] Fuzzing complete")
            print(f"    Statistics: {stats}")

        except KeyboardInterrupt:
            print("\n[i] Interrupted by user")
            stats = fuzzer.get_statistics()
            print(f"    Statistics: {stats}")

        return 0

    except ImportError as e:
        print(f"[-] Persistent fuzzer not available: {e}")
        return 1
    except Exception as e:
        print(f"[-] Fuzzing failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_list_schedules(args: argparse.Namespace) -> int:
    """List available power schedules."""
    print("\n" + "=" * 70)
    print("  Power Schedules")
    print("=" * 70 + "\n")

    schedules = [
        ("fast", "Fast schedule - prioritizes recently discovered seeds (default)"),
        ("explore", "Exploration-focused - broad coverage"),
        ("exploit", "Exploitation-focused - deep testing of interesting seeds"),
    ]

    for name, desc in schedules:
        print(f"  [{name}]")
        print(f"    {desc}")
        print()

    print("=" * 70)
    print("\nUsage: dicom-fuzzer persistent --corpus ./seeds --schedule <name>")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for persistent subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.corpus:
        return run_fuzz(args)
    elif args.list_schedules:
        return run_list_schedules(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
