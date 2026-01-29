"""State-Aware Fuzzing Subcommand for DICOM Fuzzer.

Protocol state machine fuzzing for DICOM network communication.

NOTE: This CLI module provides a simplified interface to the core state fuzzer.
For advanced usage, import dicom_fuzzer.core.state_aware_fuzzer directly.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for state subcommand."""
    parser = argparse.ArgumentParser(
        description="Protocol state machine fuzzing for DICOM network services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run state-aware fuzzing with corpus
  dicom-fuzzer state --fuzz --corpus ./seeds -n 1000

  # Export state machine to JSON
  dicom-fuzzer state --export-sm state_machine.json

  # List known protocol states
  dicom-fuzzer state --list-states

For advanced testing, use the Python API:
  from dicom_fuzzer.strategies.robustness.network.stateful.state_aware_fuzzer import StateAwareFuzzer
        """,
    )

    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--fuzz",
        action="store_true",
        help="Run state-aware fuzzing campaign",
    )
    action_group.add_argument(
        "--export-sm",
        type=str,
        metavar="FILE",
        help="Export state machine to JSON file",
    )
    action_group.add_argument(
        "--list-states",
        action="store_true",
        help="List known DICOM protocol states",
    )

    # Fuzzing options
    fuzz_group = parser.add_argument_group("fuzzing options")
    fuzz_group.add_argument(
        "--corpus",
        type=str,
        metavar="DIR",
        help="Seed corpus directory",
    )
    fuzz_group.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=1000,
        metavar="N",
        help="Maximum iterations (default: 1000)",
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
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_fuzz(args: argparse.Namespace) -> int:
    """Run state-aware fuzzing."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - State-Aware Protocol Fuzzing")
    print("=" * 70)
    print(f"  Iterations: {args.iterations}")
    if args.corpus:
        print(f"  Corpus:     {args.corpus}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.strategies.robustness.network.stateful.state_aware_fuzzer import StateAwareFuzzer

        print("[i] Initializing state-aware fuzzer...")
        fuzzer = StateAwareFuzzer()

        # Load corpus if provided
        if args.corpus:
            corpus_path = Path(args.corpus)
            if corpus_path.exists():
                seeds: list[bytes] = []
                for seed_file in corpus_path.glob("*.dcm"):
                    with open(seed_file, "rb") as f:
                        seeds.append(f.read())
                if seeds:
                    fuzzer.add_seed(seeds)
                print(f"[+] Loaded {len(seeds)} seeds from {args.corpus}")

        print(f"[i] Running {args.iterations} iterations...")
        fuzzer.run(iterations=args.iterations)

        # Get statistics
        stats = fuzzer.get_statistics()
        print("\n[+] Fuzzing complete")
        print(f"    Statistics: {json.dumps(stats, indent=2)}")

        # Save results if output specified
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            fuzzer.save_corpus(str(output_dir / "corpus"))
            print(f"\n[+] Results saved to {args.output}")

        return 0

    except ImportError as e:
        print(f"[-] State fuzzer not available: {e}")
        return 1
    except Exception as e:
        print(f"[-] Fuzzing failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_export_sm(args: argparse.Namespace) -> int:
    """Export state machine to file."""
    output_file = Path(args.export_sm)

    print("\n" + "=" * 70)
    print("  DICOM Protocol State Machine Export")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.strategies.robustness.network.stateful.state_aware_fuzzer import StateAwareFuzzer

        fuzzer = StateAwareFuzzer()
        sm_data: dict[str, Any] = fuzzer.export_state_machine()

        with open(output_file, "w") as f:
            json.dump(sm_data, f, indent=2)

        print(f"[+] State machine exported to {output_file}")
        return 0

    except Exception as e:
        print(f"[-] Export failed: {e}")
        return 1


def run_list_states(args: argparse.Namespace) -> int:
    """List known DICOM protocol states."""
    print("\n" + "=" * 70)
    print("  DICOM Protocol States (DIMSE)")
    print("=" * 70 + "\n")

    states = [
        ("STA1", "Idle", "No association"),
        ("STA2", "Transport Open", "TCP connected, awaiting A-ASSOCIATE-RQ"),
        ("STA3", "Awaiting Response", "Waiting for accept/reject"),
        ("STA5", "Association Requested", "Awaiting A-ASSOCIATE-AC/RJ"),
        ("STA6", "Established", "Ready for DIMSE operations"),
        ("STA7", "Awaiting Release", "Release requested"),
        ("STA13", "Closing", "Awaiting connection close"),
    ]

    for state_id, name, desc in states:
        print(f"  [{state_id}] {name}")
        print(f"          {desc}")
        print()

    print("=" * 70)
    print("\nReferences: DICOM PS3.7/PS3.8")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for state subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.fuzz:
        return run_fuzz(args)
    elif args.export_sm:
        return run_export_sm(args)
    elif args.list_states:
        return run_list_states(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
