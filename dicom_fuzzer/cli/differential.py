"""Differential Subcommand for DICOM Fuzzer.

Cross-parser differential testing to find parsing discrepancies.

NOTE: This CLI module provides a simplified interface to the core differential fuzzer.
For advanced usage, import dicom_fuzzer.core.differential_fuzzer directly.
"""

import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for differential subcommand."""
    parser = argparse.ArgumentParser(
        description="Differential testing across DICOM parser implementations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single file across all available parsers
  dicom-fuzzer differential --test input.dcm

  # Test directory of DICOM files
  dicom-fuzzer differential --test-dir ./corpus -o ./results

  # List available parsers
  dicom-fuzzer differential --list-parsers

For advanced testing, use the Python API:
  from dicom_fuzzer.core.differential_fuzzer import DifferentialFuzzer
        """,
    )

    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--test",
        type=str,
        metavar="FILE",
        help="Test single DICOM file across parsers",
    )
    action_group.add_argument(
        "--test-dir",
        type=str,
        metavar="DIR",
        help="Test directory of DICOM files",
    )
    action_group.add_argument(
        "--list-parsers",
        action="store_true",
        help="List available parser implementations",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        help="Output directory for results",
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


def run_test(args: argparse.Namespace) -> int:
    """Test single file across parsers."""
    input_file = Path(args.test)

    if not input_file.exists():
        print(f"[-] File not found: {input_file}")
        return 1

    print("\n" + "=" * 70)
    print("  DICOM Differential Testing")
    print("=" * 70)
    print(f"  File: {input_file}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.core.differential_fuzzer import (
            DifferentialFuzzer,
            DifferentialFuzzerConfig,
        )

        config = DifferentialFuzzerConfig()
        fuzzer = DifferentialFuzzer(config=config)

        print("[i] Testing file...")
        result = fuzzer.test_file(input_file)

        # Get statistics
        stats = fuzzer.get_statistics()

        if result.differences:
            print(f"\n[!] Found {len(result.differences)} differences")
            for diff in result.differences:
                print(f"  - {diff}")
        else:
            print("\n[+] No differences found - all parsers agree")

        print(f"\n    Statistics: {json.dumps(stats, indent=2)}")

        # Save results
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            report_file = output_dir / f"diff_{input_file.stem}.{args.format}"

            with open(report_file, "w") as f:
                if args.format == "json":
                    json.dump(
                        {
                            "file": str(input_file),
                            "differences": result.differences,
                            "stats": stats,
                        },
                        f,
                        indent=2,
                        default=str,
                    )
                else:
                    f.write(f"File: {input_file}\n")
                    f.write(f"Differences: {len(result.differences)}\n")
                    for diff in result.differences:
                        f.write(f"  - {diff}\n")

            print(f"\n[+] Results saved: {report_file}")

        return 1 if result.differences else 0

    except ImportError as e:
        print(f"[-] Differential fuzzer not available: {e}")
        return 1
    except Exception as e:
        print(f"[-] Testing failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_test_dir(args: argparse.Namespace) -> int:
    """Test directory of DICOM files."""
    input_dir = Path(args.test_dir)

    if not input_dir.exists():
        print(f"[-] Directory not found: {input_dir}")
        return 1

    print("\n" + "=" * 70)
    print("  DICOM Differential Testing - Batch Mode")
    print("=" * 70)
    print(f"  Directory: {input_dir}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.core.differential_fuzzer import (
            DifferentialFuzzer,
            DifferentialFuzzerConfig,
        )

        config = DifferentialFuzzerConfig()
        fuzzer = DifferentialFuzzer(config=config)

        print("[i] Testing files...")
        results = fuzzer.fuzz_directory(input_dir)

        # Summary
        files_with_diffs = [r for r in results if r.differences]
        total_diffs = sum(len(r.differences) for r in results)

        print(f"\n[+] Tested {len(results)} files")
        print(f"    Files with differences: {len(files_with_diffs)}")
        print(f"    Total differences: {total_diffs}")

        # Save results
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            report_file = output_dir / f"diff_batch.{args.format}"

            with open(report_file, "w") as f:
                if args.format == "json":
                    json.dump(
                        [{"differences": r.differences} for r in results],
                        f,
                        indent=2,
                        default=str,
                    )
                else:
                    for result in results:
                        f.write(f"Differences: {len(result.differences)}\n")

            print(f"\n[+] Results saved: {report_file}")

        return 1 if files_with_diffs else 0

    except ImportError as e:
        print(f"[-] Differential fuzzer not available: {e}")
        return 1
    except Exception as e:
        print(f"[-] Batch testing failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_list_parsers(args: argparse.Namespace) -> int:
    """List available parser implementations."""
    print("\n" + "=" * 70)
    print("  Available DICOM Parsers")
    print("=" * 70 + "\n")

    parsers: list[dict[str, str | None]] = [
        {
            "name": "pydicom",
            "language": "Python",
            "description": "Pure Python DICOM library",
            "module": "pydicom",
        },
        {
            "name": "gdcm",
            "language": "C++",
            "description": "Grassroots DICOM library",
            "module": "gdcm",
        },
        {
            "name": "dcmtk",
            "language": "C++",
            "description": "OFFIS DICOM Toolkit",
            "module": None,  # External binary
        },
    ]

    for p in parsers:
        try:
            module_name = p["module"]
            if module_name:
                available = importlib.util.find_spec(module_name) is not None
            else:
                # Check for dcmtk binary
                available = shutil.which("dcmdump") is not None
        except Exception:
            available = False

        status = "[+]" if available else "[-]"
        print(f"  {status} {p['name']}")
        print(f"      Language: {p['language']}")
        print(f"      {p['description']}")
        print(f"      Status: {'Available' if available else 'Not installed'}")
        print()

    print("=" * 70)
    print("\nInstallation:")
    print("  pydicom: pip install pydicom")
    print("  gdcm:    pip install python-gdcm")
    print("  dcmtk:   apt install dcmtk (Linux) / brew install dcmtk (macOS)")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for differential subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.test:
        return run_test(args)
    elif args.test_dir:
        return run_test_dir(args)
    elif args.list_parsers:
        return run_list_parsers(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
