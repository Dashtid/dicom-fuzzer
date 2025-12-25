"""Stress Testing Subcommand for DICOM Fuzzer.

Memory and performance stress testing for DICOM viewers and applications.

NOTE: This CLI module provides a simplified interface to the core stress tester.
For advanced usage, import dicom_fuzzer.harness.stress_tester directly.
"""

import argparse
import sys
import traceback
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for stress subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer stress",
        description="Memory and performance stress testing for DICOM applications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate large series (500 slices)
  dicom-fuzzer stress --generate-series --slices 500 -o ./large_series

  # Generate with specific dimensions
  dicom-fuzzer stress --generate-series --slices 200 --dimensions 1024x1024 -o ./output

  # List stress test scenarios
  dicom-fuzzer stress --list-scenarios

For advanced usage, use the Python API:
  from dicom_fuzzer.harness.stress_tester import StressTester, StressTestConfig
        """,
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--generate-series",
        action="store_true",
        help="Generate large DICOM series for stress testing",
    )
    action_group.add_argument(
        "--run-test",
        action="store_true",
        help="Run memory stress test campaign",
    )
    action_group.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List available stress test scenarios",
    )

    generation_group = parser.add_argument_group("series generation options")
    generation_group.add_argument(
        "--slices",
        type=int,
        default=100,
        metavar="N",
        help="Number of slices for generated series (default: 100)",
    )
    generation_group.add_argument(
        "--dimensions",
        type=str,
        default="512x512",
        metavar="WxH",
        help="Slice dimensions WxH (default: 512x512)",
    )
    generation_group.add_argument(
        "--pattern",
        type=str,
        choices=["gradient", "random", "anatomical"],
        default="gradient",
        help="Pixel pattern (default: gradient)",
    )
    generation_group.add_argument(
        "--modality",
        type=str,
        choices=["CT", "MR", "PT"],
        default="CT",
        help="DICOM modality (default: CT)",
    )

    testing_group = parser.add_argument_group("stress testing options")
    testing_group.add_argument(
        "--escalation-steps",
        type=str,
        default="100,250,500,1000",
        metavar="N,N,...",
        help="Comma-separated slice counts for escalation (default: 100,250,500,1000)",
    )
    testing_group.add_argument(
        "--memory-limit",
        type=int,
        default=4096,
        metavar="MB",
        help="Memory limit in MB (default: 4096)",
    )

    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        default="./artifacts/stress",
        help="Output directory (default: ./artifacts/stress)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_list_scenarios() -> int:
    """List available stress test scenarios."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Stress Test Scenarios")
    print("=" * 70 + "\n")

    scenarios = [
        (
            "Large Series",
            "Generate and load 1000+ slice series",
            [
                "Tests memory allocation during series loading",
                "Validates viewer handling of large datasets",
                "Identifies memory leaks in slice iteration",
            ],
        ),
        (
            "High Resolution",
            "4096x4096 dimension slices",
            [
                "Tests GPU memory for large textures",
                "Validates image display pipeline",
                "Identifies rendering bottlenecks",
            ],
        ),
        (
            "Incremental Loading",
            "Partial series with missing slices",
            [
                "Tests interrupted transfer handling",
                "Validates reconstruction with gaps",
                "Identifies error recovery behavior",
            ],
        ),
        (
            "Memory Escalation",
            "Progressive slice count increase",
            [
                "Default steps: 100, 250, 500, 1000 slices",
                "Monitors memory growth over time",
                "Identifies memory exhaustion thresholds",
            ],
        ),
    ]

    for name, description, details in scenarios:
        print(f"  {name}")
        print(f"    {description}")
        for detail in details:
            print(f"      - {detail}")
        print()

    print("[i] Use --generate-series or --run-test to execute stress tests")
    return 0


def parse_dimensions(dim_str: str) -> tuple[int, int]:
    """Parse WxH dimension string."""
    try:
        parts = dim_str.lower().split("x")
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError) as err:
        raise ValueError(
            f"Invalid dimensions format: {dim_str}. Use WxH (e.g., 512x512)"
        ) from err


def run_generate_series(args: argparse.Namespace) -> int:
    """Generate large DICOM series."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Large Series Generation")
    print("=" * 70)
    print(f"  Slices:     {args.slices}")
    print(f"  Dimensions: {args.dimensions}")
    print(f"  Pattern:    {args.pattern}")
    print(f"  Modality:   {args.modality}")
    print(f"  Output:     {args.output}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)

        dimensions = parse_dimensions(args.dimensions)

        config = StressTestConfig(
            max_slices=args.slices + 100,  # Allow some headroom
            max_dimensions=dimensions,
            memory_limit_mb=args.memory_limit,
        )

        tester = StressTester(config)

        # Estimate memory usage
        estimate = tester.estimate_memory_usage(args.slices, dimensions)
        print("[i] Estimated memory usage:")
        print(f"    Per slice:   {estimate['slice_mb']:.2f} MB")
        print(f"    Total data:  {estimate['series_pixel_data_mb']:.2f} MB")
        print(f"    In viewer:   {estimate['estimated_viewer_mb']:.2f} MB (approx)")
        print()

        print(f"[i] Generating {args.slices} slices...")
        series_path = tester.generate_large_series(
            output_dir=output_path,
            slice_count=args.slices,
            dimensions=dimensions,
            pixel_pattern=args.pattern,
            modality=args.modality,
        )

        # Count generated files
        dcm_files = list(series_path.glob("*.dcm"))
        print(f"\n[+] Generated {len(dcm_files)} DICOM files in: {series_path}")

        # Report actual size
        total_bytes = sum(f.stat().st_size for f in dcm_files)
        total_mb = total_bytes / (1024 * 1024)
        print(f"[+] Total size: {total_mb:.2f} MB")

        return 0

    except ImportError as e:
        print(f"[-] Module not available: {e}")
        print("[i] Ensure dicom_fuzzer.harness.stress_tester is installed")
        return 1
    except Exception as e:
        print(f"[-] Failed: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1


def run_stress_test(args: argparse.Namespace) -> int:
    """Run memory stress test campaign."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Memory Stress Test Campaign")
    print("=" * 70)
    print(f"  Escalation: {args.escalation_steps}")
    print(f"  Dimensions: {args.dimensions}")
    print(f"  Mem Limit:  {args.memory_limit} MB")
    print(f"  Output:     {args.output}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)

        dimensions = parse_dimensions(args.dimensions)
        steps = [int(s.strip()) for s in args.escalation_steps.split(",")]

        config = StressTestConfig(
            max_slices=max(steps) + 100,
            max_dimensions=dimensions,
            memory_limit_mb=args.memory_limit,
        )

        tester = StressTester(config)

        print(f"[i] Running stress test with {len(steps)} escalation steps...")
        print(f"[i] Steps: {steps}")
        print()

        results = tester.run_memory_stress_test(
            output_dir=output_path,
            escalation_steps=steps,
        )

        print("\n" + "-" * 70)
        print("  Stress Test Results")
        print("-" * 70)

        for i, result in enumerate(results):
            status = "[+]" if result.success else "[-]"
            print(f"\n{status} Step {i + 1}: {result.slice_count} slices")
            print(f"    Duration:    {result.duration_seconds:.2f}s")
            print(f"    Memory Peak: {result.memory_peak_mb:.2f} MB")
            if result.errors:
                print(f"    Errors:      {len(result.errors)}")
                for error in result.errors[:3]:
                    print(f"      - {error}")

        success_count = sum(1 for r in results if r.success)
        print(f"\n[+] Completed: {success_count}/{len(results)} steps successful")
        print(f"[+] Results saved to: {output_path}")

        return 0 if success_count == len(results) else 1

    except ImportError as e:
        print(f"[-] Module not available: {e}")
        print("[i] Ensure dicom_fuzzer.harness.stress_tester is installed")
        return 1
    except Exception as e:
        print(f"[-] Failed: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for stress subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.list_scenarios:
        return run_list_scenarios()
    elif args.generate_series:
        return run_generate_series(args)
    elif args.run_test:
        return run_stress_test(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
