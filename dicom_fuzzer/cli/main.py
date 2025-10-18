"""
DICOM Fuzzer - Command Line Interface

A security testing tool for comprehensive fuzzing of DICOM implementations.
Generates mutated DICOM files to test parser robustness and security.
"""

import argparse
import faulthandler
import logging
import shutil
import sys
import time
from pathlib import Path
from typing import List, Tuple

from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.resource_manager import ResourceLimits
from dicom_fuzzer.core.target_runner import TargetRunner

try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Enable faulthandler for debugging silent crashes and segfaults
# This will dump Python tracebacks on crashes (SIGSEGV, SIGFPE, SIGABRT, etc.)
faulthandler.enable(file=sys.stderr, all_threads=True)


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def validate_input_file(file_path: str) -> Path:
    """
    Validate that the input file exists and is a DICOM file.

    Args:
        file_path: Path to input DICOM file

    Returns:
        Validated Path object

    Raises:
        SystemExit: If file doesn't exist or isn't accessible
    """
    path = Path(file_path)
    if not path.exists():
        print(f"Error: Input file '{file_path}' not found")
        sys.exit(1)
    if not path.is_file():
        print(f"Error: '{file_path}' is not a file")
        sys.exit(1)
    return path


def parse_strategies(strategies_str: str) -> list:
    """
    Parse comma-separated strategy list.

    Args:
        strategies_str: Comma-separated strategy names

    Returns:
        List of strategy names
    """
    valid_strategies = {"metadata", "header", "pixel", "structure"}
    strategies = [s.strip().lower() for s in strategies_str.split(",")]

    invalid = set(strategies) - valid_strategies
    if invalid:
        print(f"Warning: Unknown strategies {invalid} will be ignored")
        print(f"Valid strategies: {', '.join(sorted(valid_strategies))}")

    return [s for s in strategies if s in valid_strategies]


def pre_campaign_health_check(
    output_dir: Path,
    target: str = None,
    resource_limits: ResourceLimits = None,
    verbose: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Comprehensive health check before starting fuzzing campaign.

    STABILITY: Validates environment to catch issues before wasting time
    on doomed campaigns.

    Args:
        output_dir: Output directory path
        target: Target executable path (optional)
        resource_limits: Resource limits configuration (optional)
        verbose: Enable verbose output

    Returns:
        Tuple of (passed: bool, issues: List[str])
    """
    issues = []
    warnings = []

    # Check Python version
    if sys.version_info < (3, 11):
        warnings.append(
            f"Python {sys.version_info.major}.{sys.version_info.minor} "
            "detected. Python 3.11+ recommended for best performance."
        )

    # Check required dependencies
    try:
        import pydicom
    except ImportError:
        issues.append("Missing required dependency: pydicom")

    try:
        import psutil
    except ImportError:
        warnings.append("Missing optional dependency: psutil (for resource monitoring)")

    # Check disk space
    try:
        stat = shutil.disk_usage(output_dir.parent if output_dir.exists() else ".")
        free_space_mb = stat.free / (1024 * 1024)
        if free_space_mb < 100:
            issues.append(f"Insufficient disk space: {free_space_mb:.0f}MB (need >100MB)")
        elif free_space_mb < 1024:
            warnings.append(f"Low disk space: {free_space_mb:.0f}MB (recommend >1GB)")
    except Exception as e:
        warnings.append(f"Could not check disk space: {e}")

    # Check output directory is writable
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        test_file = output_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
    except Exception as e:
        issues.append(f"Output directory not writable: {e}")

    # Check target executable if specified
    if target:
        target_path = Path(target)
        if not target_path.exists():
            issues.append(f"Target executable not found: {target}")
        elif not target_path.is_file():
            issues.append(f"Target path is not a file: {target}")

    # Check resource limits are reasonable
    if resource_limits:
        if resource_limits.max_memory_mb and resource_limits.max_memory_mb < 128:
            warnings.append("Memory limit very low (<128MB), may cause frequent OOM errors")

        if resource_limits.max_cpu_seconds and resource_limits.max_cpu_seconds < 1:
            warnings.append("CPU time limit very low (<1s), may cause frequent timeouts")

    # Report results
    passed = len(issues) == 0

    if verbose or not passed:
        if issues:
            print("\n[!] Pre-flight check found critical issues:")
            for issue in issues:
                print(f"  [-] {issue}")

        if warnings and verbose:
            print("\n[!] Pre-flight check warnings:")
            for warning in warnings:
                print(f"  [!] {warning}")

        if passed and not warnings:
            print("\n[+] Pre-flight checks passed")
        elif passed:
            print(f"\n[+] Pre-flight checks passed with {len(warnings)} warning(s)")

    return passed, issues + warnings


def main():
    """Execute DICOM fuzzing campaign with specified parameters."""
    parser = argparse.ArgumentParser(
        description="DICOM Fuzzer - Security testing tool for medical imaging systems",
        epilog="Example: %(prog)s input.dcm -c 50 -o ./output -s metadata,header -v",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument("input_file", help="Path to original DICOM file to fuzz")

    # Optional arguments
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=100,
        metavar="N",
        help="Number of fuzzed files to generate (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="./fuzzed_dicoms",
        metavar="DIR",
        help="Output directory for fuzzed files (default: ./fuzzed_dicoms)",
    )
    parser.add_argument(
        "-s",
        "--strategies",
        type=str,
        metavar="STRAT",
        help=(
            "Comma-separated list of fuzzing strategies: "
            "metadata,header,pixel,structure (default: all)"
        ),
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging output"
    )
    parser.add_argument("--version", action="version", version="DICOM Fuzzer v1.0.0")

    # Target testing options
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        metavar="EXE",
        help="Path to target application to test with fuzzed files",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Timeout in seconds for target execution (default: 5.0)",
    )
    parser.add_argument(
        "--stop-on-crash",
        action="store_true",
        help="Stop testing on first crash detected",
    )

    # Resource limit options
    resource_group = parser.add_argument_group(
        "resource limits", "Control system resource usage"
    )
    resource_group.add_argument(
        "--max-memory",
        type=int,
        metavar="MB",
        help="Maximum memory usage in MB (soft limit, default: 1024). Unix/Linux only.",
    )
    resource_group.add_argument(
        "--max-memory-hard",
        type=int,
        metavar="MB",
        help="Maximum memory hard limit in MB (default: 2048). Unix/Linux only.",
    )
    resource_group.add_argument(
        "--max-cpu-time",
        type=int,
        metavar="SEC",
        help="Maximum CPU time per operation in seconds (default: 30). Unix/Linux only.",
    )
    resource_group.add_argument(
        "--min-disk-space",
        type=int,
        metavar="MB",
        help="Minimum required free disk space in MB (default: 1024).",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Create resource limits if specified
    resource_limits = None
    if any(
        [args.max_memory, args.max_memory_hard, args.max_cpu_time, args.min_disk_space]
    ):
        resource_limits = ResourceLimits(
            max_memory_mb=args.max_memory or 1024,
            max_memory_mb_hard=args.max_memory_hard or 2048,
            max_cpu_seconds=args.max_cpu_time or 30,
            min_disk_space_mb=args.min_disk_space or 1024,
        )
        logger.info(f"Resource limits configured: {resource_limits}")

    # Validate input file
    input_path = validate_input_file(args.input_file)
    logger.info(f"Input file: {input_path}")

    # Parse strategies if specified
    selected_strategies = None
    if args.strategies:
        selected_strategies = parse_strategies(args.strategies)
        if not selected_strategies:
            print("Error: No valid strategies specified")
            sys.exit(1)
        logger.info(f"Selected strategies: {', '.join(selected_strategies)}")
    else:
        logger.info("Using all available fuzzing strategies")

    # Create output directory if needed
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {output_path}")

    # Run pre-campaign health check
    health_check_passed, health_issues = pre_campaign_health_check(
        output_dir=output_path,
        target=args.target,
        resource_limits=resource_limits,
        verbose=args.verbose,
    )

    if not health_check_passed:
        print("\n[ERROR] Pre-flight checks failed. Cannot proceed with campaign.")
        print("Please resolve the issues above and try again.")
        sys.exit(1)

    # Generate fuzzed files
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer v1.0.0 - Fuzzing Campaign")
    print("=" * 70)
    print(f"  Input:      {input_path.name}")
    print(f"  Output:     {args.output}")
    print(f"  Target:     {args.count} files")
    if selected_strategies:
        print(f"  Strategies: {', '.join(selected_strategies)}")
    else:
        print("  Strategies: all (metadata, header, pixel)")
    print("=" * 70 + "\n")

    logger.info(f"Generating {args.count} fuzzed files...")
    start_time = time.time()

    try:
        generator = DICOMGenerator(args.output, skip_write_errors=True)

        # Use progress bar if available
        if HAS_TQDM and not args.verbose:
            print("Generating fuzzed files...")
            with tqdm(total=args.count, unit="file", ncols=70) as pbar:
                # Generate in smaller batches to update progress
                batch_size = max(1, args.count // 20)  # 20 updates
                remaining = args.count
                all_files = []

                while remaining > 0:
                    current_batch = min(batch_size, remaining)
                    files = generator.generate_batch(
                        str(input_path),
                        count=current_batch,
                        strategies=selected_strategies,
                    )
                    all_files.extend(files)
                    pbar.update(len(files))
                    remaining -= current_batch

                files = all_files
        else:
            # No progress bar, generate all at once
            files = generator.generate_batch(
                str(input_path), count=args.count, strategies=selected_strategies
            )

        elapsed_time = time.time() - start_time

        # Display results (using ASCII for Windows compatibility)
        print("\n" + "=" * 70)
        print("  Campaign Results")
        print("=" * 70)
        print(f"  [+] Successfully generated: {len(files)} files")
        skipped = generator.stats.skipped_due_to_write_errors
        print(f"  [!] Skipped (write errors): {skipped}")
        files_per_sec = len(files) / elapsed_time
        print(
            f"  [T] Time elapsed: {elapsed_time:.2f}s ({files_per_sec:.1f} files/sec)"
        )

        if generator.stats.strategies_used:
            print("\n  Strategy Usage:")
            for strategy, count in sorted(generator.stats.strategies_used.items()):
                print(f"    - {strategy}: {count} times")  # noqa: E221

        print(f"\n  Output: {args.output}")
        print("=" * 70 + "\n")

        if args.verbose:
            print("Sample generated files:")
            for f in files[:10]:
                print(f"  - {f.name}")  # noqa: E221
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")
            print()

        # Target testing if --target specified
        if args.target:
            print("\n" + "=" * 70)
            print("  Target Application Testing")
            print("=" * 70)
            print(f"  Target:     {args.target}")
            print(f"  Timeout:    {args.timeout}s")
            print(f"  Test files: {len(files)}")
            print("=" * 70 + "\n")

            try:
                runner = TargetRunner(
                    target_executable=args.target,
                    timeout=args.timeout,
                    crash_dir=output_path / "crashes",
                    resource_limits=resource_limits,
                )

                logger.info("Starting target testing campaign...")
                if resource_limits:
                    logger.info("Resource limits will be enforced during testing")
                test_start = time.time()

                results = runner.run_campaign(
                    test_files=files, stop_on_crash=args.stop_on_crash
                )

                test_elapsed = time.time() - test_start

                # Display results
                summary = runner.get_summary(results)
                print(summary)
                print(
                    f"\nTarget testing completed in {test_elapsed:.2f}s "
                    f"({len(files) / test_elapsed:.1f} tests/sec)\n"
                )

            except FileNotFoundError as e:
                logger.error(f"Target executable not found: {e}")
                print(f"\n[ERROR] Target executable not found: {args.target}")
                print("Please verify the path and try again.")
                sys.exit(1)
            except Exception as e:
                logger.error(f"Target testing failed: {e}", exc_info=args.verbose)
                print(f"\n[ERROR] Target testing failed: {e}")
                if args.verbose:
                    import traceback

                    traceback.print_exc()
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Campaign stopped by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fuzzing failed: {e}", exc_info=args.verbose)
        print(f"\n[ERROR] Fuzzing failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
