"""DICOM Fuzzer - Command Line Interface

A security testing tool for comprehensive fuzzing of DICOM implementations.
Generates mutated DICOM files to test parser robustness and security.
"""

import argparse
import faulthandler
import json
import logging
import shutil
import sys
import time
from pathlib import Path

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


# CLI Helper Functions
def format_file_size(size: int) -> str:
    """Format file size for CLI output.

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g., "1.0 MB")

    """
    kb = 1024
    mb = kb * 1024
    gb = mb * 1024

    if size < kb:
        return f"{size} B"
    elif size < mb:
        return f"{size / kb:.1f} KB"
    elif size < gb:
        return f"{size / mb:.1f} MB"
    else:
        return f"{size / gb:.1f} GB"


def format_duration(seconds: float) -> str:
    """Format duration for CLI output (adapted from helpers.format_duration).

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "1h 1m 1s")

    """
    # Use utils format_duration but adjust format to match test expectations
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {minutes}m {secs}s"


def validate_strategy(strategy: str, valid_strategies: list[str]) -> bool:
    """Validate that a strategy name is valid or special keyword 'all'.

    Args:
        strategy: Strategy name to validate
        valid_strategies: List of valid strategy names

    Returns:
        True if strategy is valid or is 'all', False otherwise

    """
    return strategy in valid_strategies or strategy == "all"


def parse_target_config(config_path: str) -> dict[str, any]:
    """Parse target configuration from JSON file.

    Args:
        config_path: Path to JSON configuration file

    Returns:
        Dictionary containing target configuration

    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON

    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        config: dict[str, any] = json.load(f)

    return config


def apply_resource_limits(resource_limits: dict | ResourceLimits) -> None:
    """Apply resource limits to current process.

    Args:
        resource_limits: Resource limits configuration to apply (dict or ResourceLimits instance)

    Note:
        This is a wrapper for testing. Actual resource limiting
        is handled by ResourceLimits class and target_runner.

    """
    # If dict is passed, create ResourceLimits instance for test compatibility
    if isinstance(resource_limits, dict):
        limits = ResourceLimits(**resource_limits)
        limits.enforce()
    elif isinstance(resource_limits, ResourceLimits):
        resource_limits.enforce()
    # Otherwise, it's a no-op (None or other)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def validate_input_file(file_path: str) -> Path:
    """Validate that the input file exists and is a DICOM file.

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


def parse_strategies(strategies_str: str | None) -> list:
    """Parse comma-separated strategy list.

    Args:
        strategies_str: Comma-separated strategy names (or None for empty list)

    Returns:
        List of strategy names

    """
    valid_strategies = {"metadata", "header", "pixel", "structure"}

    # Handle None input - return empty list
    if strategies_str is None:
        return []

    # Handle empty string - return empty list
    if not strategies_str.strip():
        return []

    strategies = [s.strip().lower() for s in strategies_str.split(",")]

    invalid = set(strategies) - valid_strategies
    if invalid:
        print(f"Warning: Unknown strategies {invalid} will be ignored")
        print(f"Valid strategies: {', '.join(sorted(valid_strategies))}")

    return [s for s in strategies if s in valid_strategies]


def pre_campaign_health_check(
    output_dir: Path,
    target: str | None = None,
    resource_limits: ResourceLimits | None = None,
    verbose: bool = False,
) -> tuple[bool, list[str]]:
    """Comprehensive health check before starting fuzzing campaign.

    STABILITY: Validates environment to catch issues before wasting time
    on doomed campaigns.

    Args:
        output_dir: Output directory path
        target: Target executable path (optional)
        resource_limits: Resource limits configuration (optional)
        verbose: Enable verbose output

    Returns:
        tuple of (passed: bool, issues: list[str])

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
        import pydicom  # noqa: F401
    except ImportError:
        issues.append("Missing required dependency: pydicom")

    try:
        import psutil  # noqa: F401
    except ImportError:
        warnings.append("Missing optional dependency: psutil (for resource monitoring)")

    # Check disk space
    try:
        stat = shutil.disk_usage(output_dir.parent if output_dir.exists() else ".")
        free_space_mb = stat.free / (1024 * 1024)
        if free_space_mb < 100:
            issues.append(
                f"Insufficient disk space: {free_space_mb:.0f}MB (need >100MB)"
            )
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
            warnings.append(
                "Memory limit very low (<128MB), may cause frequent OOM errors"
            )

        if resource_limits.max_cpu_seconds and resource_limits.max_cpu_seconds < 1:
            warnings.append(
                "CPU time limit very low (<1s), may cause frequent timeouts"
            )

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


def main() -> None:
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
        default="./output",
        metavar="DIR",
        help="Output directory for fuzzed files (default: ./output)",
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
        [
            getattr(args, "max_memory", None),
            getattr(args, "max_memory_hard", None),
            getattr(args, "max_cpu_time", None),
            getattr(args, "min_disk_space", None),
        ]
    ):
        resource_limits = ResourceLimits(
            max_memory_mb=getattr(args, "max_memory", None)
            or getattr(args, "max_memory_hard", None)
            or 1024,
            max_memory_mb_hard=getattr(args, "max_memory_hard", None) or 2048,
            max_cpu_seconds=getattr(args, "max_cpu_time", None)
            or getattr(args, "max_cpu", None)
            or 30,
            min_disk_space_mb=getattr(args, "min_disk_space", None) or 1024,
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
    # Handle both 'count' and 'num_mutations' for test compatibility
    num_files = getattr(args, "count", None) or getattr(args, "num_mutations", 100)
    print(f"  Target:     {num_files} files")
    if selected_strategies:
        print(f"  Strategies: {', '.join(selected_strategies)}")
    else:
        print("  Strategies: all (metadata, header, pixel)")
    print("=" * 70 + "\n")

    logger.info(f"Generating {num_files} fuzzed files...")
    start_time = time.time()

    try:
        generator = DICOMGenerator(args.output, skip_write_errors=True)

        # Use progress bar if available and file count is large enough
        if HAS_TQDM and not args.verbose and num_files >= 20:
            print("Generating fuzzed files...")
            with tqdm(total=num_files, unit="file", ncols=70) as pbar:
                # Generate in smaller batches to update progress
                batch_size = max(1, num_files // 20)  # 20 updates
                remaining = num_files
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
            # No progress bar or small file count, generate all at once
            files = generator.generate_batch(
                str(input_path), count=num_files, strategies=selected_strategies
            )

        elapsed_time = time.time() - start_time

        # Display results (using ASCII for Windows compatibility)
        print("\n" + "=" * 70)
        print("  Campaign Results")
        print("=" * 70)
        print(f"  [+] Successfully generated: {len(files)} files")
        skipped = (
            getattr(generator.stats, "skipped_due_to_write_errors", 0)
            if hasattr(generator, "stats")
            else 0
        )
        print(f"  [!] Skipped (write errors): {skipped}")
        files_per_sec = len(files) / elapsed_time
        print(
            f"  [T] Time elapsed: {elapsed_time:.2f}s ({files_per_sec:.1f} files/sec)"
        )

        # Check if stats exist and strategies_used is a dict (for test compatibility)
        if hasattr(generator, "stats") and hasattr(generator.stats, "strategies_used"):
            strategies_used = generator.stats.strategies_used
            if isinstance(strategies_used, dict) and strategies_used:
                print("\n  Strategy Usage:")
                for strategy, count in sorted(strategies_used.items()):
                    print(f"    - {strategy}: {count} times")

        print(f"\n  Output: {args.output}")
        print("=" * 70 + "\n")

        if args.verbose:
            print("Sample generated files:")
            for f in files[:10]:
                print(f"  - {f.name}")
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
                    crash_dir=str(output_path / "crashes"),
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

    return 0


if __name__ == "__main__":
    main()
