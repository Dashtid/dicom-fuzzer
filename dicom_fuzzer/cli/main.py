"""DICOM Fuzzer - Command Line Interface

A security testing tool for comprehensive fuzzing of DICOM implementations.
Generates mutated DICOM files to test parser robustness and security.
"""

import argparse
import faulthandler
import importlib
import importlib.util
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

from dicom_fuzzer.cli import output as cli
from dicom_fuzzer.cli.argument_parser import create_parser
from dicom_fuzzer.cli.campaign_runner import CampaignRunner
from dicom_fuzzer.cli.network_controller import NetworkFuzzingController
from dicom_fuzzer.cli.security_controller import SecurityFuzzingController
from dicom_fuzzer.cli.target_controller import TargetTestingController
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager

# Module-level logger
logger = logging.getLogger(__name__)

# Check for optional dependencies
HAS_PSUTIL = importlib.util.find_spec("psutil") is not None

# Enable faulthandler for debugging silent crashes and segfaults
# This will dump Python tracebacks on crashes (SIGSEGV, SIGFPE, SIGABRT, etc.)
faulthandler.enable(file=sys.stderr, all_threads=True)


# Subcommand registry: maps subcommand name to module path
# Uses lazy imports for faster startup when subcommand not used
SUBCOMMANDS: dict[str, str] = {
    "samples": "dicom_fuzzer.cli.samples",
    "tls": "dicom_fuzzer.cli.tls",
    "persistent": "dicom_fuzzer.cli.persistent",
    "state": "dicom_fuzzer.cli.state",
    "corpus": "dicom_fuzzer.cli.corpus",
    "study": "dicom_fuzzer.cli.study",
    "study-campaign": "dicom_fuzzer.cli.study_campaign",
    "calibrate": "dicom_fuzzer.cli.calibrate",
    "stress": "dicom_fuzzer.cli.stress",
    "target": "dicom_fuzzer.cli.target",
}


# ============================================================================
# CLI Helper Functions
# ============================================================================


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


def parse_target_config(config_path: str) -> dict[str, Any]:
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
        config: dict[str, Any] = json.load(f)

    return config


def apply_resource_limits(
    resource_limits: dict[str, Any] | ResourceLimits | None,
) -> None:
    """Apply resource limits to current process.

    Args:
        resource_limits: Resource limits configuration to apply (dict or ResourceLimits instance)

    Note:
        This is a wrapper for testing. Actual resource limiting
        is handled by ResourceManager class using context manager.
        This function just validates resources are available.

    """
    if resource_limits is None:
        return None

    # If dict is passed, create ResourceLimits instance for test compatibility
    if isinstance(resource_limits, dict):
        limits = ResourceLimits(**resource_limits)
    else:
        limits = resource_limits

    # Use ResourceManager to check available resources
    manager = ResourceManager(limits)
    manager.check_available_resources()
    return None


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _scan_directory_for_dicom(
    path: Path, recursive: bool, extensions: set[str]
) -> list[Path]:
    """Scan directory for DICOM files.

    Args:
        path: Directory path to scan.
        recursive: If True, scan recursively.
        extensions: Set of valid DICOM extensions.

    Returns:
        List of found DICOM file paths.

    """
    iterator = path.rglob("*") if recursive else path.iterdir()
    return [
        file_path
        for file_path in iterator
        if file_path.is_file() and _is_potential_dicom(file_path, extensions)
    ]


def validate_input_path(input_path: str, recursive: bool = False) -> list[Path]:
    """Validate input path and return list of DICOM files.

    Args:
        input_path: Path to input DICOM file or directory
        recursive: If True and input is directory, scan recursively

    Returns:
        List of validated Path objects for DICOM files

    Raises:
        SystemExit: If path doesn't exist or no valid files found

    """
    path = Path(input_path)
    if not path.exists():
        print(f"Error: Input path '{input_path}' not found")
        sys.exit(1)

    if path.is_file():
        return [path]

    if path.is_dir():
        dicom_extensions = {".dcm", ".dicom", ".dic", ""}
        files = _scan_directory_for_dicom(path, recursive, dicom_extensions)

        if not files:
            print(f"Error: No DICOM files found in '{input_path}'")
            if not recursive:
                print("Tip: Use --recursive to scan subdirectories")
            sys.exit(1)

        return sorted(files)

    print(f"Error: '{input_path}' is not a regular file or directory")
    sys.exit(1)


def _is_potential_dicom(file_path: Path, extensions: set[str]) -> bool:
    """Check if file might be a DICOM file based on extension or signature."""
    # Check extension
    if file_path.suffix.lower() in extensions:
        # For files with .dcm/.dicom extension, assume DICOM
        if file_path.suffix.lower() in {".dcm", ".dicom", ".dic"}:
            return True

        # For files without extension, check for DICOM signature
        if file_path.suffix == "":
            try:
                with open(file_path, "rb") as f:
                    # Check for DICM magic bytes at offset 128
                    f.seek(128)
                    magic = f.read(4)
                    return magic == b"DICM"
            except OSError:
                return False

    return False


def validate_input_file(file_path: str) -> Path:
    """Validate that the input file exists and is a DICOM file.

    Args:
        file_path: Path to input DICOM file

    Returns:
        Validated Path object

    Raises:
        SystemExit: If file doesn't exist or isn't accessible

    Note:
        This function is kept for backwards compatibility.
        Use validate_input_path for new code supporting directories.

    """
    path = Path(file_path)
    if not path.exists():
        print(f"Error: Input file '{file_path}' not found")
        sys.exit(1)
    if not path.is_file():
        print(f"Error: '{file_path}' is not a file")
        sys.exit(1)
    return path


def parse_strategies(strategies_str: str | None) -> list[str]:
    """Parse comma-separated strategy list.

    Args:
        strategies_str: Comma-separated strategy names (or None for empty list)

    Returns:
        List of strategy names

    """
    valid_strategies = {"metadata", "header", "pixel", "structure", "exploit-patterns"}

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


def _check_dependencies(issues: list[str], warnings: list[str]) -> None:
    """Check Python version and required dependencies."""
    if sys.version_info < (3, 11):
        warnings.append(
            f"Python {sys.version_info.major}.{sys.version_info.minor} "
            "detected. Python 3.11+ recommended for best performance."
        )

    try:
        import pydicom  # noqa: F401
    except ImportError:
        issues.append("Missing required dependency: pydicom")

    try:
        import psutil  # noqa: F401
    except ImportError:
        warnings.append("Missing optional dependency: psutil (for resource monitoring)")


def _check_disk_space(output_dir: Path, issues: list[str], warnings: list[str]) -> None:
    """Check available disk space."""
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


def _check_output_dir(output_dir: Path, issues: list[str]) -> None:
    """Check output directory is writable."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        test_file = output_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
    except Exception as e:
        issues.append(f"Output directory not writable: {e}")


def _check_target(target: str | None, issues: list[str]) -> None:
    """Check target executable exists."""
    if not target:
        return
    target_path = Path(target)
    if not target_path.exists():
        issues.append(f"Target executable not found: {target}")
    elif not target_path.is_file():
        issues.append(f"Target path is not a file: {target}")


def _check_resource_limits(
    resource_limits: ResourceLimits | None, warnings: list[str]
) -> None:
    """Check resource limits are reasonable."""
    if not resource_limits:
        return
    if resource_limits.max_memory_mb and resource_limits.max_memory_mb < 128:
        warnings.append("Memory limit very low (<128MB), may cause frequent OOM errors")
    if resource_limits.max_cpu_seconds and resource_limits.max_cpu_seconds < 1:
        warnings.append("CPU time limit very low (<1s), may cause frequent timeouts")


def _report_health_check(issues: list[str], warnings: list[str], verbose: bool) -> None:
    """Report health check results."""
    passed = len(issues) == 0
    if not verbose and passed:
        return

    if issues:
        cli.warning("Pre-flight check found critical issues:")
        for issue in issues:
            cli.error(issue)

    if warnings and verbose:
        cli.warning("Pre-flight check warnings:")
        for warn_msg in warnings:
            cli.warning(warn_msg)

    if passed and not warnings:
        cli.success("Pre-flight checks passed")
    elif passed:
        cli.success(f"Pre-flight checks passed with {len(warnings)} warning(s)")


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
    issues: list[str] = []
    warnings: list[str] = []

    _check_dependencies(issues, warnings)
    _check_disk_space(output_dir, issues, warnings)
    _check_output_dir(output_dir, issues)
    _check_target(target, issues)
    _check_resource_limits(resource_limits, warnings)
    _report_health_check(issues, warnings, verbose)

    return len(issues) == 0, issues + warnings


# ============================================================================
# Main Entry Point
# ============================================================================


def _run_optional_controllers(
    args: argparse.Namespace,
    files: list[Path],
    input_files: list[Path],
    output_path: Path,
    resource_limits: ResourceLimits | None,
) -> int:
    """Run optional fuzzing controllers based on args.

    Returns:
        Exit code (0 for success, non-zero for errors).

    """
    if getattr(args, "network_fuzz", False):
        NetworkFuzzingController.run(args, files)

    if getattr(args, "security_fuzz", False):
        num_files = getattr(args, "count", 100)
        SecurityFuzzingController.run(args, input_files[0], output_path, num_files)

    if getattr(args, "target", None):
        result = TargetTestingController.run(args, files, output_path, resource_limits)
        if result != 0:
            return result

    return 0


def main() -> int:
    """Execute DICOM fuzzing campaign with specified parameters.

    Returns:
        Exit code (0 for success, non-zero for errors)

    """
    if len(sys.argv) > 1 and sys.argv[1] in SUBCOMMANDS:
        module = importlib.import_module(SUBCOMMANDS[sys.argv[1]])
        exit_code: int = module.main(sys.argv[2:])
        return exit_code

    parser = create_parser()
    args = parser.parse_args()

    quiet_mode = getattr(args, "quiet", False)
    json_mode = getattr(args, "json", False)

    if quiet_mode and not args.verbose:
        logging.getLogger().setLevel(logging.ERROR)
        setup_logging(False)
    else:
        setup_logging(args.verbose)

    try:
        resource_limits = _create_resource_limits(args)
        recursive = getattr(args, "recursive", False)
        input_files = validate_input_path(args.input_file, recursive)
        selected_strategies = parse_strategies(getattr(args, "strategies", None))

        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)

        passed, _ = pre_campaign_health_check(
            output_path,
            target=getattr(args, "target", None),
            resource_limits=resource_limits,
            verbose=args.verbose,
        )
        if not passed:
            cli.error("Pre-flight check failed. Fix issues and retry.")
            return 1

        runner = CampaignRunner(args, input_files, selected_strategies)
        runner.display_header()
        files, results_data = runner.generate_files()
        runner.display_results(files, results_data, json_mode, quiet_mode)

        return _run_optional_controllers(
            args, files, input_files, output_path, resource_limits
        )

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Campaign stopped by user")
        return 130
    except Exception as e:
        logger.error(f"Fuzzing failed: {e}", exc_info=args.verbose)
        print(f"\n[ERROR] Fuzzing failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def _create_resource_limits(args: argparse.Namespace) -> ResourceLimits | None:
    """Create ResourceLimits from command-line arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        ResourceLimits instance or None if no limits specified

    """
    max_memory = getattr(args, "max_memory", None)
    max_memory_hard = getattr(args, "max_memory_hard", None)
    max_cpu_time = getattr(args, "max_cpu_time", None)
    min_disk_space = getattr(args, "min_disk_space", None)

    # Check if any limits specified
    if not any([max_memory, max_memory_hard, max_cpu_time, min_disk_space]):
        return None

    return ResourceLimits(
        max_memory_mb=max_memory or max_memory_hard or 1024,
        max_cpu_seconds=max_cpu_time or 30,
        min_disk_space_mb=min_disk_space or 1024,
    )


if __name__ == "__main__":
    sys.exit(main())
