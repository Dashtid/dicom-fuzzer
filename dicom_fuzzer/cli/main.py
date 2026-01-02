"""DICOM Fuzzer - Command Line Interface

A security testing tool for comprehensive fuzzing of DICOM implementations.
Generates mutated DICOM files to test parser robustness and security.
"""

import argparse
import faulthandler
import importlib
import json
import logging
import shutil
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from dicom_fuzzer.cli import output as cli
from dicom_fuzzer.cli.gui_runner import GUITargetRunner
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager
from dicom_fuzzer.core.target_runner import TargetRunner

# Module-level logger
logger = logging.getLogger(__name__)

# Import new modules for advanced fuzzing features
try:
    from dicom_fuzzer.core.gui_monitor import (
        GUIMonitor,  # noqa: F401 - imported for future GUI fuzzing commands
        MonitorConfig,  # noqa: F401 - imported for future GUI fuzzing commands
        ResponseAwareFuzzer,  # noqa: F401 - imported for future GUI fuzzing commands
    )

    HAS_GUI_MONITOR = True
except ImportError:
    HAS_GUI_MONITOR = False

try:
    from dicom_fuzzer.core.network_fuzzer import (
        DICOMNetworkConfig,
        DICOMNetworkFuzzer,
        FuzzingStrategy,
    )

    HAS_NETWORK_FUZZER = True
except ImportError:
    HAS_NETWORK_FUZZER = False

try:
    from dicom_fuzzer.strategies.medical_device_security import (
        MedicalDeviceSecurityConfig,
        MedicalDeviceSecurityFuzzer,
        VulnerabilityClass,
    )

    HAS_SECURITY_FUZZER = True
except ImportError:
    HAS_SECURITY_FUZZER = False

try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import importlib.util

    HAS_PSUTIL = importlib.util.find_spec("psutil") is not None
except ImportError:
    HAS_PSUTIL = False

# Enable faulthandler for debugging silent crashes and segfaults
# This will dump Python tracebacks on crashes (SIGSEGV, SIGFPE, SIGABRT, etc.)
faulthandler.enable(file=sys.stderr, all_threads=True)


# Subcommand registry: maps subcommand name to module path
# Uses lazy imports for faster startup when subcommand not used
SUBCOMMANDS: dict[str, str] = {
    "samples": "dicom_fuzzer.cli.samples",
    "tls": "dicom_fuzzer.cli.tls",
    "differential": "dicom_fuzzer.cli.differential",
    "persistent": "dicom_fuzzer.cli.persistent",
    "state": "dicom_fuzzer.cli.state",
    "corpus": "dicom_fuzzer.cli.corpus",
    "study": "dicom_fuzzer.cli.study",
    "study-campaign": "dicom_fuzzer.cli.study_campaign",
    "calibrate": "dicom_fuzzer.cli.calibrate",
    "stress": "dicom_fuzzer.cli.stress",
    "target": "dicom_fuzzer.cli.target",
}


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


def apply_resource_limits(resource_limits: dict | ResourceLimits | None) -> None:
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
        # Find DICOM files in directory
        dicom_extensions = {".dcm", ".dicom", ".dic", ""}  # Include no extension
        files = []

        if recursive:
            # Recursive scan
            for file_path in path.rglob("*"):
                if file_path.is_file() and _is_potential_dicom(
                    file_path, dicom_extensions
                ):
                    files.append(file_path)
        else:
            # Non-recursive scan (immediate children only)
            for file_path in path.iterdir():
                if file_path.is_file() and _is_potential_dicom(
                    file_path, dicom_extensions
                ):
                    files.append(file_path)

        if not files:
            print(f"Error: No DICOM files found in '{input_path}'")
            if not recursive:
                print("Tip: Use --recursive to scan subdirectories")
            sys.exit(1)

        return sorted(files)

    # Path exists but is neither file nor directory (e.g., symlink, device)
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

    return passed, issues + warnings


def main() -> int:
    """Execute DICOM fuzzing campaign with specified parameters.

    Returns:
        Exit code (0 for success, non-zero for errors)

    """
    # Handle subcommands via registry lookup (lazy import for faster startup)
    if len(sys.argv) > 1 and sys.argv[1] in SUBCOMMANDS:
        module = importlib.import_module(SUBCOMMANDS[sys.argv[1]])
        exit_code: int = module.main(sys.argv[2:])
        return exit_code

    parser = argparse.ArgumentParser(
        description="DICOM Fuzzer - Security testing tool for medical imaging systems",
        epilog="""
Examples:
  # Fuzz a single file
  %(prog)s input.dcm -c 50 -o ./output

  # Fuzz all DICOM files in a directory
  %(prog)s ./dicom_folder/ -c 10 -o ./output

  # Generate synthetic samples
  %(prog)s samples --generate -c 10 -o ./samples

Subcommands (use --help for details):
  samples      Generate synthetic/malicious DICOM samples
  tls          DICOM TLS/authentication testing
  differential Cross-parser differential testing
  persistent   AFL-style persistent mode fuzzing
  state        Protocol state machine fuzzing
  corpus       Corpus management and minimization
  study        Study-level fuzzing (cross-series attacks)
  calibrate    Calibration/measurement fuzzing
  stress       Memory stress testing
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument(
        "input_file",
        help="Path to DICOM file or directory. Use 'samples' subcommand to generate test data.",
    )

    # Directory/recursive options
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan input directory for DICOM files",
    )

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
        default="./artifacts/campaigns",
        metavar="DIR",
        help="Output directory for fuzzed files (default: ./artifacts/campaigns)",
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
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress all output except errors"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format (useful for CI/CD pipelines)",
    )
    parser.add_argument("--version", action="version", version="DICOM Fuzzer v1.7.0")

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
    parser.add_argument(
        "--gui-mode",
        action="store_true",
        help=(
            "Enable GUI application mode. Use this for DICOM viewers that don't "
            "exit after processing (e.g., Hermes Affinity, MicroDicom, RadiAnt). "
            "In GUI mode, the app is killed after timeout and SUCCESS means "
            "the app didn't crash before timeout. Requires psutil."
        ),
    )
    parser.add_argument(
        "--memory-limit",
        type=int,
        metavar="MB",
        help=(
            "Memory limit for GUI mode in MB. Kill target if exceeded. "
            "Only used with --gui-mode."
        ),
    )
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help=(
            "Delay in seconds after launching GUI app before monitoring starts. "
            "Use this for applications that need time to load (e.g., 2.0 for Hermes). "
            "Only used with --gui-mode. (default: 0.0)"
        ),
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

    # Network fuzzing options
    network_group = parser.add_argument_group(
        "network fuzzing", "DICOM network protocol fuzzing options"
    )
    network_group.add_argument(
        "--network-fuzz",
        action="store_true",
        help=(
            "Enable DICOM network protocol fuzzing. Fuzz DICOM Association "
            "(A-ASSOCIATE), C-STORE, C-FIND, C-MOVE operations. "
            "Requires target host and port."
        ),
    )
    network_group.add_argument(
        "--host",
        type=str,
        default="localhost",
        metavar="HOST",
        help="Target DICOM server host for network fuzzing (default: localhost)",
    )
    network_group.add_argument(
        "--port",
        type=int,
        default=11112,
        metavar="PORT",
        help="Target DICOM server port for network fuzzing (default: 11112)",
    )
    network_group.add_argument(
        "--ae-title",
        type=str,
        default="FUZZ_SCU",
        metavar="TITLE",
        help="AE Title to use for network fuzzing (default: FUZZ_SCU)",
    )
    network_group.add_argument(
        "--network-strategy",
        type=str,
        choices=[
            "malformed_pdu",
            "invalid_length",
            "buffer_overflow",
            "integer_overflow",
            "null_bytes",
            "unicode_injection",
            "protocol_state",
            "timing_attack",
            "all",
        ],
        default="all",
        metavar="STRAT",
        help="Network fuzzing strategy (default: all). Options: malformed_pdu, invalid_length, "
        "buffer_overflow, integer_overflow, null_bytes, unicode_injection, protocol_state, "
        "timing_attack, all",
    )

    # Security testing options
    security_group = parser.add_argument_group(
        "security testing", "Medical device security vulnerability testing"
    )
    security_group.add_argument(
        "--security-fuzz",
        action="store_true",
        help=(
            "Enable medical device security fuzzing. Generates mutations targeting "
            "CVE patterns (CVE-2025-35975, CVE-2025-36521, etc.) and vulnerability "
            "classes (OOB read/write, buffer overflow, format string, etc.)."
        ),
    )
    security_group.add_argument(
        "--target-cves",
        type=str,
        metavar="CVES",
        help=(
            "Comma-separated list of CVE patterns to target. "
            "Options: CVE-2025-35975, CVE-2025-36521, CVE-2025-5943, "
            "CVE-2025-1001, CVE-2022-2119, CVE-2022-2120 (default: all)"
        ),
    )
    security_group.add_argument(
        "--vuln-classes",
        type=str,
        metavar="CLASSES",
        help=(
            "Comma-separated list of vulnerability classes to target. "
            "Options: oob_write, oob_read, stack_overflow, heap_overflow, "
            "integer_overflow, format_string, null_deref, dos (default: all)"
        ),
    )
    security_group.add_argument(
        "--security-report",
        type=str,
        metavar="FILE",
        help="Output file for security fuzzing report (JSON format)",
    )

    # Response-aware GUI monitoring options
    monitor_group = parser.add_argument_group(
        "response monitoring", "Response-aware GUI monitoring options"
    )
    monitor_group.add_argument(
        "--response-aware",
        action="store_true",
        help=(
            "Enable response-aware fuzzing. Monitors GUI application for "
            "error dialogs, warning popups, memory issues, and hangs. "
            "Requires --gui-mode and pywinauto."
        ),
    )
    monitor_group.add_argument(
        "--detect-dialogs",
        action="store_true",
        help="Detect error dialogs and warning popups (requires pywinauto)",
    )
    monitor_group.add_argument(
        "--memory-threshold",
        type=int,
        default=1024,
        metavar="MB",
        help="Memory threshold for spike detection in MB (default: 1024)",
    )
    monitor_group.add_argument(
        "--hang-timeout",
        type=float,
        default=30.0,
        metavar="SEC",
        help="Timeout for hang detection in seconds (default: 30.0)",
    )

    args = parser.parse_args()

    # Handle quiet mode - suppress output except errors
    quiet_mode = getattr(args, "quiet", False)
    json_mode = getattr(args, "json", False)

    # Setup logging (verbose overrides quiet)
    if quiet_mode and not args.verbose:
        logging.getLogger().setLevel(logging.ERROR)
        setup_logging(False)
    else:
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

    # Validate input path (file or directory)
    recursive = getattr(args, "recursive", False)
    input_files = validate_input_path(args.input_file, recursive=recursive)
    is_directory_input = len(input_files) > 1 or Path(args.input_file).is_dir()

    if is_directory_input:
        logger.info(f"Found {len(input_files)} DICOM files in input directory")
    else:
        logger.info(f"Input file: {input_files[0]}")

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

    # Handle both 'count' and 'num_mutations' for test compatibility
    _count = getattr(args, "count", None)
    _num_mutations = getattr(args, "num_mutations", None)
    num_files_per_input: int = (
        _count
        if _count is not None
        else (_num_mutations if _num_mutations is not None else 100)
    )

    # Generate fuzzed files
    cli.header("DICOM Fuzzer - Fuzzing Campaign", "v1.6.0")
    if is_directory_input:
        cli.detail("Input", f"{args.input_file} ({len(input_files)} files)")
        if recursive:
            cli.detail("Mode", "Recursive directory scan")
        cli.detail("Per-file", f"{num_files_per_input} mutations each")
        total_expected = num_files_per_input * len(input_files)
        cli.detail("Total", f"~{total_expected} files (max)")
    else:
        cli.detail("Input", str(input_files[0].name))
        cli.detail("Target", f"{num_files_per_input} files")
    cli.detail("Output", str(args.output))
    if selected_strategies:
        cli.detail("Strategies", ", ".join(selected_strategies))
    else:
        cli.detail("Strategies", "all (metadata, header, pixel)")
    cli.divider()

    total_expected = num_files_per_input * len(input_files)
    logger.info(f"Generating up to {total_expected} fuzzed files...")
    start_time = time.time()

    try:
        generator = DICOMGenerator(args.output, skip_write_errors=True)
        files: list[Path] = []

        # Process each input file
        if is_directory_input:
            # Multiple input files from directory
            print(f"Processing {len(input_files)} input files...")
            input_iterator: Iterable[Path]
            if HAS_TQDM and not args.verbose:
                from tqdm import tqdm as tqdm_iter

                input_iterator = tqdm_iter(
                    input_files,
                    desc="Input files",
                    unit="file",
                    ncols=70,
                )
            else:
                input_iterator = input_files

            for input_file in input_iterator:
                try:
                    batch_files = generator.generate_batch(
                        str(input_file),
                        count=num_files_per_input,
                        strategies=selected_strategies,
                    )
                    files.extend(batch_files)
                except Exception as e:
                    logger.warning(f"Failed to process {input_file}: {e}")
                    if args.verbose:
                        print(f"  [!] Skipping {input_file.name}: {e}")
        else:
            # Single input file - use original progress bar logic
            input_path = input_files[0]
            if HAS_TQDM and not args.verbose and num_files_per_input >= 20:
                print("Generating fuzzed files...")
                with tqdm(total=num_files_per_input, unit="file", ncols=70) as pbar:
                    # Generate in smaller batches to update progress
                    batch_size = max(1, num_files_per_input // 20)  # 20 updates
                    remaining = num_files_per_input
                    all_files: list[Path] = []

                    while remaining > 0:
                        current_batch = min(batch_size, remaining)
                        batch_files = generator.generate_batch(
                            str(input_path),
                            count=current_batch,
                            strategies=selected_strategies,
                        )
                        all_files.extend(batch_files)
                        pbar.update(len(batch_files))
                        remaining -= current_batch

                    files = all_files
            else:
                # No progress bar or small file count, generate all at once
                files = generator.generate_batch(
                    str(input_path),
                    count=num_files_per_input,
                    strategies=selected_strategies,
                )

        elapsed_time = time.time() - start_time
        skipped = (
            getattr(generator.stats, "skipped_due_to_write_errors", 0)
            if hasattr(generator, "stats")
            else 0
        )
        files_per_sec = len(files) / elapsed_time if elapsed_time > 0 else 0

        # Collect results for potential JSON output
        results_data = {
            "status": "success",
            "generated_count": len(files),
            "skipped_count": skipped,
            "duration_seconds": round(elapsed_time, 2),
            "files_per_second": round(files_per_sec, 1),
            "output_directory": str(args.output),
            "files": [str(f) for f in files[:100]],  # Limit to 100 in JSON
        }

        # Add strategy usage if available
        if hasattr(generator, "stats") and hasattr(generator.stats, "strategies_used"):
            strategies_used = generator.stats.strategies_used
            if isinstance(strategies_used, dict) and strategies_used:
                results_data["strategies_used"] = strategies_used

        # Output in JSON format if requested
        if json_mode:
            print(json.dumps(results_data, indent=2))
        elif not quiet_mode:
            # Display results with colored output
            cli.section("Campaign Results")
            stats = {
                "Successfully generated": f"{len(files)} files",
                "Skipped": skipped,
                "Duration": f"{elapsed_time:.2f}s ({files_per_sec:.1f} files/sec)",
                "Output": str(args.output),
            }

            if "strategies_used" in results_data:
                strat_used = results_data["strategies_used"]
                if isinstance(strat_used, dict):
                    stats["Strategies"] = ", ".join(
                        f"{s}({c})" for s, c in sorted(strat_used.items())
                    )

            cli.print_summary(
                "Fuzzing Complete",
                stats,
                success_count=len(files),
                error_count=skipped,
            )

            if args.verbose:
                cli.info("Sample generated files:")
                for f in files[:10]:
                    cli.status(f"  - {f.name}")
                if len(files) > 10:
                    cli.status(f"  ... and {len(files) - 10} more")

        # Network fuzzing if --network-fuzz specified
        if getattr(args, "network_fuzz", False):
            if not HAS_NETWORK_FUZZER:
                cli.error("Network fuzzing module not available.")
                cli.status(
                    "Please check that dicom_fuzzer.core.network_fuzzer is installed."
                )
                sys.exit(1)

            cli.header("DICOM Network Protocol Fuzzing")
            cli.detail("Host", f"{args.host}:{args.port}")
            cli.detail("AE Title", args.ae_title)
            cli.detail("Strategy", args.network_strategy)
            cli.divider()

            try:
                network_config = DICOMNetworkConfig(
                    target_host=args.host,
                    target_port=args.port,
                    calling_ae=args.ae_title,
                    timeout=args.timeout,
                )
                network_fuzzer = DICOMNetworkFuzzer(network_config)

                # Run network fuzzing with selected strategy
                logger.info("Starting DICOM network protocol fuzzing...")
                strategy_map = {
                    "malformed_pdu": FuzzingStrategy.MALFORMED_PDU,
                    "invalid_length": FuzzingStrategy.INVALID_LENGTH,
                    "buffer_overflow": FuzzingStrategy.BUFFER_OVERFLOW,
                    "integer_overflow": FuzzingStrategy.INTEGER_OVERFLOW,
                    "null_bytes": FuzzingStrategy.NULL_BYTES,
                    "unicode_injection": FuzzingStrategy.UNICODE_INJECTION,
                    "protocol_state": FuzzingStrategy.PROTOCOL_STATE,
                    "timing_attack": FuzzingStrategy.TIMING_ATTACK,
                    "all": None,  # None means run all strategies
                }
                selected_strategy = strategy_map.get(args.network_strategy)
                strategies = [selected_strategy] if selected_strategy else None
                network_results = network_fuzzer.run_campaign(strategies=strategies)

                # Print results
                print("\n  Network Fuzzing Results:")
                print(f"  Total PDUs sent:  {len(network_results)}")
                errors = sum(1 for r in network_results if r.error)
                print(f"  Errors detected:  {errors}")

                # Print errors if any
                if errors > 0 and args.verbose:
                    print("\n  Errors:")
                    for result in network_results:
                        if result.error:
                            print(f"    - {result.strategy.value}: {result.error}")

                print("=" * 70 + "\n")

            except Exception as e:
                logger.error(f"Network fuzzing failed: {e}", exc_info=args.verbose)
                print(f"\n[ERROR] Network fuzzing failed: {e}")
                if args.verbose:
                    import traceback

                    traceback.print_exc()

        # Security fuzzing if --security-fuzz specified
        if getattr(args, "security_fuzz", False):
            if not HAS_SECURITY_FUZZER:
                print("[ERROR] Security fuzzing module not available.")
                print(
                    "Please check that dicom_fuzzer.strategies.medical_device_security is installed."
                )
                sys.exit(1)

            print("\n" + "=" * 70)
            print("  Medical Device Security Fuzzing")
            print("=" * 70)

            try:
                import pydicom

                # Load the first input DICOM file (for security fuzzing)
                first_input = input_files[0]
                ds = pydicom.dcmread(str(first_input))

                # Parse CVE targets if specified
                target_cves = None
                if getattr(args, "target_cves", None):
                    from dicom_fuzzer.strategies.medical_device_security import (
                        CVEPattern,
                    )

                    cve_map = {
                        "CVE-2025-35975": CVEPattern.CVE_2025_35975,
                        "CVE-2025-36521": CVEPattern.CVE_2025_36521,
                        "CVE-2025-5943": CVEPattern.CVE_2025_5943,
                        "CVE-2025-1001": CVEPattern.CVE_2025_1001,
                        "CVE-2022-2119": CVEPattern.CVE_2022_2119,
                        "CVE-2022-2120": CVEPattern.CVE_2022_2120,
                    }
                    target_cves = []
                    for cve in args.target_cves.split(","):
                        cve = cve.strip().upper()
                        if cve in cve_map:
                            target_cves.append(cve_map[cve])
                        else:
                            print(f"  [!] Unknown CVE: {cve}")

                # Parse vulnerability classes if specified
                target_vulns = None
                if getattr(args, "vuln_classes", None):
                    vuln_map = {
                        "oob_write": VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                        "oob_read": VulnerabilityClass.OUT_OF_BOUNDS_READ,
                        "stack_overflow": VulnerabilityClass.STACK_BUFFER_OVERFLOW,
                        "heap_overflow": VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
                        "integer_overflow": VulnerabilityClass.INTEGER_OVERFLOW,
                        "format_string": VulnerabilityClass.FORMAT_STRING,
                        "null_deref": VulnerabilityClass.NULL_POINTER_DEREF,
                        "dos": VulnerabilityClass.DENIAL_OF_SERVICE,
                    }
                    target_vulns = []
                    for vuln in args.vuln_classes.split(","):
                        vuln = vuln.strip().lower()
                        if vuln in vuln_map:
                            target_vulns.append(vuln_map[vuln])
                        else:
                            print(f"  [!] Unknown vulnerability class: {vuln}")

                # Create security fuzzer config
                security_config = MedicalDeviceSecurityConfig(
                    target_cves=target_cves
                    if target_cves
                    else list(CVEPattern)
                    if "CVEPattern" in dir()
                    else [],
                    target_vulns=target_vulns
                    if target_vulns
                    else list(VulnerabilityClass),
                )
                security_fuzzer = MedicalDeviceSecurityFuzzer(security_config)

                # Generate security mutations
                mutations = security_fuzzer.generate_mutations(ds)
                print(f"  Mutations generated: {len(mutations)}")

                # Print summary
                security_fuzzer.print_summary()

                # Save report if specified
                if getattr(args, "security_report", None):
                    summary = security_fuzzer.get_summary()
                    report_path = Path(args.security_report)
                    with open(report_path, "w") as report_file:
                        json.dump(summary, report_file, indent=2)
                    print(f"  Report saved to: {report_path}")

                # Apply mutations and save fuzzed files
                if mutations and args.target:
                    print(f"\n  Applying {len(mutations)} security mutations...")
                    security_output = output_path / "security_fuzzed"
                    security_output.mkdir(parents=True, exist_ok=True)

                    for i, mutation in enumerate(mutations[:num_files_per_input]):
                        try:
                            ds_copy = pydicom.dcmread(str(first_input))
                            mutated_ds = security_fuzzer.apply_mutation(
                                ds_copy, mutation
                            )
                            output_file = (
                                security_output
                                / f"security_{i:04d}_{mutation.name}.dcm"
                            )
                            mutated_ds.save_as(str(output_file))
                        except Exception as e:
                            logger.debug(
                                f"Failed to apply mutation {mutation.name}: {e}"
                            )

                    print(f"  Security-fuzzed files saved to: {security_output}")

            except Exception as e:
                logger.error(f"Security fuzzing failed: {e}", exc_info=args.verbose)
                print(f"\n[ERROR] Security fuzzing failed: {e}")
                if args.verbose:
                    import traceback

                    traceback.print_exc()

        # Target testing if --target specified
        if args.target:
            gui_mode = getattr(args, "gui_mode", False)
            memory_limit = getattr(args, "memory_limit", None)

            print("\n" + "=" * 70)
            if gui_mode:
                print("  GUI Application Testing (--gui-mode)")
            else:
                print("  Target Application Testing")
            print("=" * 70)
            print(f"  Target:     {args.target}")
            print(f"  Timeout:    {args.timeout}s")
            print(f"  Test files: {len(files)}")
            if gui_mode:
                print("  Mode:       GUI (app killed after timeout)")
                if memory_limit:
                    print(f"  Mem limit:  {memory_limit}MB")
                startup_delay_display = getattr(args, "startup_delay", 0.0)
                if startup_delay_display > 0:
                    print(
                        f"  Startup:    {startup_delay_display}s delay before monitoring"
                    )
            print("=" * 70 + "\n")

            try:
                runner: GUITargetRunner | TargetRunner
                if gui_mode:
                    # Use GUITargetRunner for GUI applications
                    if not HAS_PSUTIL:
                        print(
                            "[ERROR] GUI mode requires psutil. "
                            "Install with: pip install psutil"
                        )
                        sys.exit(1)

                    startup_delay = getattr(args, "startup_delay", 0.0)
                    runner = GUITargetRunner(
                        target_executable=args.target,
                        timeout=args.timeout,
                        crash_dir=str(output_path / "crashes"),
                        memory_limit_mb=memory_limit,
                        startup_delay=startup_delay,
                    )
                    logger.info("Starting GUI fuzzing campaign...")
                else:
                    # Use standard TargetRunner for CLI applications
                    runner = TargetRunner(
                        target_executable=args.target,
                        timeout=args.timeout,
                        crash_dir=str(output_path / "crashes"),
                        resource_limits=resource_limits,
                    )
                    logger.info("Starting target testing campaign...")

                if resource_limits and not gui_mode:
                    logger.info("Resource limits will be enforced during testing")

                test_start = time.time()

                results = runner.run_campaign(
                    test_files=files, stop_on_crash=args.stop_on_crash
                )

                test_elapsed = time.time() - test_start

                # Display results (type mismatch between GUITargetRunner/TargetRunner result types)
                summary = runner.get_summary(results)  # type: ignore[arg-type,assignment]
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
            except ImportError as e:
                logger.error(f"Missing dependency: {e}")
                print(f"\n[ERROR] {e}")
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
