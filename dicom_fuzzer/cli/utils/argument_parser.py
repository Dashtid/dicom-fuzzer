"""Argument Parser for DICOM Fuzzer CLI.

Centralizes all command-line argument definitions for the main fuzzing command.
"""

from __future__ import annotations

import argparse

# Version string for the fuzzer
VERSION = "DICOM Fuzzer v1.7.0"


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for the main command.

    Returns:
        Configured ArgumentParser with all argument groups.

    """
    parser = argparse.ArgumentParser(
        description="DICOM Fuzzer - Security testing tool for medical imaging systems",
        epilog="""
Examples:
  # Fuzz a single file
  %(prog)s input.dcm -c 50 -o ./output

  # Fuzz all DICOM files in a directory
  %(prog)s ./dicom_folder/ -c 10 -o ./output

  # List DICOM sample sources
  %(prog)s samples --list-sources

Subcommands (use --help for details):
  samples      Manage DICOM seed files (sources, strip pixel data)
  tls          DICOM TLS/authentication testing
  persistent   AFL-style persistent mode fuzzing
  state        Protocol state machine fuzzing
  corpus       Corpus management and minimization
  study        Study-level fuzzing (cross-series attacks)
  calibrate    Calibration/measurement fuzzing
  stress       Memory stress testing
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    _add_basic_args(parser)
    _add_target_args(parser)
    _add_resource_args(parser)
    _add_network_args(parser)
    _add_security_args(parser)
    _add_monitor_args(parser)

    return parser


def _add_basic_args(parser: argparse.ArgumentParser) -> None:
    """Add basic/required arguments."""
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
    parser.add_argument("--version", action="version", version=VERSION)


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    """Add target testing arguments."""
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


def _add_resource_args(parser: argparse.ArgumentParser) -> None:
    """Add resource limit arguments."""
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


def _add_network_args(parser: argparse.ArgumentParser) -> None:
    """Add network fuzzing arguments."""
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


def _add_security_args(parser: argparse.ArgumentParser) -> None:
    """Add security testing arguments."""
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


def _add_monitor_args(parser: argparse.ArgumentParser) -> None:
    """Add response monitoring arguments."""
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
