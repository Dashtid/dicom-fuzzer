"""DICOMweb Subcommand for DICOM Fuzzer.

Security testing for DICOMweb REST API services including:
- WADO-RS (Web Access to DICOM Objects)
- STOW-RS (Store Over the Web)
- QIDO-RS (Query based on ID)

NOTE: This CLI module provides a simplified interface to the core DICOMweb fuzzer.
For advanced usage, import dicom_fuzzer.core.dicomweb_fuzzer directly.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Attack categories
ATTACK_CATEGORIES = [
    "injection",
    "path_traversal",
    "authentication",
    "idor",
    "xxe",
    "ssrf",
]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for dicomweb subcommand."""
    parser = argparse.ArgumentParser(
        description="Security testing for DICOMweb REST API services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan DICOMweb server
  dicom-fuzzer dicomweb --scan https://pacs.example.com/dicomweb

  # Scan with authentication
  dicom-fuzzer dicomweb --scan https://example.com/dicomweb --auth-token "Bearer xxx"

  # List DICOMweb endpoints
  dicom-fuzzer dicomweb --list-endpoints

For advanced testing, use the Python API:
  from dicom_fuzzer.core.dicomweb_fuzzer import DICOMwebFuzzer
        """,
    )

    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--scan",
        type=str,
        metavar="URL",
        help="Base URL of DICOMweb service to scan",
    )
    action_group.add_argument(
        "--list-endpoints",
        action="store_true",
        help="List all DICOMweb endpoints that will be tested",
    )

    # Target options
    target_group = parser.add_argument_group("target options")
    target_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SEC",
        help="Request timeout in seconds (default: 30)",
    )

    # Authentication options
    auth_group = parser.add_argument_group("authentication options")
    auth_group.add_argument(
        "--auth-token",
        type=str,
        metavar="TOKEN",
        help="Authorization header value (e.g., 'Bearer xxx')",
    )
    auth_group.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        help="Output directory for reports",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    """Run security scan of DICOMweb service."""
    base_url = args.scan

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - DICOMweb Security Scanner")
    print("=" * 70)
    print(f"  Target:   {base_url}")
    print(f"  Timeout:  {args.timeout}s")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.core.dicomweb_fuzzer import (
            DICOMwebFuzzer,
            DICOMwebFuzzerConfig,
        )

        config = DICOMwebFuzzerConfig(
            base_url=base_url,
            timeout=args.timeout,
            auth_token=args.auth_token or "",
            verify_ssl=not args.no_verify_ssl,
        )

        fuzzer = DICOMwebFuzzer(config=config)

        print("[i] Starting security scan...")
        results = fuzzer.run_full_campaign()

        print(f"\n[+] Scan complete: {len(results)} tests run")

        # Save report if output specified
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            report_file = output_dir / "dicomweb_scan.json"

            report_data: dict[str, Any] = {
                "target": base_url,
                "tests_run": len(results),
                "results": results,
            }

            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"\n[+] Report saved: {report_file}")

        return 0

    except ImportError as e:
        print(f"[-] DICOMweb fuzzer not available: {e}")
        return 1
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_list_endpoints(args: argparse.Namespace) -> int:
    """List all DICOMweb endpoints that will be tested."""
    print("\n" + "=" * 70)
    print("  DICOMweb Endpoints")
    print("=" * 70 + "\n")

    endpoints = {
        "WADO-RS (Retrieve)": [
            "GET /studies/{study}",
            "GET /studies/{study}/series/{series}",
            "GET /studies/{study}/series/{series}/instances/{instance}",
            "GET /studies/{study}/metadata",
        ],
        "STOW-RS (Store)": [
            "POST /studies",
            "POST /studies/{study}",
        ],
        "QIDO-RS (Query)": [
            "GET /studies?{query}",
            "GET /studies/{study}/series?{query}",
        ],
    }

    for service, paths in endpoints.items():
        print(f"  [{service}]")
        for path in paths:
            print(f"    - {path}")
        print()

    print("=" * 70)
    print("\nAttack Categories:")
    for cat in ATTACK_CATEGORIES:
        print(f"  - {cat}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for dicomweb subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.scan:
        return run_scan(args)
    elif args.list_endpoints:
        return run_list_endpoints(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
