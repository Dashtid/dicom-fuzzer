"""SBOM Generation CLI Command.

Generate FDA-compliant Software Bill of Materials in CycloneDX and SPDX formats.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    """Generate SBOM from project files.

    Args:
        argv: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code (0 for success)

    """
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer sbom",
        description="Generate Software Bill of Materials (SBOM) for FDA compliance",
        epilog="""
Examples:
  # Generate SBOM in all formats
  %(prog)s

  # Generate only CycloneDX format
  %(prog)s --format cyclonedx

  # Generate with organization and device info
  %(prog)s --org "Medical Corp" --device "DICOM Viewer" -o ./reports

  # Generate from specific project directory
  %(prog)s --project /path/to/project
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="./output/sbom",
        metavar="DIR",
        help="Output directory for SBOM files (default: ./output/sbom)",
    )

    parser.add_argument(
        "-p",
        "--project",
        type=str,
        metavar="DIR",
        help="Project directory containing pyproject.toml/uv.lock (default: current)",
    )

    parser.add_argument(
        "--org",
        "--organization",
        type=str,
        default="",
        metavar="NAME",
        help="Organization name for SBOM metadata",
    )

    parser.add_argument(
        "--device",
        type=str,
        default="",
        metavar="NAME",
        help="Device/product name for SBOM metadata",
    )

    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=["cyclonedx", "spdx", "summary", "all"],
        default="all",
        help="Output format (default: all)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args(argv)

    # Import here to avoid circular imports
    from dicom_fuzzer.reporting.sbom import generate_sbom

    print("=" * 60)
    print("  DICOM Fuzzer - SBOM Generator")
    print("=" * 60)

    # Determine formats to generate
    if args.format == "all":
        formats = ["cyclonedx", "spdx", "summary"]
    else:
        formats = [args.format]

    # Generate SBOM
    project_dir = Path(args.project) if args.project else None
    output_dir = Path(args.output)

    print(f"\n[i] Project directory: {project_dir or 'current'}")
    print(f"[i] Output directory: {output_dir}")
    print(f"[i] Formats: {', '.join(formats)}")

    if args.org:
        print(f"[i] Organization: {args.org}")
    if args.device:
        print(f"[i] Device: {args.device}")

    print("-" * 60)

    try:
        outputs = generate_sbom(
            project_dir=project_dir,
            output_dir=output_dir,
            organization=args.org,
            device_name=args.device,
            formats=formats,
        )

        print("\n[+] SBOM generation complete:")
        for fmt, path in outputs.items():
            print(f"    - {fmt}: {path}")

        # Print component count if verbose
        if args.verbose:
            from dicom_fuzzer.reporting.sbom import SBOMGenerator

            generator = SBOMGenerator(project_dir)
            sbom = generator.generate()
            print(f"\n[i] Components in SBOM: {len(sbom.components)}")
            if sbom.root_component:
                root = sbom.root_component
                print(f"[i] Root component: {root.name} v{root.version}")

        print("\n" + "=" * 60)
        return 0

    except Exception as e:
        print(f"\n[-] Error generating SBOM: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
