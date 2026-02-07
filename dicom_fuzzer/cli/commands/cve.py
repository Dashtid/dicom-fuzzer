"""CVE Replication CLI - Generate DICOM files that replicate known CVEs.

This is NOT fuzzing - it produces deterministic output for specific vulnerabilities.
Use this to validate whether a DICOM viewer/parser is vulnerable to known CVEs.

Usage:
    dicom-fuzzer cve --list                     # List all available CVEs
    dicom-fuzzer cve --cve CVE-2025-5943 -t input.dcm -o output/
    dicom-fuzzer cve --all -t input.dcm -o cve_files/
    dicom-fuzzer cve --product MicroDicom -t input.dcm -o output/
    dicom-fuzzer cve --all -t input.dcm --target viewer.exe   # Generate + test
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.cve import CVEFile, CVEGenerator, get_cve_info, list_cves
from dicom_fuzzer.cve.registry import (
    CVECategory,
    get_cves_by_category,
    get_cves_by_product,
)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CVE subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer cve",
        description="Generate DICOM files that replicate known CVEs for security validation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all available CVEs
  dicom-fuzzer cve --list

  # Generate files for a specific CVE
  dicom-fuzzer cve --cve CVE-2025-5943 -t template.dcm -o ./output

  # Generate files for all CVEs
  dicom-fuzzer cve --all -t template.dcm -o ./cve_files

  # Generate files for CVEs affecting a specific product
  dicom-fuzzer cve --product MicroDicom -t template.dcm -o ./output

  # Generate files for a specific category
  dicom-fuzzer cve --category heap_overflow -t template.dcm -o ./output

  # Generate and test against a target viewer
  dicom-fuzzer cve --all -t template.dcm --target viewer.exe
""",
    )

    # Mode selection (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--list",
        action="store_true",
        help="List all available CVEs with descriptions",
    )
    mode_group.add_argument(
        "--cve",
        type=str,
        metavar="CVE-ID",
        help="Generate files for a specific CVE (e.g., CVE-2025-5943)",
    )
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Generate files for all known CVEs",
    )
    mode_group.add_argument(
        "--product",
        type=str,
        metavar="NAME",
        help="Generate files for CVEs affecting a specific product (e.g., MicroDicom)",
    )
    mode_group.add_argument(
        "--category",
        type=str,
        metavar="CAT",
        help="Generate files for CVEs in a specific category (e.g., heap_overflow)",
    )
    mode_group.add_argument(
        "--info",
        type=str,
        metavar="CVE-ID",
        help="Show detailed information about a specific CVE",
    )

    # Input/output options
    parser.add_argument(
        "-t",
        "--template",
        type=str,
        metavar="FILE",
        help="Template DICOM file to use as base for mutations",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="./cve_output",
        metavar="DIR",
        help="Output directory for generated files (default: ./cve_output)",
    )

    # Target testing options
    parser.add_argument(
        "--target",
        type=str,
        metavar="EXE",
        help="Path to viewer executable to test generated files against",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-file execution timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--stop-on-crash",
        action="store_true",
        help="Stop testing after the first crash",
    )

    # Output format options
    parser.add_argument(
        "--flat",
        action="store_true",
        help="Save all files directly in output dir (no subdirectories per CVE)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def cmd_list_cves(json_output: bool = False) -> int:
    """List all available CVEs."""
    cves = list_cves()

    if json_output:
        import json

        data = []
        for cve_id in cves:
            info = get_cve_info(cve_id)
            if info:
                data.append(info.to_dict())
        print(json.dumps(data, indent=2))
        return 0

    print(f"\n[+] Available CVEs: {len(cves)}\n")
    print(f"{'CVE ID':<18} {'Severity':<10} {'Product':<20} {'Description'}")
    print("-" * 100)

    for cve_id in cves:
        info = get_cve_info(cve_id)
        if info:
            desc = (
                info.description[:45] + "..."
                if len(info.description) > 45
                else info.description
            )
            print(
                f"{cve_id:<18} {info.severity:<10} {info.affected_product:<20} {desc}"
            )

    print("\n[i] Use 'dicom-fuzzer cve --info CVE-ID' for details")
    return 0


def cmd_show_info(cve_id: str) -> int:
    """Show detailed information about a CVE."""
    info = get_cve_info(cve_id.upper())

    if info is None:
        print(f"[-] Unknown CVE: {cve_id}")
        print("[i] Use 'dicom-fuzzer cve --list' to see available CVEs")
        return 1

    print(f"\n{'=' * 60}")
    print(f"  {info.cve_id}")
    print(f"{'=' * 60}")
    print(f"  Description: {info.description}")
    print(f"  Category:    {info.category.value}")
    print(f"  Severity:    {info.severity.upper()}")
    if info.cvss_score:
        print(f"  CVSS Score:  {info.cvss_score}")
    print(f"  Product:     {info.affected_product}")
    if info.affected_versions:
        print(f"  Versions:    {info.affected_versions}")
    print(f"  Target:      {info.target_component}")
    print(f"  Variants:    {info.variants}")

    if info.references:
        print("\n  References:")
        for ref in info.references:
            print(f"    - {ref}")

    print()
    return 0


def cmd_generate(
    generator: CVEGenerator,
    cve_id: str,
    template: bytes,
    output_dir: Path,
    flat: bool,
    verbose: bool,
) -> tuple[int, list[CVEFile]]:
    """Generate files for a specific CVE.

    Returns:
        Tuple of (return_code, list_of_generated_files).

    """
    try:
        files = generator.generate(cve_id, template)
    except ValueError as e:
        print(f"[-] Error: {e}")
        return 1, []

    info = files[0].info
    print(f"\n[+] {cve_id}: {info.description}")
    print(f"    Generating {len(files)} variant(s)...")

    for cve_file in files:
        if flat:
            file_path = output_dir / cve_file.filename
        else:
            cve_dir = output_dir / cve_id
            cve_dir.mkdir(parents=True, exist_ok=True)
            file_path = cve_dir / f"{cve_file.variant}.dcm"

        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(cve_file.data)

        if verbose:
            print(f"    -> {file_path}")

    return 0, files


def cmd_test_target(
    cve_files: list[CVEFile],
    target: str,
    output_dir: Path,
    timeout: float,
    stop_on_crash: bool,
    verbose: bool,
) -> int:
    """Run generated CVE files against a target executable."""
    from dicom_fuzzer.core.harness.target_runner import ExecutionStatus, TargetRunner

    target_path = Path(target)
    if not target_path.exists():
        print(f"[-] Error: Target executable not found: {target}")
        return 1

    crash_dir = output_dir / "crashes"
    crash_dir.mkdir(parents=True, exist_ok=True)

    runner = TargetRunner(
        target_executable=str(target_path),
        timeout=timeout,
        crash_dir=str(crash_dir),
        enable_monitoring=True,
        collect_stdout=False,
        collect_stderr=True,
        max_retries=0,
        enable_circuit_breaker=False,
    )

    # Save files to a test directory and build path -> CVEFile map
    test_dir = output_dir / "test_files"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_paths: list[Path] = []
    file_map: dict[Path, CVEFile] = {}
    for cve_file in cve_files:
        path = cve_file.save(test_dir)
        test_paths.append(path)
        file_map[path] = cve_file

    print(f"\n[+] Testing {len(test_paths)} CVE files against: {target_path.name}")
    results = runner.run_campaign(test_paths, stop_on_crash=stop_on_crash)

    crashes = results.get(ExecutionStatus.CRASH, [])
    hangs = results.get(ExecutionStatus.HANG, [])
    successes = results.get(ExecutionStatus.SUCCESS, [])
    errors = results.get(ExecutionStatus.ERROR, [])

    total = len(test_paths)
    print(f"\n{'=' * 60}")
    print(f"  CVE Validation Results: {total} files tested")
    print(f"{'=' * 60}")
    print(f"  [+] Passed:  {len(successes)}")
    print(f"  [-] Crashed: {len(crashes)}")
    print(f"  [!] Hung:    {len(hangs)}")
    print(f"  [!] Errors:  {len(errors)}")

    if crashes:
        print("\n  Crashes (potential vulnerabilities):")
        for r in crashes:
            cf = file_map.get(r.test_file)
            label = f"{cf.cve_id}/{cf.variant}" if cf else str(r.test_file.name)
            info_line = f"    [-] {label}"
            if r.is_exploitable and r.windows_crash_info:
                info_line += f" [EXPLOITABLE: {r.windows_crash_info.exception_name}]"
            print(info_line)
            if verbose and r.stderr:
                for line in r.stderr.strip().splitlines()[:3]:
                    print(f"        {line}")

    if hangs:
        print("\n  Hangs (potential DoS):")
        for r in hangs:
            cf = file_map.get(r.test_file)
            label = f"{cf.cve_id}/{cf.variant}" if cf else str(r.test_file.name)
            print(f"    [!] {label} ({r.hang_reason})")

    if crashes:
        print(f"\n  [i] Crash artifacts saved to: {crash_dir}")

    return 1 if crashes or hangs else 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for CVE CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)

    # Handle list command
    if args.list:
        return cmd_list_cves(args.json)

    # Handle info command
    if args.info:
        return cmd_show_info(args.info)

    # For generation commands, we need a template
    if not args.template:
        print("[-] Error: --template is required for generating CVE files")
        print("[i] Use: dicom-fuzzer cve --cve CVE-ID -t template.dcm -o output/")
        return 1

    template_path = Path(args.template)
    if not template_path.exists():
        print(f"[-] Error: Template file not found: {args.template}")
        return 1

    template_bytes = template_path.read_bytes()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    generator = CVEGenerator()
    all_cve_files: list[CVEFile] = []

    # Handle specific CVE
    if args.cve:
        rc, files = cmd_generate(
            generator,
            args.cve.upper(),
            template_bytes,
            output_dir,
            args.flat,
            args.verbose,
        )
        if rc != 0:
            return rc
        all_cve_files.extend(files)

    # Handle --all
    elif args.all:
        print(f"\n[+] Generating files for all {len(generator.available_cves)} CVEs...")
        total_files = 0
        for cve_id in generator.available_cves:
            rc, files = cmd_generate(
                generator,
                cve_id,
                template_bytes,
                output_dir,
                args.flat,
                args.verbose,
            )
            if rc != 0:
                print(f"    [!] Warning: Failed to generate {cve_id}")
            else:
                total_files += len(files)
                all_cve_files.extend(files)

        print(f"\n[+] Generated {total_files} files in {output_dir}")

    # Handle --product
    elif args.product:
        matching = get_cves_by_product(args.product)
        if not matching:
            print(f"[-] No CVEs found for product: {args.product}")
            return 1

        print(f"\n[+] Found {len(matching)} CVEs affecting {args.product}")
        for info in matching:
            if info.cve_id in generator.available_cves:
                rc, files = cmd_generate(
                    generator,
                    info.cve_id,
                    template_bytes,
                    output_dir,
                    args.flat,
                    args.verbose,
                )
                if rc == 0:
                    all_cve_files.extend(files)

    # Handle --category
    elif args.category:
        try:
            category = CVECategory(args.category)
        except ValueError:
            print(f"[-] Unknown category: {args.category}")
            print(f"[i] Valid categories: {', '.join(c.value for c in CVECategory)}")
            return 1

        matching = get_cves_by_category(category)
        if not matching:
            print(f"[-] No CVEs found for category: {args.category}")
            return 1

        print(f"\n[+] Found {len(matching)} CVEs in category {args.category}")
        for info in matching:
            if info.cve_id in generator.available_cves:
                rc, files = cmd_generate(
                    generator,
                    info.cve_id,
                    template_bytes,
                    output_dir,
                    args.flat,
                    args.verbose,
                )
                if rc == 0:
                    all_cve_files.extend(files)

    # If --target specified, run generated files against the target
    if args.target and all_cve_files:
        return cmd_test_target(
            all_cve_files,
            args.target,
            output_dir,
            args.timeout,
            args.stop_on_crash,
            args.verbose,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
