"""Samples Subcommand for DICOM Fuzzer.

Provides functionality to generate sample DICOM files for testing,
including synthetic samples and intentionally malicious samples
for security testing.
"""

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.core.synthetic import SyntheticDicomGenerator

# Public DICOM sample sources
SAMPLE_SOURCES = {
    "rubo": {
        "name": "Rubo Medical Imaging",
        "url": "https://www.rubomedical.com/dicom_files/",
        "description": "Free sample DICOM files for testing",
    },
    "osirix": {
        "name": "OsiriX DICOM Sample Images",
        "url": "https://www.osirix-viewer.com/resources/dicom-image-library/",
        "description": "Large collection of DICOM datasets from various modalities",
    },
    "dicom_library": {
        "name": "DICOM Library",
        "url": "https://www.dicomlibrary.com/",
        "description": "Free DICOM image sharing and anonymization service",
    },
    "tcia": {
        "name": "The Cancer Imaging Archive (TCIA)",
        "url": "https://www.cancerimagingarchive.net/",
        "description": "Large public archive of cancer imaging data (requires registration)",
    },
    "medpix": {
        "name": "MedPix",
        "url": "https://medpix.nlm.nih.gov/",
        "description": "NIH database of medical images (requires registration)",
    },
}

# Supported modalities for generation
SUPPORTED_MODALITIES = ["CT", "MR", "US", "CR", "DX", "PT", "NM", "XA", "RF", "SC"]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for samples subcommand."""
    parser = argparse.ArgumentParser(
        description="Generate or list sample DICOM files for fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 10 synthetic CT images
  dicom-fuzzer samples --generate -c 10 -m CT -o ./samples

  # Generate a series of 20 MR slices
  dicom-fuzzer samples --generate --series -c 20 -m MR -o ./samples

  # List download sources
  dicom-fuzzer samples --list-sources

  # Generate all malicious samples for security testing
  dicom-fuzzer samples --malicious -o ./malicious_samples

  # Generate only preamble attack samples (polyglots)
  dicom-fuzzer samples --preamble-attacks -o ./polyglots

  # Generate CVE reproduction samples
  dicom-fuzzer samples --cve-samples -o ./cve_samples

  # Generate parser stress tests with deep nesting
  dicom-fuzzer samples --parser-stress --depth 200 -o ./stress_tests

  # Scan DICOM files for security threats
  dicom-fuzzer samples --scan ./dicom_folder --recursive

  # Sanitize a potentially malicious file
  dicom-fuzzer samples --sanitize suspicious.dcm
        """,
    )

    # Action arguments (mutually exclusive)
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--generate",
        action="store_true",
        help="Generate synthetic DICOM files (no PHI)",
    )
    action_group.add_argument(
        "--list-sources",
        action="store_true",
        help="List public sources for downloading real DICOM samples",
    )
    action_group.add_argument(
        "--malicious",
        action="store_true",
        help="Generate malicious DICOM samples for security testing (all categories)",
    )
    action_group.add_argument(
        "--preamble-attacks",
        action="store_true",
        help="Generate PE/DICOM and ELF/DICOM polyglot files (CVE-2019-11687)",
    )
    action_group.add_argument(
        "--cve-samples",
        action="store_true",
        help="Generate CVE reproduction samples for known vulnerabilities",
    )
    action_group.add_argument(
        "--parser-stress",
        action="store_true",
        help="Generate parser stress test samples (deep nesting, truncation, etc.)",
    )
    action_group.add_argument(
        "--compliance",
        action="store_true",
        help="Generate DICOM compliance violation samples",
    )
    action_group.add_argument(
        "--scan",
        type=str,
        metavar="PATH",
        help="Scan DICOM file(s) for security issues",
    )
    action_group.add_argument(
        "--sanitize",
        type=str,
        metavar="PATH",
        help="Sanitize DICOM file preamble (neutralize polyglot attacks)",
    )
    action_group.add_argument(
        "--strip-pixel-data",
        type=str,
        metavar="PATH",
        help="Strip PixelData from DICOM files for corpus optimization",
    )

    # Generation options
    gen_group = parser.add_argument_group("generation options")
    gen_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=10,
        metavar="N",
        help="Number of files to generate (default: 10)",
    )
    gen_group.add_argument(
        "-o",
        "--output",
        type=str,
        default="./artifacts/samples",
        metavar="DIR",
        help="Output directory (default: ./artifacts/samples)",
    )
    gen_group.add_argument(
        "-m",
        "--modality",
        type=str,
        choices=SUPPORTED_MODALITIES,
        metavar="MOD",
        help="Modality to generate (CT, MR, US, CR, DX, PT, NM, XA, RF, SC). "
        "If not specified, generates random modalities.",
    )
    gen_group.add_argument(
        "--series",
        action="store_true",
        help="Generate files as a consistent series (same patient/study/series UIDs)",
    )
    gen_group.add_argument(
        "--rows",
        type=int,
        default=256,
        metavar="N",
        help="Image rows (default: 256)",
    )
    gen_group.add_argument(
        "--columns",
        type=int,
        default=256,
        metavar="N",
        help="Image columns (default: 256)",
    )
    gen_group.add_argument(
        "--seed",
        type=int,
        metavar="N",
        help="Random seed for reproducible generation",
    )
    gen_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    # Malicious sample options
    mal_group = parser.add_argument_group("malicious sample options")
    mal_group.add_argument(
        "--depth",
        type=int,
        default=100,
        metavar="N",
        help="Nesting depth for parser stress tests (default: 100)",
    )
    mal_group.add_argument(
        "--base-dicom",
        type=str,
        metavar="FILE",
        help="Base DICOM file to use for sample generation (uses synthetic if not provided)",
    )

    # Scanning options
    scan_group = parser.add_argument_group("scanning options")
    scan_group.add_argument(
        "--json",
        action="store_true",
        help="Output scan results in JSON format",
    )
    scan_group.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan directories",
    )

    return parser


def run_generate(args: argparse.Namespace) -> int:
    """Generate synthetic DICOM files."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Synthetic Sample Generation")
    print("=" * 70)
    print(f"  Output:     {output_dir}")
    print(f"  Count:      {args.count}")
    print(f"  Modality:   {args.modality or 'random'}")
    print(f"  Image size: {args.rows}x{args.columns}")
    if args.series:
        print("  Mode:       Series (consistent UIDs)")
    if args.seed is not None:
        print(f"  Seed:       {args.seed}")
    print("=" * 70 + "\n")

    generator = SyntheticDicomGenerator(output_dir, seed=args.seed)

    try:
        if args.series:
            # Generate as a series
            modality = args.modality or "CT"
            files = generator.generate_series(
                count=args.count,
                modality=modality,
                rows=args.rows,
                columns=args.columns,
            )
        else:
            # Generate individual files
            files = generator.generate_batch(
                count=args.count,
                modality=args.modality,
                rows=args.rows,
                columns=args.columns,
            )

        print(f"[+] Generated {len(files)} synthetic DICOM files")

        if args.verbose:
            print("\nGenerated files:")
            for f in files[:10]:
                print(f"  - {f.name}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")

        print(f"\nOutput directory: {output_dir}")
        print("\nNote: All data is synthetic - no PHI concerns.")
        return 0

    except Exception as e:
        print(f"[ERROR] Generation failed: {e}")
        return 1


def run_list_sources(args: argparse.Namespace) -> int:
    """List public DICOM sample sources."""
    print("\n" + "=" * 70)
    print("  Public DICOM Sample Sources")
    print("=" * 70)
    print()

    for key, source in SAMPLE_SOURCES.items():
        print(f"  [{key}] {source['name']}")
        print(f"    URL: {source['url']}")
        print(f"    {source['description']}")
        print()

    print("=" * 70)
    print("\nNote: Most sources provide anonymized clinical data.")
    print("Always verify licensing and comply with data usage terms.")
    print("For fuzzing, synthetic data (--generate) avoids compliance concerns.")
    return 0


def run_malicious(args: argparse.Namespace) -> int:
    """Generate all categories of malicious samples."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Malicious Sample Generation")
    print("=" * 70)
    print(f"  Output: {output_dir}")
    print("  [!] WARNING: These samples are intentionally malicious!")
    print("  [!] Use only in controlled security testing environments.")
    print("=" * 70 + "\n")

    total_generated = 0
    errors: list[str] = []

    # Generate preamble attacks
    print("[i] Generating preamble attack samples...")
    try:
        from dicom_fuzzer.generators.preamble_attacks.generator import (
            PreambleAttackGenerator,
        )

        preamble_dir = output_dir / "preamble_attacks"
        preamble_dir.mkdir(parents=True, exist_ok=True)

        gen = PreambleAttackGenerator()
        pe_path = gen.create_pe_dicom(preamble_dir / "pe_dicom_polyglot.dcm")
        if pe_path:
            total_generated += 1
            if args.verbose:
                print(f"    [+] {pe_path.name}")

        elf_path = gen.create_elf_dicom(preamble_dir / "elf_dicom_polyglot.dcm")
        if elf_path:
            total_generated += 1
            if args.verbose:
                print(f"    [+] {elf_path.name}")

        print("    [+] Preamble attacks: 2 samples")
    except Exception as e:
        errors.append(f"Preamble attacks: {e}")
        print(f"    [-] Failed: {e}")

    # Generate CVE samples
    print("[i] Generating CVE reproduction samples...")
    try:
        from dicom_fuzzer.generators.cve_reproductions.generator import (
            CVESampleGenerator,
        )

        cve_dir = output_dir / "cve_reproductions"
        cve_gen = CVESampleGenerator(cve_dir)
        cve_results = cve_gen.generate_all()
        cve_count = sum(1 for p in cve_results.values() if p is not None)
        total_generated += cve_count

        if args.verbose:
            for cve_id, cve_path in cve_results.items():
                if cve_path:
                    print(f"    [+] {cve_id}: {cve_path.name}")

        print(f"    [+] CVE reproductions: {cve_count} samples")
    except Exception as e:
        errors.append(f"CVE samples: {e}")
        print(f"    [-] Failed: {e}")

    # Generate parser stress samples
    print("[i] Generating parser stress samples...")
    try:
        from dicom_fuzzer.generators.parser_stress.generator import (
            ParserStressGenerator,
        )

        stress_dir = output_dir / "parser_stress"
        stress_gen = ParserStressGenerator(stress_dir)
        stress_results = stress_gen.generate_all()
        stress_count = sum(1 for p in stress_results.values() if p is not None)
        total_generated += stress_count

        if args.verbose:
            for name, stress_path in stress_results.items():
                if stress_path:
                    print(f"    [+] {name}: {stress_path.name}")

        print(f"    [+] Parser stress: {stress_count} samples")
    except Exception as e:
        errors.append(f"Parser stress: {e}")
        print(f"    [-] Failed: {e}")

    # Generate compliance violation samples
    print("[i] Generating compliance violation samples...")
    try:
        from dicom_fuzzer.generators.compliance_violations.generator import (
            ComplianceViolationGenerator,
        )

        compliance_dir = output_dir / "compliance_violations"
        compliance_gen = ComplianceViolationGenerator(compliance_dir)
        compliance_results = compliance_gen.generate_all()
        # compliance_results is dict[str, dict[str, Path]] - nested structure
        compliance_count = sum(len(samples) for samples in compliance_results.values())
        total_generated += compliance_count

        if args.verbose:
            for category, samples in compliance_results.items():
                for sample_name, sample_path in samples.items():
                    print(f"    [+] {category}/{sample_name}: {sample_path.name}")

        print(f"    [+] Compliance violations: {compliance_count} samples")
    except Exception as e:
        errors.append(f"Compliance violations: {e}")
        print(f"    [-] Failed: {e}")

    # Summary
    print("\n" + "=" * 70)
    print("  Generation Complete")
    print("=" * 70)
    print(f"  [+] Total samples generated: {total_generated}")
    if errors:
        print(f"  [-] Errors: {len(errors)}")
        for err in errors:
            print(f"      - {err}")
    print(f"  Output: {output_dir}")
    print("=" * 70 + "\n")

    return 0 if not errors else 1


def run_preamble_attacks(args: argparse.Namespace) -> int:
    """Generate preamble attack samples (polyglots)."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  Preamble Attack Sample Generation")
    print("=" * 70)
    print(f"  Output: {output_dir}")
    print("  [!] WARNING: These are executable polyglot files!")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.generators.preamble_attacks.generator import (
            PreambleAttackGenerator,
        )

        gen = PreambleAttackGenerator()
        generated = []

        pe_path = gen.create_pe_dicom(output_dir / "pe_dicom_polyglot.dcm")
        if pe_path:
            generated.append(pe_path)
            print(f"  [+] PE/DICOM polyglot: {pe_path.name}")

        elf_path = gen.create_elf_dicom(output_dir / "elf_dicom_polyglot.dcm")
        if elf_path:
            generated.append(elf_path)
            print(f"  [+] ELF/DICOM polyglot: {elf_path.name}")

        print(f"\n[+] Generated {len(generated)} polyglot samples")
        print(f"Output: {output_dir}")
        return 0

    except Exception as e:
        print(f"[-] Failed: {e}")
        return 1


def run_cve_samples(args: argparse.Namespace) -> int:
    """Generate CVE reproduction samples."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  CVE Reproduction Sample Generation")
    print("=" * 70)
    print(f"  Output: {output_dir}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.generators.cve_reproductions.generator import (
            CVESampleGenerator,
        )

        gen = CVESampleGenerator(output_dir)
        results = gen.generate_all()

        for cve_id, path in results.items():
            if path:
                print(f"  [+] {cve_id}: {path.name}")
            else:
                print(f"  [-] {cve_id}: Failed to generate")

        success_count = sum(1 for p in results.values() if p is not None)
        print(f"\n[+] Generated {success_count}/{len(results)} CVE samples")
        print(f"Output: {output_dir}")
        return 0

    except Exception as e:
        print(f"[-] Failed: {e}")
        return 1


def run_parser_stress(args: argparse.Namespace) -> int:
    """Generate parser stress test samples."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  Parser Stress Sample Generation")
    print("=" * 70)
    print(f"  Output: {output_dir}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.generators.parser_stress.generator import (
            ParserStressGenerator,
        )

        gen = ParserStressGenerator(output_dir)
        results = gen.generate_all()

        for name, path in results.items():
            if path:
                print(f"  [+] {name}: {path.name}")
            else:
                print(f"  [-] {name}: Failed to generate")

        success_count = sum(1 for p in results.values() if p is not None)
        print(f"\n[+] Generated {success_count}/{len(results)} stress samples")
        print(f"Output: {output_dir}")
        return 0

    except Exception as e:
        print(f"[-] Failed: {e}")
        return 1


def run_compliance(args: argparse.Namespace) -> int:
    """Generate compliance violation samples."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  Compliance Violation Sample Generation")
    print("=" * 70)
    print(f"  Output: {output_dir}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.generators.compliance_violations.generator import (
            ComplianceViolationGenerator,
        )

        compliance_gen = ComplianceViolationGenerator(output_dir)
        compliance_results = compliance_gen.generate_all()
        # compliance_results is dict[str, dict[str, Path]] - nested structure
        total_samples = 0
        for category, samples in compliance_results.items():
            print(f"  [{category}]")
            for sample_name, sample_path in samples.items():
                print(f"    [+] {sample_name}: {sample_path.name}")
                total_samples += 1

        print(
            f"\n[+] Generated {total_samples} compliance samples in {len(compliance_results)} categories"
        )
        print(f"Output: {output_dir}")
        return 0

    except Exception as e:
        print(f"[-] Failed: {e}")
        return 1


def run_scan(args: argparse.Namespace) -> int:
    """Scan DICOM files for security issues."""
    import json as json_module

    scan_path = Path(args.scan)

    if not scan_path.exists():
        print(f"[-] Path not found: {scan_path}")
        return 1

    print("\n" + "=" * 70)
    print("  DICOM Security Scanner")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.generators.detection.scanner import (
            DicomSecurityScanner,
            ScanResult,
        )

        scanner = DicomSecurityScanner()
        results: list[ScanResult] = []

        if scan_path.is_file():
            result = scanner.scan_file(scan_path)
            results.append(result)
        else:
            # Scan directory
            pattern = "**/*.dcm" if args.recursive else "*.dcm"
            for dicom_file in scan_path.glob(pattern):
                if dicom_file.is_file():
                    result = scanner.scan_file(dicom_file)
                    results.append(result)

        # Output results
        if args.json:
            output = [
                {
                    "file": str(r.path),
                    "findings": [
                        {
                            "category": f.category,
                            "severity": f.severity.value,
                            "description": f.description,
                        }
                        for f in r.findings
                    ],
                    "is_clean": r.is_clean,
                }
                for r in results
            ]
            print(json_module.dumps(output, indent=2))
        else:
            for result in results:
                if result.is_clean:
                    print(f"  [+] {result.path.name}: Clean")
                else:
                    print(
                        f"  [!] {result.path.name}: {len(result.findings)} finding(s)"
                    )
                    for finding in result.findings:
                        print(
                            f"      - [{finding.severity.value}] {finding.category}: {finding.description}"
                        )

            # Summary
            clean_count = sum(1 for r in results if r.is_clean)
            print(
                f"\n[i] Scanned {len(results)} files: {clean_count} clean, {len(results) - clean_count} with findings"
            )

        return 0

    except Exception as e:
        print(f"[-] Scan failed: {e}")
        return 1


def run_sanitize(args: argparse.Namespace) -> int:
    """Sanitize DICOM file preamble."""
    sanitize_path = Path(args.sanitize)

    if not sanitize_path.exists():
        print(f"[-] File not found: {sanitize_path}")
        return 1

    if not sanitize_path.is_file():
        print("[-] Sanitize requires a single file path")
        return 1

    print("\n" + "=" * 70)
    print("  DICOM Preamble Sanitizer")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.generators.detection.sanitizer import (
            DicomSanitizer,
            SanitizeAction,
        )

        sanitizer = DicomSanitizer()
        output_path = (
            sanitize_path.parent
            / f"{sanitize_path.stem}_sanitized{sanitize_path.suffix}"
        )

        result = sanitizer.sanitize_file(sanitize_path, output_path)

        if result.action == SanitizeAction.CLEARED:
            print(f"  [+] Sanitized: {sanitize_path.name}")
            print(f"  [i] Original preamble type: {result.original_preamble_type}")
            print(f"  [i] Output: {output_path}")
        elif result.action == SanitizeAction.SKIPPED:
            print(f"  [i] No sanitization needed: {sanitize_path.name}")
            print(f"  [i] Preamble was already safe: {result.original_preamble_type}")
        else:
            print(f"  [-] {result.message}")

        return 0

    except Exception as e:
        print(f"[-] Sanitization failed: {e}")
        return 1


def run_strip_pixel_data(args: argparse.Namespace) -> int:
    """Strip PixelData from DICOM files for corpus optimization."""
    input_path = Path(args.strip_pixel_data)

    if not input_path.exists():
        print(f"[-] Path not found: {input_path}")
        return 1

    print("\n" + "=" * 70)
    print("  DICOM Corpus Optimizer - Strip PixelData")
    print("=" * 70)
    print(f"  Input:  {input_path}")
    print(f"  Output: {args.output}")
    print("  [i] Stripping PixelData, OverlayData, WaveformData")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.utils.corpus_minimization import (
            optimize_corpus,
            strip_pixel_data,
        )

        output_dir = Path(args.output)

        if input_path.is_file():
            # Single file
            output_file = output_dir / input_path.name
            output_dir.mkdir(parents=True, exist_ok=True)

            success, bytes_saved = strip_pixel_data(input_path, output_file)
            if success:
                original_size = input_path.stat().st_size
                new_size = output_file.stat().st_size
                reduction = (
                    100 * bytes_saved / original_size if original_size > 0 else 0
                )
                print(f"  [+] {input_path.name}")
                print(f"      Original: {original_size / 1024:.1f} KB")
                print(f"      Stripped: {new_size / 1024:.1f} KB")
                print(f"      Saved:    {bytes_saved / 1024:.1f} KB ({reduction:.1f}%)")
            else:
                print(f"  [-] Failed to process: {input_path.name}")
                return 1
        else:
            # Directory
            stats = optimize_corpus(
                corpus_dir=input_path,
                output_dir=output_dir,
                strip_pixels=True,
                strip_overlays=True,
                strip_waveforms=True,
                dry_run=False,
            )

            print(f"  [+] Files processed:   {stats['files_processed']}")
            print(f"  [+] Files optimized:   {stats['files_optimized']}")
            print(f"  [-] Files skipped:     {stats['files_skipped']}")
            print(f"  Original size:         {stats['original_size_mb']:.2f} MB")
            print(f"  Optimized size:        {stats['optimized_size_mb']:.2f} MB")
            print(
                f"  Space saved:           {stats['bytes_saved'] / (1024 * 1024):.2f} MB"
            )
            print(f"  Reduction:             {stats['reduction_percent']:.1f}%")

        print(f"\n[+] Output: {output_dir}")
        print("\n[i] Optimized corpus is ready for faster fuzzing.")
        print("    Use with AFL++/libFuzzer for improved throughput.")
        return 0

    except Exception as e:
        print(f"[-] Optimization failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for samples subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.generate:
        return run_generate(args)
    elif args.list_sources:
        return run_list_sources(args)
    elif args.malicious:
        return run_malicious(args)
    elif args.preamble_attacks:
        return run_preamble_attacks(args)
    elif args.cve_samples:
        return run_cve_samples(args)
    elif args.parser_stress:
        return run_parser_stress(args)
    elif args.compliance:
        return run_compliance(args)
    elif args.scan:
        return run_scan(args)
    elif args.sanitize:
        return run_sanitize(args)
    elif args.strip_pixel_data:
        return run_strip_pixel_data(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
