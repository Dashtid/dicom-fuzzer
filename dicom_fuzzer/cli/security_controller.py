"""Security Fuzzing Controller for DICOM Fuzzer CLI.

Handles CVE-based exploit pattern security testing.
"""

from __future__ import annotations

import json
import logging
from argparse import Namespace
from pathlib import Path

logger = logging.getLogger(__name__)

# Check for security fuzzer availability
try:
    from dicom_fuzzer.strategies.exploit import (
        CVE_MUTATIONS,
        CVECategory,
        ExploitPatternApplicator,
        get_available_cves,
        get_mutations_by_category,
        apply_cve_mutation,
    )

    HAS_SECURITY_FUZZER = True
except ImportError:
    HAS_SECURITY_FUZZER = False


class SecurityFuzzingController:
    """Controller for CVE-based security fuzzing."""

    @staticmethod
    def is_available() -> bool:
        """Check if security fuzzing module is available."""
        return HAS_SECURITY_FUZZER

    @staticmethod
    def run(
        args: Namespace,
        input_file: Path,
        output_dir: Path,
        num_files: int = 100,
    ) -> int:
        """Run security fuzzing campaign.

        Args:
            args: Parsed command-line arguments
            input_file: Input DICOM file to use as base
            output_dir: Output directory for fuzzed files
            num_files: Maximum number of files to generate

        Returns:
            Exit code (0 for success, 1 for failure)

        """
        if not HAS_SECURITY_FUZZER:
            print("[ERROR] Security fuzzing module not available.")
            print(
                "Please check that dicom_fuzzer.strategies.exploit is installed."
            )
            return 1

        print("\n" + "=" * 70)
        print("  CVE-Based Security Fuzzing")
        print("=" * 70)

        try:
            import pydicom

            # Load the input DICOM file
            ds = pydicom.dcmread(str(input_file))

            # Create exploit pattern applicator
            applicator = ExploitPatternApplicator()

            # Print available CVEs
            available_cves = get_available_cves()
            print(f"  Available CVE patterns: {len(available_cves)}")
            for cve in sorted(available_cves)[:10]:
                print(f"    - {cve}")
            if len(available_cves) > 10:
                print(f"    ... and {len(available_cves) - 10} more")

            # Apply exploit patterns
            mutated_ds = applicator.apply_exploit_patterns(ds)
            patterns_applied = applicator.get_patterns_applied()

            print(f"\n  Patterns applied: {len(patterns_applied)}")
            for pattern in patterns_applied:
                print(f"    [+] {pattern}")

            # Save report if specified
            SecurityFuzzingController._save_report(args, patterns_applied)

            # Save fuzzed files if output specified
            if getattr(args, "target", None):
                SecurityFuzzingController._save_fuzzed_files(
                    input_file=input_file,
                    output_dir=output_dir,
                    num_files=min(num_files, len(CVE_MUTATIONS)),
                )

            print("=" * 70 + "\n")
            return 0

        except Exception as e:
            logger.error(f"Security fuzzing failed: {e}", exc_info=args.verbose)
            print(f"\n[ERROR] Security fuzzing failed: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()
            return 1

    @staticmethod
    def _save_report(args: Namespace, patterns_applied: list[str]) -> None:
        """Save security report if specified.

        Args:
            args: Parsed command-line arguments
            patterns_applied: List of applied pattern names

        """
        report_path_str = getattr(args, "security_report", None)
        if report_path_str:
            report = {
                "total_patterns": len(patterns_applied),
                "patterns_applied": patterns_applied,
                "available_cves": get_available_cves(),
                "mutations_by_category": {
                    cat.value: len(get_mutations_by_category(cat))
                    for cat in CVECategory
                },
            }
            report_path = Path(report_path_str)
            with open(report_path, "w") as report_file:
                json.dump(report, report_file, indent=2)
            print(f"  Report saved to: {report_path}")

    @staticmethod
    def _save_fuzzed_files(
        input_file: Path,
        output_dir: Path,
        num_files: int,
    ) -> None:
        """Generate and save fuzzed files with different CVE patterns.

        Args:
            input_file: Source DICOM file
            output_dir: Output directory
            num_files: Number of files to generate

        """
        import pydicom

        print(f"\n  Generating {num_files} security-fuzzed files...")
        security_output = output_dir / "security_fuzzed"
        security_output.mkdir(parents=True, exist_ok=True)

        cve_ids = get_available_cves()[:num_files]
        files_saved = 0

        for i, cve_id in enumerate(cve_ids):
            try:
                ds = pydicom.dcmread(str(input_file))
                mutated_ds = apply_cve_mutation(ds, cve_id)
                if mutated_ds:
                    safe_cve = cve_id.replace("-", "_").replace(".", "_")
                    output_file = security_output / f"security_{i:04d}_{safe_cve}.dcm"
                    mutated_ds.save_as(str(output_file))
                    files_saved += 1
            except Exception as e:
                logger.debug(f"Failed to apply CVE {cve_id}: {e}")

        print(f"  Security-fuzzed files saved to: {security_output}")
        print(f"  Files generated: {files_saved}/{num_files}")
