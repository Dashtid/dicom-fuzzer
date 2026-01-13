"""Security Fuzzing Controller for DICOM Fuzzer CLI.

Handles medical device security vulnerability testing.
"""

from __future__ import annotations

import json
import logging
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dicom_fuzzer.strategies.medical_device_security import SecurityMutation

logger = logging.getLogger(__name__)

# Check for security fuzzer availability
try:
    from dicom_fuzzer.strategies.medical_device_security import (
        CVEPattern,
        MedicalDeviceSecurityConfig,
        MedicalDeviceSecurityFuzzer,
        VulnerabilityClass,
    )

    HAS_SECURITY_FUZZER = True
except ImportError:
    HAS_SECURITY_FUZZER = False
    CVEPattern = None  # type: ignore[misc, assignment]
    VulnerabilityClass = None  # type: ignore[misc, assignment]


# CVE name to enum mapping
CVE_MAP: dict[str, CVEPattern] = {}
if HAS_SECURITY_FUZZER and CVEPattern is not None:
    CVE_MAP = {
        "CVE-2025-35975": CVEPattern.CVE_2025_35975,
        "CVE-2025-36521": CVEPattern.CVE_2025_36521,
        "CVE-2025-5943": CVEPattern.CVE_2025_5943,
        "CVE-2025-1001": CVEPattern.CVE_2025_1001,
        "CVE-2022-2119": CVEPattern.CVE_2022_2119,
        "CVE-2022-2120": CVEPattern.CVE_2022_2120,
    }

# Vulnerability class name to enum mapping
VULN_MAP: dict[str, VulnerabilityClass] = {}
if HAS_SECURITY_FUZZER and VulnerabilityClass is not None:
    VULN_MAP = {
        "oob_write": VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
        "oob_read": VulnerabilityClass.OUT_OF_BOUNDS_READ,
        "stack_overflow": VulnerabilityClass.STACK_BUFFER_OVERFLOW,
        "heap_overflow": VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        "integer_overflow": VulnerabilityClass.INTEGER_OVERFLOW,
        "format_string": VulnerabilityClass.FORMAT_STRING,
        "null_deref": VulnerabilityClass.NULL_POINTER_DEREF,
        "dos": VulnerabilityClass.DENIAL_OF_SERVICE,
    }


class SecurityFuzzingController:
    """Controller for medical device security fuzzing."""

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
                "Please check that dicom_fuzzer.strategies.medical_device_security is installed."
            )
            return 1

        print("\n" + "=" * 70)
        print("  Medical Device Security Fuzzing")
        print("=" * 70)

        try:
            import pydicom

            # Load the input DICOM file
            ds = pydicom.dcmread(str(input_file))

            # Parse CVE targets
            target_cves = SecurityFuzzingController._parse_cves(
                getattr(args, "target_cves", None)
            )

            # Parse vulnerability classes
            target_vulns = SecurityFuzzingController._parse_vuln_classes(
                getattr(args, "vuln_classes", None)
            )

            # Create security fuzzer config
            security_config = MedicalDeviceSecurityConfig(
                target_cves=target_cves if target_cves else list(CVEPattern),
                target_vulns=target_vulns if target_vulns else list(VulnerabilityClass),
            )
            security_fuzzer = MedicalDeviceSecurityFuzzer(security_config)

            # Generate security mutations
            mutations = security_fuzzer.generate_mutations(ds)
            print(f"  Mutations generated: {len(mutations)}")

            # Print summary
            security_fuzzer.print_summary()

            # Save report if specified
            SecurityFuzzingController._save_report(args, security_fuzzer)

            # Apply mutations and save fuzzed files
            if mutations and getattr(args, "target", None):
                SecurityFuzzingController._apply_mutations(
                    input_file=input_file,
                    output_dir=output_dir,
                    mutations=mutations[:num_files],
                    security_fuzzer=security_fuzzer,
                )

            return 0

        except Exception as e:
            logger.error(f"Security fuzzing failed: {e}", exc_info=args.verbose)
            print(f"\n[ERROR] Security fuzzing failed: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()
            return 1

    @staticmethod
    def _parse_cves(cve_str: str | None) -> list[CVEPattern] | None:
        """Parse CVE target string into enum list.

        Args:
            cve_str: Comma-separated CVE identifiers

        Returns:
            List of CVEPattern enums or None

        """
        if not cve_str:
            return None

        target_cves = []
        for cve in cve_str.split(","):
            cve = cve.strip().upper()
            if cve in CVE_MAP:
                target_cves.append(CVE_MAP[cve])
            else:
                print(f"  [!] Unknown CVE: {cve}")

        return target_cves if target_cves else None

    @staticmethod
    def _parse_vuln_classes(vuln_str: str | None) -> list[VulnerabilityClass] | None:
        """Parse vulnerability class string into enum list.

        Args:
            vuln_str: Comma-separated vulnerability class names

        Returns:
            List of VulnerabilityClass enums or None

        """
        if not vuln_str:
            return None

        target_vulns = []
        for vuln in vuln_str.split(","):
            vuln = vuln.strip().lower()
            if vuln in VULN_MAP:
                target_vulns.append(VULN_MAP[vuln])
            else:
                print(f"  [!] Unknown vulnerability class: {vuln}")

        return target_vulns if target_vulns else None

    @staticmethod
    def _save_report(
        args: Namespace, security_fuzzer: MedicalDeviceSecurityFuzzer
    ) -> None:
        """Save security report if specified.

        Args:
            args: Parsed command-line arguments
            security_fuzzer: The security fuzzer instance

        """
        report_path_str = getattr(args, "security_report", None)
        if report_path_str:
            summary = security_fuzzer.get_summary()
            report_path = Path(report_path_str)
            with open(report_path, "w") as report_file:
                json.dump(summary, report_file, indent=2)
            print(f"  Report saved to: {report_path}")

    @staticmethod
    def _apply_mutations(
        input_file: Path,
        output_dir: Path,
        mutations: list[SecurityMutation],
        security_fuzzer: MedicalDeviceSecurityFuzzer,
    ) -> None:
        """Apply mutations and save fuzzed files.

        Args:
            input_file: Source DICOM file
            output_dir: Output directory
            mutations: List of mutations to apply
            security_fuzzer: The security fuzzer instance

        """
        import pydicom

        print(f"\n  Applying {len(mutations)} security mutations...")
        security_output = output_dir / "security_fuzzed"
        security_output.mkdir(parents=True, exist_ok=True)

        for i, mutation in enumerate(mutations):
            try:
                ds_copy = pydicom.dcmread(str(input_file))
                mutated_ds = security_fuzzer.apply_mutation(ds_copy, mutation)
                output_file = security_output / f"security_{i:04d}_{mutation.name}.dcm"
                mutated_ds.save_as(str(output_file))
            except Exception as e:
                logger.debug(f"Failed to apply mutation {mutation.name}: {e}")

        print(f"  Security-fuzzed files saved to: {security_output}")
