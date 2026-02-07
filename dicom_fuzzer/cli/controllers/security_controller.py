"""Security Fuzzing Controller for DICOM Fuzzer CLI.

DEPRECATED: CVE replication has been moved to the 'cve' subcommand.
Use: dicom-fuzzer cve --help

CVE replication is NOT fuzzing - it produces deterministic output for
validating whether a DICOM parser is vulnerable to known CVEs.
"""

from __future__ import annotations

import logging
from argparse import Namespace
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityFuzzingController:
    """Controller for CVE-based security testing.

    DEPRECATED: Use the 'cve' subcommand instead:
        dicom-fuzzer cve --help
    """

    @staticmethod
    def is_available() -> bool:
        """Check if security testing is available.

        Always returns True since we redirect to the cve subcommand.
        """
        return True

    @staticmethod
    def run(
        args: Namespace,
        input_file: Path,
        output_dir: Path,
        num_files: int = 100,
    ) -> int:
        """Run security testing campaign.

        DEPRECATED: Redirects to the 'cve' subcommand.

        Args:
            args: Parsed command-line arguments
            input_file: Input DICOM file to use as base
            output_dir: Output directory
            num_files: Ignored (CVE generation is deterministic)

        Returns:
            Exit code (0 for success, 1 for failure)

        """
        print("\n" + "=" * 70)
        print("  NOTICE: --security-fuzz is deprecated")
        print("=" * 70)
        print()
        print("  CVE replication has moved to a dedicated subcommand.")
        print("  CVE files are generated deterministically, not through fuzzing.")
        print()
        print("  Use the new 'cve' subcommand instead:")
        print()
        print(f"    dicom-fuzzer cve --all -t {input_file} -o {output_dir}")
        print()
        print("  Or for a specific CVE:")
        print()
        print(
            f"    dicom-fuzzer cve --cve CVE-2025-5943 -t {input_file} -o {output_dir}"
        )
        print()
        print("  List available CVEs:")
        print()
        print("    dicom-fuzzer cve --list")
        print()
        print("=" * 70 + "\n")

        # Still generate files for backward compatibility
        try:
            from dicom_fuzzer.cve import CVEGenerator

            generator = CVEGenerator()
            template_bytes = input_file.read_bytes()

            # Generate all CVE files
            security_output = output_dir / "cve_files"
            saved_paths = generator.save_all(template_bytes, security_output)

            print(f"  Generated {len(saved_paths)} CVE replication files")
            print(f"  Output directory: {security_output}")
            print()

            return 0

        except Exception as e:
            logger.error(
                f"CVE generation failed: {e}", exc_info=getattr(args, "verbose", False)
            )
            print(f"\n[ERROR] CVE generation failed: {e}")
            return 1
