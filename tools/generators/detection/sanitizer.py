#!/usr/bin/env python3
"""DICOM Preamble Sanitizer

Neutralizes polyglot attacks (PE/DICOM, ELF/DICOM) by clearing
the DICOM preamble, removing any executable content while
preserving the medical image data.

This tool addresses CVE-2019-11687.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class SanitizeAction(Enum):
    """Actions taken during sanitization."""

    CLEARED = "cleared"  # Preamble was cleared
    SKIPPED = "skipped"  # File was already safe
    FAILED = "failed"  # Sanitization failed
    NOT_DICOM = "not_dicom"  # Not a valid DICOM file


@dataclass
class SanitizeResult:
    """Result of sanitizing a DICOM file."""

    input_path: Path
    output_path: Path | None
    action: SanitizeAction
    original_preamble_type: str
    message: str


class DicomSanitizer:
    """Sanitizes DICOM files by clearing potentially malicious preambles.

    The DICOM preamble (first 128 bytes) can contain executable content
    that turns the file into a polyglot (PE/DICOM, ELF/DICOM).
    This tool removes that content while preserving the DICOM data.
    """

    # Executable signatures
    EXEC_SIGNATURES = {
        b"MZ": "PE (Windows)",
        b"\x7fELF": "ELF (Linux)",
        b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
        b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
        b"\xce\xfa\xed\xfe": "Mach-O 32-bit (reversed)",
        b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (reversed)",
    }

    DICM_MAGIC = b"DICM"

    def __init__(self, backup: bool = True) -> None:
        """Initialize sanitizer.

        Args:
            backup: Whether to create backup files before sanitizing in-place

        """
        self.backup = backup

    def detect_preamble_type(self, preamble: bytes) -> str:
        """Detect the type of content in the preamble.

        Args:
            preamble: 128-byte preamble

        Returns:
            Description of preamble content type

        """
        # Check for executables
        for sig, name in self.EXEC_SIGNATURES.items():
            if preamble[: len(sig)] == sig:
                return name

        # Check for null preamble
        if preamble == b"\x00" * 128:
            return "Safe (null bytes)"

        # Check for TIFF
        if preamble[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
            return "Safe (TIFF header)"

        # Check for mostly null
        non_null = sum(1 for b in preamble if b != 0)
        if non_null < 10:
            return "Safe (mostly null)"

        return "Unknown content"

    def is_preamble_safe(self, preamble: bytes) -> bool:
        """Check if preamble is safe (not executable).

        Args:
            preamble: 128-byte preamble

        Returns:
            True if preamble is safe

        """
        preamble_type = self.detect_preamble_type(preamble)
        return preamble_type.startswith("Safe")

    def sanitize_file(
        self,
        input_path: str | Path,
        output_path: str | Path | None = None,
        force: bool = False,
    ) -> SanitizeResult:
        """Sanitize a DICOM file by clearing its preamble.

        Args:
            input_path: Path to input DICOM file
            output_path: Path for sanitized output (None = in-place)
            force: Sanitize even if preamble appears safe

        Returns:
            SanitizeResult describing the action taken

        """
        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path
            in_place = True
        else:
            output_path = Path(output_path)
            in_place = False

        # Read file
        try:
            with open(input_path, "rb") as f:
                content = f.read()
        except OSError as e:
            return SanitizeResult(
                input_path=input_path,
                output_path=None,
                action=SanitizeAction.FAILED,
                original_preamble_type="Unknown",
                message=f"Failed to read file: {e}",
            )

        # Validate DICOM
        if len(content) < 132:
            return SanitizeResult(
                input_path=input_path,
                output_path=None,
                action=SanitizeAction.NOT_DICOM,
                original_preamble_type="N/A",
                message="File too small to be valid DICOM",
            )

        preamble = content[:128]
        magic = content[128:132]

        if magic != self.DICM_MAGIC:
            return SanitizeResult(
                input_path=input_path,
                output_path=None,
                action=SanitizeAction.NOT_DICOM,
                original_preamble_type=self.detect_preamble_type(preamble),
                message="File does not have DICM magic (not Part 10 DICOM)",
            )

        preamble_type = self.detect_preamble_type(preamble)

        # Check if sanitization needed
        if not force and self.is_preamble_safe(preamble):
            return SanitizeResult(
                input_path=input_path,
                output_path=output_path if not in_place else None,
                action=SanitizeAction.SKIPPED,
                original_preamble_type=preamble_type,
                message="Preamble is already safe, no changes made",
            )

        # Create backup if in-place
        if in_place and self.backup:
            backup_path = input_path.with_suffix(input_path.suffix + ".bak")
            try:
                shutil.copy2(input_path, backup_path)
            except OSError as e:
                return SanitizeResult(
                    input_path=input_path,
                    output_path=None,
                    action=SanitizeAction.FAILED,
                    original_preamble_type=preamble_type,
                    message=f"Failed to create backup: {e}",
                )

        # Sanitize: replace preamble with null bytes
        sanitized_content = b"\x00" * 128 + content[128:]

        # Write output
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(sanitized_content)
        except OSError as e:
            return SanitizeResult(
                input_path=input_path,
                output_path=None,
                action=SanitizeAction.FAILED,
                original_preamble_type=preamble_type,
                message=f"Failed to write output: {e}",
            )

        return SanitizeResult(
            input_path=input_path,
            output_path=output_path,
            action=SanitizeAction.CLEARED,
            original_preamble_type=preamble_type,
            message=f"Preamble cleared (was: {preamble_type})",
        )

    def sanitize_directory(
        self,
        directory: str | Path,
        output_dir: str | Path | None = None,
        recursive: bool = True,
        force: bool = False,
    ) -> list[SanitizeResult]:
        """Sanitize all DICOM files in a directory.

        Args:
            directory: Input directory
            output_dir: Output directory (None = in-place)
            recursive: Process subdirectories
            force: Sanitize even if preamble appears safe

        Returns:
            List of SanitizeResults

        """
        directory = Path(directory)
        results = []

        pattern = "**/*" if recursive else "*"
        extensions = (".dcm", ".dicom", ".DCM", ".DICOM")

        for ext in extensions:
            for input_path in directory.glob(f"{pattern}{ext}"):
                if not input_path.is_file():
                    continue

                if output_dir:
                    # Preserve directory structure
                    rel_path = input_path.relative_to(directory)
                    output_path = Path(output_dir) / rel_path
                else:
                    output_path = None

                result = self.sanitize_file(input_path, output_path, force)
                results.append(result)

        return results


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sanitize DICOM files by clearing preambles"
    )
    parser.add_argument(
        "input",
        help="Input file or directory",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file or directory (default: in-place)",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Process directories recursively",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Sanitize even if preamble appears safe",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backup files for in-place sanitization",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only show errors and warnings",
    )

    args = parser.parse_args()

    sanitizer = DicomSanitizer(backup=not args.no_backup)
    input_path = Path(args.input)

    if input_path.is_file():
        results = [sanitizer.sanitize_file(input_path, args.output, args.force)]
    else:
        results = sanitizer.sanitize_directory(
            input_path, args.output, args.recursive, args.force
        )

    # Print results
    cleared = sum(1 for r in results if r.action == SanitizeAction.CLEARED)
    skipped = sum(1 for r in results if r.action == SanitizeAction.SKIPPED)
    failed = sum(1 for r in results if r.action == SanitizeAction.FAILED)
    not_dicom = sum(1 for r in results if r.action == SanitizeAction.NOT_DICOM)

    for r in results:
        if args.quiet and r.action == SanitizeAction.SKIPPED:
            continue

        status_map = {
            SanitizeAction.CLEARED: "[+] CLEARED",
            SanitizeAction.SKIPPED: "[=] SKIPPED",
            SanitizeAction.FAILED: "[-] FAILED",
            SanitizeAction.NOT_DICOM: "[?] NOT_DICOM",
        }

        print(f"{status_map[r.action]} {r.input_path}")
        if not args.quiet:
            print(f"    Original: {r.original_preamble_type}")
            print(f"    {r.message}")
            if r.output_path and r.output_path != r.input_path:
                print(f"    Output: {r.output_path}")

    print(
        f"\nSummary: {cleared} cleared, {skipped} skipped, {failed} failed, {not_dicom} not DICOM"
    )


if __name__ == "__main__":
    main()
