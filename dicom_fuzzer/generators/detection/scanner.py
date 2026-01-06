#!/usr/bin/env python3
"""DICOM Security Scanner

Scans DICOM files for security issues including:
- Polyglot attacks (PE/DICOM, ELF/DICOM)
- Suspicious preamble content
- Known malicious patterns
- Compliance violations that may indicate tampering
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A security finding from scanning a DICOM file."""

    severity: Severity
    category: str
    description: str
    offset: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result of scanning a DICOM file."""

    path: Path
    is_dicom: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def is_clean(self) -> bool:
        """Check if no high-severity findings."""
        return not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )

    @property
    def max_severity(self) -> Severity | None:
        """Get the highest severity finding."""
        if not self.findings:
            return None
        severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for sev in severities:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None


class DicomSecurityScanner:
    """Security scanner for DICOM files.

    Detects polyglot attacks, suspicious content, and compliance issues.
    """

    # Executable magic bytes
    PE_MAGIC = b"MZ"
    ELF_MAGIC = b"\x7fELF"
    MACHO_32 = b"\xfe\xed\xfa\xce"
    MACHO_64 = b"\xfe\xed\xfa\xcf"
    MACHO_32_REV = b"\xce\xfa\xed\xfe"
    MACHO_64_REV = b"\xcf\xfa\xed\xfe"

    # DICOM magic
    DICM_MAGIC = b"DICM"

    # Suspicious strings in preamble
    SUSPICIOUS_STRINGS = [
        b"cmd.exe",
        b"powershell",
        b"/bin/bash",
        b"/bin/sh",
        b"wget ",
        b"curl ",
        b"http://",
        b"https://",
        b"<script",
        b"eval(",
    ]

    # Safe preamble patterns
    SAFE_PREAMBLE_PATTERNS = [
        b"\x00" * 128,  # Null bytes
        b"II\x2a\x00",  # TIFF little-endian
        b"MM\x00\x2a",  # TIFF big-endian
    ]

    def scan_file(self, path: str | Path) -> ScanResult:
        """Scan a single DICOM file for security issues.

        Args:
            path: Path to the DICOM file

        Returns:
            ScanResult with findings

        """
        path = Path(path)
        result = ScanResult(path=path, is_dicom=False)

        if not path.exists():
            result.error = f"File not found: {path}"
            return result

        try:
            with open(path, "rb") as f:
                # Read preamble and magic
                preamble = f.read(128)
                if len(preamble) < 128:
                    result.error = "File too small for DICOM preamble"
                    return result

                magic = f.read(4)
                if magic == self.DICM_MAGIC:
                    result.is_dicom = True

                # Read more for deeper analysis
                f.seek(0)
                header_data = f.read(1024)

        except OSError as e:
            result.error = f"Error reading file: {e}"
            return result

        # Run all checks
        self._check_executable_preamble(preamble, magic, result)
        self._check_suspicious_strings(preamble, result)
        self._check_shellcode_patterns(preamble, result)
        self._check_preamble_safety(preamble, result)

        if result.is_dicom:
            self._check_dicom_structure(header_data, result)

        return result

    def _check_executable_preamble(
        self, preamble: bytes, magic: bytes, result: ScanResult
    ) -> None:
        """Check for executable headers in preamble."""
        is_dicm = magic == self.DICM_MAGIC

        # PE check
        if preamble[:2] == self.PE_MAGIC:
            result.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="polyglot",
                    description="PE (Windows) executable header in DICOM preamble",
                    offset=0,
                    details={
                        "type": "PE/DICOM polyglot",
                        "cve": "CVE-2019-11687",
                        "is_valid_dicom": is_dicm,
                    },
                )
            )

            # Check for PE signature
            if len(preamble) >= 64:
                e_lfanew = struct.unpack_from("<I", preamble, 60)[0]
                result.findings[-1].details["pe_header_offset"] = e_lfanew

        # ELF check
        if preamble[:4] == self.ELF_MAGIC:
            elf_class = preamble[4] if len(preamble) > 4 else 0
            result.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="polyglot",
                    description="ELF (Linux) executable header in DICOM preamble",
                    offset=0,
                    details={
                        "type": "ELF/DICOM polyglot",
                        "cve": "CVE-2019-11687",
                        "elf_class": "64-bit" if elf_class == 2 else "32-bit",
                        "is_valid_dicom": is_dicm,
                    },
                )
            )

        # Mach-O check
        if preamble[:4] in (
            self.MACHO_32,
            self.MACHO_64,
            self.MACHO_32_REV,
            self.MACHO_64_REV,
        ):
            result.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="polyglot",
                    description="Mach-O (macOS) executable header in DICOM preamble",
                    offset=0,
                    details={
                        "type": "Mach-O/DICOM polyglot",
                        "cve": "CVE-2019-11687",
                        "is_valid_dicom": is_dicm,
                    },
                )
            )

    def _check_suspicious_strings(self, preamble: bytes, result: ScanResult) -> None:
        """Check for suspicious strings in preamble."""
        preamble_lower = preamble.lower()

        for suspicious in self.SUSPICIOUS_STRINGS:
            if suspicious.lower() in preamble_lower:
                result.findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="suspicious_content",
                        description=f"Suspicious string found in preamble: {suspicious.decode('ascii', errors='replace')}",
                        offset=preamble_lower.find(suspicious.lower()),
                        details={
                            "pattern": suspicious.decode("ascii", errors="replace")
                        },
                    )
                )

    def _check_shellcode_patterns(self, preamble: bytes, result: ScanResult) -> None:
        """Check for common shellcode patterns."""
        shellcode_patterns = [
            (b"\xcd\x80", "Linux int 0x80 syscall"),
            (b"\x0f\x05", "Linux syscall instruction"),
            (b"\x0f\x34", "Windows sysenter"),
            (b"\x90" * 5, "NOP sled"),
            (b"\xcc", "INT3 breakpoint"),
        ]

        for pattern, description in shellcode_patterns:
            if pattern in preamble:
                result.findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="shellcode",
                        description=f"Potential shellcode pattern: {description}",
                        offset=preamble.find(pattern),
                        details={"pattern_hex": pattern.hex()},
                    )
                )

    def _check_preamble_safety(self, preamble: bytes, result: ScanResult) -> None:
        """Check if preamble uses safe patterns."""
        # Check for null preamble
        if preamble == b"\x00" * 128:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="preamble",
                    description="Preamble contains safe null bytes",
                    details={"pattern": "null"},
                )
            )
            return

        # Check for TIFF preamble
        if preamble[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="preamble",
                    description="Preamble contains TIFF header (common, safe)",
                    details={"pattern": "tiff"},
                )
            )
            return

        # If not null or TIFF, and not executable, flag as unusual
        if not any(preamble[: len(p)] == p for p in [self.PE_MAGIC, self.ELF_MAGIC]):
            # Check if it has non-null content
            non_null = sum(1 for b in preamble if b != 0)
            if non_null > 10:
                result.findings.append(
                    Finding(
                        severity=Severity.LOW,
                        category="preamble",
                        description="Preamble contains unusual non-null content",
                        details={"non_null_bytes": non_null},
                    )
                )

    def _check_dicom_structure(self, header_data: bytes, result: ScanResult) -> None:
        """Check DICOM structure for anomalies."""
        # Basic structure checks
        if len(header_data) < 132:
            result.findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="structure",
                    description="File too small to contain valid DICOM metadata",
                )
            )

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        extensions: tuple[str, ...] = (".dcm", ".dicom", ".DCM", ".DICOM"),
    ) -> list[ScanResult]:
        """Scan all DICOM files in a directory.

        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories
            extensions: File extensions to scan

        Returns:
            List of ScanResults

        """
        directory = Path(directory)
        results = []

        pattern = "**/*" if recursive else "*"

        for ext in extensions:
            for path in directory.glob(f"{pattern}{ext}"):
                if path.is_file():
                    results.append(self.scan_file(path))

        # Also scan files without extension that might be DICOM
        for path in directory.glob(pattern):
            if path.is_file() and path.suffix == "":
                result = self.scan_file(path)
                if result.is_dicom:
                    results.append(result)

        return results


def _result_to_dict(r: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "path": str(r.path),
        "is_dicom": r.is_dicom,
        "is_clean": r.is_clean,
        "max_severity": r.max_severity.value if r.max_severity else None,
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "description": f.description,
                "offset": f.offset,
                "details": f.details,
            }
            for f in r.findings
        ],
        "error": r.error,
    }


def _print_result_text(r: ScanResult, verbose: bool) -> None:
    """Print a ScanResult in human-readable text format."""
    if r.is_clean:
        status = "[CLEAN]"
    elif r.max_severity:
        status = f"[{r.max_severity.value.upper()}]"
    else:
        status = "[UNKNOWN]"
    print(f"{status} {r.path}")

    if r.error:
        print(f"  Error: {r.error}")
        return

    for f in r.findings:
        if not verbose and f.severity == Severity.INFO:
            continue
        print(f"  [{f.severity.value.upper()}] {f.category}: {f.description}")
        if f.offset is not None:
            print(f"    Offset: {f.offset}")
        if f.details:
            for k, v in f.details.items():
                print(f"    {k}: {v}")


def main() -> None:
    """CLI entry point."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Scan DICOM files for security issues")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "-r", "--recursive", action="store_true", help="Scan recursively"
    )
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Include INFO level"
    )

    args = parser.parse_args()
    scanner = DicomSecurityScanner()
    path = Path(args.path)

    results = (
        [scanner.scan_file(path)]
        if path.is_file()
        else scanner.scan_directory(path, recursive=args.recursive)
    )

    if args.json:
        print(json.dumps([_result_to_dict(r) for r in results], indent=2))
    else:
        for r in results:
            _print_result_text(r, args.verbose)


if __name__ == "__main__":
    main()
