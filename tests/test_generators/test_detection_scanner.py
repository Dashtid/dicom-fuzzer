"""Tests for DICOM Security Scanner.

Tests the DicomSecurityScanner for detecting polyglot attacks,
suspicious content, and security issues in DICOM files.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.generators.detection.scanner import (
    DicomSecurityScanner,
    Finding,
    ScanResult,
    Severity,
)


class TestSeverityEnum:
    """Tests for Severity enum."""

    def test_severity_values(self) -> None:
        """Test severity enum has expected string values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_count(self) -> None:
        """Test all severity levels exist."""
        assert len(Severity) == 5


class TestFinding:
    """Tests for Finding dataclass."""

    def test_create_finding_minimal(self) -> None:
        """Test creating finding with minimal fields."""
        finding = Finding(
            severity=Severity.HIGH,
            category="polyglot",
            description="PE header detected",
        )
        assert finding.severity == Severity.HIGH
        assert finding.category == "polyglot"
        assert finding.description == "PE header detected"
        assert finding.offset is None
        assert finding.details == {}

    def test_create_finding_full(self) -> None:
        """Test creating finding with all fields."""
        finding = Finding(
            severity=Severity.CRITICAL,
            category="executable",
            description="Windows PE in preamble",
            offset=0,
            details={"type": "PE/DICOM", "cve": "CVE-2019-11687"},
        )
        assert finding.offset == 0
        assert finding.details["cve"] == "CVE-2019-11687"


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_defaults(self) -> None:
        """Test scan result default values."""
        result = ScanResult(path=Path("test.dcm"), is_dicom=True)
        assert result.findings == []
        assert result.error is None

    def test_is_clean_true_when_no_findings(self) -> None:
        """Test is_clean returns True with no findings."""
        result = ScanResult(path=Path("test.dcm"), is_dicom=True)
        assert result.is_clean is True

    def test_is_clean_true_with_low_severity(self) -> None:
        """Test is_clean returns True with low severity findings."""
        result = ScanResult(
            path=Path("test.dcm"),
            is_dicom=True,
            findings=[
                Finding(Severity.LOW, "preamble", "unusual content"),
                Finding(Severity.INFO, "preamble", "null bytes"),
            ],
        )
        assert result.is_clean is True

    def test_is_clean_false_with_high_severity(self) -> None:
        """Test is_clean returns False with high severity finding."""
        result = ScanResult(
            path=Path("test.dcm"),
            is_dicom=True,
            findings=[
                Finding(Severity.HIGH, "suspicious", "cmd.exe found"),
            ],
        )
        assert result.is_clean is False

    def test_is_clean_false_with_critical_severity(self) -> None:
        """Test is_clean returns False with critical severity finding."""
        result = ScanResult(
            path=Path("test.dcm"),
            is_dicom=True,
            findings=[
                Finding(Severity.CRITICAL, "polyglot", "PE header"),
            ],
        )
        assert result.is_clean is False

    def test_max_severity_none_when_no_findings(self) -> None:
        """Test max_severity returns None with no findings."""
        result = ScanResult(path=Path("test.dcm"), is_dicom=True)
        assert result.max_severity is None

    def test_max_severity_returns_highest(self) -> None:
        """Test max_severity returns highest severity."""
        result = ScanResult(
            path=Path("test.dcm"),
            is_dicom=True,
            findings=[
                Finding(Severity.LOW, "preamble", "unusual"),
                Finding(Severity.HIGH, "suspicious", "cmd.exe"),
                Finding(Severity.MEDIUM, "shellcode", "NOP sled"),
            ],
        )
        assert result.max_severity == Severity.HIGH

    def test_max_severity_critical(self) -> None:
        """Test max_severity returns critical when present."""
        result = ScanResult(
            path=Path("test.dcm"),
            is_dicom=True,
            findings=[
                Finding(Severity.HIGH, "suspicious", "script"),
                Finding(Severity.CRITICAL, "polyglot", "PE header"),
            ],
        )
        assert result.max_severity == Severity.CRITICAL


class TestScanFile:
    """Tests for scan_file method."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_scan_missing_file(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning non-existent file."""
        result = scanner.scan_file(tmp_path / "nonexistent.dcm")
        assert result.is_dicom is False
        assert "not found" in result.error.lower()

    def test_scan_file_too_small(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning file smaller than preamble."""
        small_file = tmp_path / "small.dcm"
        small_file.write_bytes(b"\x00" * 50)
        result = scanner.scan_file(small_file)
        assert "too small" in result.error.lower()

    def test_scan_valid_dicom(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning valid DICOM with safe preamble."""
        safe_file = tmp_path / "safe.dcm"
        content = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        safe_file.write_bytes(content)
        result = scanner.scan_file(safe_file)
        assert result.is_dicom is True
        assert result.error is None

    def test_scan_non_dicom_file(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning file without DICM magic."""
        non_dicom = tmp_path / "notdicom.dcm"
        content = b"\x00" * 128 + b"NOTD" + b"\x00" * 100
        non_dicom.write_bytes(content)
        result = scanner.scan_file(non_dicom)
        assert result.is_dicom is False


class TestExecutablePreamble:
    """Tests for executable preamble detection."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_detect_pe_header(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of PE/DICOM polyglot."""
        pe_file = tmp_path / "pe_polyglot.dcm"
        # MZ header + padding + DICM
        content = b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        pe_file.write_bytes(content)

        result = scanner.scan_file(pe_file)
        assert result.is_dicom is True
        assert any(f.category == "polyglot" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)
        assert any("PE" in f.description for f in result.findings)

    def test_detect_elf_header(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of ELF/DICOM polyglot."""
        elf_file = tmp_path / "elf_polyglot.dcm"
        # ELF magic + class byte (64-bit) + padding + DICM
        content = b"\x7fELF\x02" + b"\x00" * 123 + b"DICM" + b"\x00" * 100
        elf_file.write_bytes(content)

        result = scanner.scan_file(elf_file)
        assert result.is_dicom is True
        assert any(f.category == "polyglot" for f in result.findings)
        assert any("ELF" in f.description for f in result.findings)
        # Check ELF class detection
        elf_finding = next(f for f in result.findings if "ELF" in f.description)
        assert "64-bit" in elf_finding.details.get("elf_class", "")

    def test_detect_elf_32bit(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of 32-bit ELF."""
        elf_file = tmp_path / "elf32_polyglot.dcm"
        content = b"\x7fELF\x01" + b"\x00" * 123 + b"DICM" + b"\x00" * 100
        elf_file.write_bytes(content)

        result = scanner.scan_file(elf_file)
        elf_finding = next(f for f in result.findings if "ELF" in f.description)
        assert "32-bit" in elf_finding.details.get("elf_class", "")

    def test_detect_macho_header(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of Mach-O/DICOM polyglot."""
        macho_file = tmp_path / "macho_polyglot.dcm"
        # Mach-O 64-bit magic + padding + DICM
        content = b"\xfe\xed\xfa\xcf" + b"\x00" * 124 + b"DICM" + b"\x00" * 100
        macho_file.write_bytes(content)

        result = scanner.scan_file(macho_file)
        assert any("Mach-O" in f.description for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_pe_header_offset_extracted(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test PE header offset is extracted from e_lfanew."""
        pe_file = tmp_path / "pe_with_offset.dcm"
        # Create PE with e_lfanew at offset 60
        content = bytearray(b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100)
        # Set e_lfanew (little-endian at offset 60) to 0x80
        content[60:64] = b"\x80\x00\x00\x00"
        pe_file.write_bytes(bytes(content))

        result = scanner.scan_file(pe_file)
        pe_finding = next((f for f in result.findings if "PE" in f.description), None)
        assert pe_finding is not None
        assert pe_finding.details.get("pe_header_offset") == 0x80


class TestSuspiciousStrings:
    """Tests for suspicious string detection."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_detect_cmd_exe(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of cmd.exe in preamble."""
        file = tmp_path / "cmd.dcm"
        content = b"cmd.exe " + b"\x00" * 120 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("cmd.exe" in f.description for f in result.findings)
        assert any(f.severity == Severity.HIGH for f in result.findings)

    def test_detect_powershell(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of powershell in preamble."""
        file = tmp_path / "ps.dcm"
        content = b"powershell" + b"\x00" * 118 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("powershell" in f.description.lower() for f in result.findings)

    def test_detect_http_url(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of http:// URL in preamble."""
        file = tmp_path / "http.dcm"
        content = b"http://evil.com" + b"\x00" * 113 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("http://" in f.description for f in result.findings)

    def test_detect_script_tag(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of <script in preamble."""
        file = tmp_path / "script.dcm"
        content = b"<script>alert(1)</script>" + b"\x00" * 103 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("<script" in f.description for f in result.findings)

    def test_no_suspicious_strings(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test no false positives for safe content."""
        file = tmp_path / "safe.dcm"
        content = b"SAFE CONTENT" + b"\x00" * 116 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert not any(f.category == "suspicious_content" for f in result.findings)


class TestShellcodePatterns:
    """Tests for shellcode pattern detection."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_detect_linux_syscall(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of Linux int 0x80 syscall."""
        file = tmp_path / "syscall.dcm"
        content = b"\x00" * 50 + b"\xcd\x80" + b"\x00" * 76 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any(f.category == "shellcode" for f in result.findings)
        assert any("syscall" in f.description.lower() for f in result.findings)

    def test_detect_nop_sled(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of NOP sled."""
        file = tmp_path / "nop.dcm"
        content = b"\x90" * 10 + b"\x00" * 118 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("NOP" in f.description for f in result.findings)

    def test_detect_breakpoint(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of INT3 breakpoint."""
        file = tmp_path / "int3.dcm"
        content = b"\x00" * 64 + b"\xcc" + b"\x00" * 63 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("breakpoint" in f.description.lower() for f in result.findings)

    def test_detect_syscall_instruction(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test detection of Linux syscall instruction."""
        file = tmp_path / "syscall2.dcm"
        content = b"\x00" * 50 + b"\x0f\x05" + b"\x00" * 76 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any(f.category == "shellcode" for f in result.findings)


class TestPreambleSafety:
    """Tests for preamble safety checks."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_null_preamble_is_safe(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test null preamble is marked as safe."""
        file = tmp_path / "null.dcm"
        content = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any(
            f.category == "preamble" and "null" in f.description.lower()
            for f in result.findings
        )
        # Null preamble should only have INFO level finding
        preamble_findings = [f for f in result.findings if f.category == "preamble"]
        assert all(f.severity == Severity.INFO for f in preamble_findings)

    def test_tiff_preamble_is_safe(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test TIFF header preamble is marked as safe."""
        file = tmp_path / "tiff.dcm"
        # Little-endian TIFF header
        content = b"II\x2a\x00" + b"\x00" * 124 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("TIFF" in f.description for f in result.findings)

    def test_tiff_big_endian(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test big-endian TIFF header is recognized."""
        file = tmp_path / "tiff_be.dcm"
        content = b"MM\x00\x2a" + b"\x00" * 124 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any("TIFF" in f.description for f in result.findings)

    def test_unusual_preamble_flagged(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test unusual non-null preamble is flagged as LOW."""
        file = tmp_path / "unusual.dcm"
        # Random data that's not an executable signature
        content = b"RANDOM DATA HERE" + b"X" * 112 + b"DICM" + b"\x00" * 100
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert any(
            f.category == "preamble" and "unusual" in f.description.lower()
            for f in result.findings
        )


class TestDicomStructure:
    """Tests for DICOM structure validation."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_valid_structure(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test valid DICOM structure passes."""
        file = tmp_path / "valid.dcm"
        content = b"\x00" * 128 + b"DICM" + b"\x00" * 200
        file.write_bytes(content)

        result = scanner.scan_file(file)
        assert result.is_dicom is True
        assert not any(f.category == "structure" for f in result.findings)

    def test_small_dicom_flagged(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test too-small DICOM structure is flagged."""
        file = tmp_path / "small.dcm"
        # Just preamble + magic, no metadata
        content = b"\x00" * 128 + b"DICM"
        file.write_bytes(content)

        result = scanner.scan_file(file)
        # This should still be detected as DICOM but flagged
        assert result.is_dicom is True


class TestScanDirectory:
    """Tests for directory scanning."""

    @pytest.fixture
    def scanner(self) -> DicomSecurityScanner:
        """Create scanner instance."""
        return DicomSecurityScanner()

    def test_scan_empty_directory(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning empty directory."""
        results = scanner.scan_directory(tmp_path)
        assert results == []

    def test_scan_directory_with_dcm_files(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning directory with .dcm files."""
        # Create test files
        for i in range(3):
            file = tmp_path / f"test{i}.dcm"
            content = b"\x00" * 128 + b"DICM" + b"\x00" * 100
            file.write_bytes(content)

        results = scanner.scan_directory(tmp_path)
        # On Windows, .dcm and .DCM match same files (case-insensitive)
        # So we may get duplicate results - just check we found all files
        unique_paths = {r.path for r in results}
        assert len(unique_paths) >= 3

    def test_scan_directory_recursive(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test recursive directory scanning."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        # File in root
        (tmp_path / "root.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        # File in subdir
        (subdir / "sub.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        results = scanner.scan_directory(tmp_path, recursive=True)
        # Check unique paths found (Windows case-insensitive may cause duplicates)
        unique_paths = {r.path for r in results}
        assert len(unique_paths) >= 2

    def test_scan_directory_non_recursive(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test non-recursive directory scanning."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        (tmp_path / "root.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        (subdir / "sub.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        results = scanner.scan_directory(tmp_path, recursive=False)
        # Check unique paths found (Windows case-insensitive may cause duplicates)
        unique_paths = {r.path for r in results}
        # Non-recursive should only find root file, not subdir
        assert len(unique_paths) >= 1
        assert all(r.path.parent == tmp_path for r in results)

    def test_scan_directory_filters_extensions(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test directory scanning filters by extension."""
        (tmp_path / "test.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        (tmp_path / "test.txt").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        (tmp_path / "test.DICOM").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        results = scanner.scan_directory(tmp_path)
        paths = [r.path.suffix for r in results]
        assert ".dcm" in paths or ".DICOM" in paths
        # .txt should not be scanned as it's not a recognized extension
        assert len([r for r in results if r.path.suffix == ".txt"]) == 0

    def test_scan_extensionless_dicom(
        self, scanner: DicomSecurityScanner, tmp_path: Path
    ) -> None:
        """Test scanning files without extension that are valid DICOM."""
        # File without extension but with DICOM magic
        file = tmp_path / "dicom_file"
        file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        results = scanner.scan_directory(tmp_path)
        # Should find the extensionless DICOM
        assert any(r.path.name == "dicom_file" for r in results)


class TestReadErrors:
    """Tests for file read error handling."""

    def test_read_error_handled(self, tmp_path: Path) -> None:
        """Test OSError during file read is handled."""
        scanner = DicomSecurityScanner()
        file = tmp_path / "test.dcm"
        file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = scanner.scan_file(file)
            assert result.error is not None
            assert "Error reading" in result.error
