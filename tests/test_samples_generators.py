"""
Tests for malicious sample generators.

Tests the sample generation tools for:
- PE/DICOM and ELF/DICOM polyglot generation
- CVE reproduction sample generation
- Parser stress test generation
- Compliance violation generation
- Detection tools (scanner, sanitizer)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add samples directory to path for imports
SAMPLES_DIR = Path(__file__).parent.parent / "samples"
sys.path.insert(0, str(SAMPLES_DIR))


class TestPreambleAttackGenerator:
    """Tests for PE/DICOM and ELF/DICOM polyglot generation."""

    def test_import_generator(self) -> None:
        """Test that generator module can be imported."""
        from preamble_attacks.generator import PreambleAttackGenerator

        assert PreambleAttackGenerator is not None

    def test_create_pe_dicom(self, tmp_path: Path) -> None:
        """Test PE/DICOM polyglot generation."""
        from preamble_attacks.generator import PreambleAttackGenerator

        generator = PreambleAttackGenerator()
        output_path = tmp_path / "test_pe.dcm"

        result = generator.create_pe_dicom(output_path)

        assert result.exists()
        assert result.stat().st_size > 0

        # Verify PE header in preamble
        with open(result, "rb") as f:
            preamble = f.read(128)
            magic = f.read(4)

        assert preamble[:2] == b"MZ"  # PE magic
        assert magic == b"DICM"  # DICOM magic

    def test_create_elf_dicom(self, tmp_path: Path) -> None:
        """Test ELF/DICOM polyglot generation."""
        from preamble_attacks.generator import PreambleAttackGenerator

        generator = PreambleAttackGenerator()
        output_path = tmp_path / "test_elf.dcm"

        result = generator.create_elf_dicom(output_path)

        assert result.exists()
        assert result.stat().st_size > 0

        # Verify ELF header in preamble
        with open(result, "rb") as f:
            preamble = f.read(128)
            magic = f.read(4)

        assert preamble[:4] == b"\x7fELF"  # ELF magic
        assert magic == b"DICM"  # DICOM magic

    def test_validate_polyglot_pe(self, tmp_path: Path) -> None:
        """Test polyglot validation for PE/DICOM."""
        from preamble_attacks.generator import PreambleAttackGenerator

        generator = PreambleAttackGenerator()
        output_path = tmp_path / "test_pe.dcm"
        generator.create_pe_dicom(output_path)

        result = generator.validate_polyglot(output_path)

        assert result["is_dicom"] is True
        assert result["is_pe"] is True
        assert result["is_elf"] is False
        assert result["is_polyglot"] is True
        assert result["preamble_type"] == "PE (Windows)"

    def test_validate_polyglot_elf(self, tmp_path: Path) -> None:
        """Test polyglot validation for ELF/DICOM."""
        from preamble_attacks.generator import PreambleAttackGenerator

        generator = PreambleAttackGenerator()
        output_path = tmp_path / "test_elf.dcm"
        generator.create_elf_dicom(output_path)

        result = generator.validate_polyglot(output_path)

        assert result["is_dicom"] is True
        assert result["is_pe"] is False
        assert result["is_elf"] is True
        assert result["is_polyglot"] is True
        assert result["preamble_type"] == "ELF (Linux)"

    def test_sanitize_preamble(self, tmp_path: Path) -> None:
        """Test preamble sanitization."""
        from preamble_attacks.generator import PreambleAttackGenerator

        generator = PreambleAttackGenerator()

        # Create PE/DICOM
        pe_path = tmp_path / "pe.dcm"
        generator.create_pe_dicom(pe_path)

        # Sanitize
        clean_path = tmp_path / "clean.dcm"
        result = generator.sanitize_preamble(pe_path, clean_path)

        assert result.exists()

        # Verify preamble is cleared
        with open(result, "rb") as f:
            preamble = f.read(128)
            magic = f.read(4)

        assert preamble == b"\x00" * 128  # Null preamble
        assert magic == b"DICM"  # Still valid DICOM


class TestCVEGenerator:
    """Tests for CVE reproduction sample generation."""

    def test_import_generator(self) -> None:
        """Test that CVE generator module can be imported."""
        from cve_reproductions.generator import CVE_DATABASE, CVESampleGenerator

        assert CVESampleGenerator is not None
        assert len(CVE_DATABASE) >= 7

    def test_generate_cve_2019_11687(self, tmp_path: Path) -> None:
        """Test CVE-2019-11687 sample generation."""
        from cve_reproductions.generator import CVESampleGenerator

        generator = CVESampleGenerator(tmp_path)
        result = generator.generate_cve_2019_11687()

        assert result.exists()
        assert result.stat().st_size > 0

        # Verify PE header
        with open(result, "rb") as f:
            preamble = f.read(128)
        assert preamble[:2] == b"MZ"

    def test_generate_cve_2022_2119(self, tmp_path: Path) -> None:
        """Test CVE-2022-2119 sample generation (path traversal)."""
        from cve_reproductions.generator import CVESampleGenerator

        generator = CVESampleGenerator(tmp_path)
        result = generator.generate_cve_2022_2119()

        assert result.exists()

    def test_generate_cve_2025_5943(self, tmp_path: Path) -> None:
        """Test CVE-2025-5943 sample generation (OOB write)."""
        from cve_reproductions.generator import CVESampleGenerator

        generator = CVESampleGenerator(tmp_path)
        result = generator.generate_cve_2025_5943()

        assert result.exists()

    def test_generate_all_cves(self, tmp_path: Path) -> None:
        """Test generating all CVE samples."""
        from cve_reproductions.generator import CVESampleGenerator

        generator = CVESampleGenerator(tmp_path)
        results = generator.generate_all()

        assert len(results) == 7
        for cve_id, path in results.items():
            if path is not None:
                assert path.exists(), f"Missing sample for {cve_id}"


class TestParserStressGenerator:
    """Tests for parser stress test generation."""

    def test_import_generator(self) -> None:
        """Test that parser stress generator can be imported."""
        from parser_stress.generator import ParserStressGenerator

        assert ParserStressGenerator is not None

    def test_generate_deep_sequence_nesting(self, tmp_path: Path) -> None:
        """Test deep sequence nesting sample."""
        from parser_stress.generator import ParserStressGenerator

        generator = ParserStressGenerator(tmp_path)
        result = generator.generate_deep_sequence_nesting()

        assert result.exists()
        assert result.stat().st_size > 0

    def test_generate_truncated_pixeldata(self, tmp_path: Path) -> None:
        """Test truncated pixel data sample."""
        from parser_stress.generator import ParserStressGenerator

        generator = ParserStressGenerator(tmp_path)
        result = generator.generate_truncated_pixeldata()

        assert result.exists()

    def test_generate_all_stress_tests(self, tmp_path: Path) -> None:
        """Test generating all stress test samples."""
        from parser_stress.generator import ParserStressGenerator

        generator = ParserStressGenerator(tmp_path)
        results = generator.generate_all()

        assert len(results) >= 6
        for name, path in results.items():
            if path is not None:
                assert path.exists(), f"Missing sample: {name}"


class TestComplianceViolationGenerator:
    """Tests for compliance violation generation."""

    def test_import_generator(self) -> None:
        """Test that compliance generator can be imported."""
        from compliance_violations.generator import ComplianceViolationGenerator

        assert ComplianceViolationGenerator is not None

    def test_generate_invalid_vr_samples(self, tmp_path: Path) -> None:
        """Test invalid VR sample generation."""
        from compliance_violations.generator import ComplianceViolationGenerator

        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_invalid_vr_samples()

        assert len(results) >= 3
        for name, path in results.items():
            assert path.exists(), f"Missing sample: {name}"

    def test_generate_oversized_samples(self, tmp_path: Path) -> None:
        """Test oversized value sample generation."""
        from compliance_violations.generator import ComplianceViolationGenerator

        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_oversized_samples()

        assert len(results) >= 3

    def test_generate_all_violations(self, tmp_path: Path) -> None:
        """Test generating all compliance violation samples."""
        from compliance_violations.generator import ComplianceViolationGenerator

        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_all()

        assert "invalid_vr" in results
        assert "oversized_values" in results
        assert "missing_required" in results
        assert "encoding_errors" in results


class TestDetectionScanner:
    """Tests for the detection scanner."""

    def test_import_scanner(self) -> None:
        """Test that scanner can be imported."""
        from detection.scanner import DicomSecurityScanner

        assert DicomSecurityScanner is not None

    def test_scan_pe_dicom(self, tmp_path: Path) -> None:
        """Test scanning PE/DICOM polyglot."""
        from detection.scanner import DicomSecurityScanner, Severity
        from preamble_attacks.generator import PreambleAttackGenerator

        # Create PE/DICOM
        generator = PreambleAttackGenerator()
        pe_path = tmp_path / "pe.dcm"
        generator.create_pe_dicom(pe_path)

        # Scan
        scanner = DicomSecurityScanner()
        result = scanner.scan_file(pe_path)

        assert result.is_dicom is True
        assert result.is_clean is False
        assert result.max_severity == Severity.CRITICAL
        assert any(f.category == "polyglot" for f in result.findings)

    def test_scan_clean_dicom(self, tmp_path: Path) -> None:
        """Test scanning clean DICOM file."""
        from detection.scanner import DicomSecurityScanner
        from preamble_attacks.generator import PreambleAttackGenerator

        # Create and sanitize
        generator = PreambleAttackGenerator()
        pe_path = tmp_path / "pe.dcm"
        generator.create_pe_dicom(pe_path)
        clean_path = tmp_path / "clean.dcm"
        generator.sanitize_preamble(pe_path, clean_path)

        # Scan
        scanner = DicomSecurityScanner()
        result = scanner.scan_file(clean_path)

        assert result.is_dicom is True
        assert result.is_clean is True


class TestDetectionSanitizer:
    """Tests for the detection sanitizer."""

    def test_import_sanitizer(self) -> None:
        """Test that sanitizer can be imported."""
        from detection.sanitizer import DicomSanitizer

        assert DicomSanitizer is not None

    def test_sanitize_pe_dicom(self, tmp_path: Path) -> None:
        """Test sanitizing PE/DICOM polyglot."""
        from detection.sanitizer import DicomSanitizer, SanitizeAction
        from preamble_attacks.generator import PreambleAttackGenerator

        # Create PE/DICOM
        generator = PreambleAttackGenerator()
        pe_path = tmp_path / "pe.dcm"
        generator.create_pe_dicom(pe_path)

        # Sanitize
        sanitizer = DicomSanitizer(backup=False)
        clean_path = tmp_path / "clean.dcm"
        result = sanitizer.sanitize_file(pe_path, clean_path)

        assert result.action == SanitizeAction.CLEARED
        assert result.original_preamble_type == "PE (Windows)"
        assert clean_path.exists()

    def test_sanitize_already_clean(self, tmp_path: Path) -> None:
        """Test sanitizing already clean file."""
        from detection.sanitizer import DicomSanitizer, SanitizeAction
        from preamble_attacks.generator import PreambleAttackGenerator

        # Create and sanitize
        generator = PreambleAttackGenerator()
        pe_path = tmp_path / "pe.dcm"
        generator.create_pe_dicom(pe_path)
        clean_path = tmp_path / "clean.dcm"
        generator.sanitize_preamble(pe_path, clean_path)

        # Try to sanitize again
        sanitizer = DicomSanitizer(backup=False)
        result = sanitizer.sanitize_file(clean_path, tmp_path / "clean2.dcm")

        assert result.action == SanitizeAction.SKIPPED

    def test_detect_preamble_types(self) -> None:
        """Test preamble type detection."""
        from detection.sanitizer import DicomSanitizer

        sanitizer = DicomSanitizer()

        # Test PE detection
        pe_preamble = b"MZ" + b"\x00" * 126
        assert sanitizer.detect_preamble_type(pe_preamble) == "PE (Windows)"

        # Test ELF detection
        elf_preamble = b"\x7fELF" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(elf_preamble) == "ELF (Linux)"

        # Test null preamble
        null_preamble = b"\x00" * 128
        assert "Safe" in sanitizer.detect_preamble_type(null_preamble)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
