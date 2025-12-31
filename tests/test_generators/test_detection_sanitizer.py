"""Tests for DICOM Preamble Sanitizer.

Tests the DicomSanitizer for neutralizing polyglot attacks
by clearing DICOM preambles that contain executable content.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.generators.detection.sanitizer import (
    DicomSanitizer,
    SanitizeAction,
    SanitizeResult,
)


class TestSanitizeAction:
    """Tests for SanitizeAction enum."""

    def test_action_values(self) -> None:
        """Test action enum has expected string values."""
        assert SanitizeAction.CLEARED.value == "cleared"
        assert SanitizeAction.SKIPPED.value == "skipped"
        assert SanitizeAction.FAILED.value == "failed"
        assert SanitizeAction.NOT_DICOM.value == "not_dicom"

    def test_action_count(self) -> None:
        """Test all action types exist."""
        assert len(SanitizeAction) == 4


class TestSanitizeResult:
    """Tests for SanitizeResult dataclass."""

    def test_create_result(self) -> None:
        """Test creating result with all fields."""
        result = SanitizeResult(
            input_path=Path("input.dcm"),
            output_path=Path("output.dcm"),
            action=SanitizeAction.CLEARED,
            original_preamble_type="PE (Windows)",
            message="Preamble cleared",
        )
        assert result.input_path == Path("input.dcm")
        assert result.output_path == Path("output.dcm")
        assert result.action == SanitizeAction.CLEARED
        assert result.original_preamble_type == "PE (Windows)"

    def test_result_with_none_output(self) -> None:
        """Test result with None output path."""
        result = SanitizeResult(
            input_path=Path("input.dcm"),
            output_path=None,
            action=SanitizeAction.FAILED,
            original_preamble_type="Unknown",
            message="Read error",
        )
        assert result.output_path is None


class TestDicomSanitizerInit:
    """Tests for DicomSanitizer initialization."""

    def test_init_default_backup(self) -> None:
        """Test default initialization enables backup."""
        sanitizer = DicomSanitizer()
        assert sanitizer.backup is True

    def test_init_no_backup(self) -> None:
        """Test initialization with backup disabled."""
        sanitizer = DicomSanitizer(backup=False)
        assert sanitizer.backup is False


class TestDetectPreambleType:
    """Tests for preamble type detection."""

    @pytest.fixture
    def sanitizer(self) -> DicomSanitizer:
        """Create sanitizer instance."""
        return DicomSanitizer()

    def test_detect_pe_header(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of PE header."""
        preamble = b"MZ" + b"\x00" * 126
        assert sanitizer.detect_preamble_type(preamble) == "PE (Windows)"

    def test_detect_elf_header(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of ELF header."""
        preamble = b"\x7fELF" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "ELF (Linux)"

    def test_detect_macho_32(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of Mach-O 32-bit header."""
        preamble = b"\xfe\xed\xfa\xce" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "Mach-O 32-bit"

    def test_detect_macho_64(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of Mach-O 64-bit header."""
        preamble = b"\xfe\xed\xfa\xcf" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "Mach-O 64-bit"

    def test_detect_macho_32_reversed(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of reversed Mach-O 32-bit header."""
        preamble = b"\xce\xfa\xed\xfe" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "Mach-O 32-bit (reversed)"

    def test_detect_macho_64_reversed(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of reversed Mach-O 64-bit header."""
        preamble = b"\xcf\xfa\xed\xfe" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "Mach-O 64-bit (reversed)"

    def test_detect_null_bytes(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of null byte preamble."""
        preamble = b"\x00" * 128
        assert sanitizer.detect_preamble_type(preamble) == "Safe (null bytes)"

    def test_detect_tiff_little_endian(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of TIFF little-endian header."""
        preamble = b"II\x2a\x00" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "Safe (TIFF header)"

    def test_detect_tiff_big_endian(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of TIFF big-endian header."""
        preamble = b"MM\x00\x2a" + b"\x00" * 124
        assert sanitizer.detect_preamble_type(preamble) == "Safe (TIFF header)"

    def test_detect_mostly_null(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of mostly null preamble."""
        preamble = b"AB" + b"\x00" * 126  # Only 2 non-null bytes
        assert sanitizer.detect_preamble_type(preamble) == "Safe (mostly null)"

    def test_detect_unknown_content(self, sanitizer: DicomSanitizer) -> None:
        """Test detection of unknown content."""
        preamble = b"RANDOM DATA " + b"X" * 116
        assert sanitizer.detect_preamble_type(preamble) == "Unknown content"


class TestIsPreambleSafe:
    """Tests for preamble safety checking."""

    @pytest.fixture
    def sanitizer(self) -> DicomSanitizer:
        """Create sanitizer instance."""
        return DicomSanitizer()

    def test_null_preamble_is_safe(self, sanitizer: DicomSanitizer) -> None:
        """Test null preamble is considered safe."""
        preamble = b"\x00" * 128
        assert sanitizer.is_preamble_safe(preamble) is True

    def test_tiff_preamble_is_safe(self, sanitizer: DicomSanitizer) -> None:
        """Test TIFF preamble is considered safe."""
        preamble = b"II\x2a\x00" + b"\x00" * 124
        assert sanitizer.is_preamble_safe(preamble) is True

    def test_mostly_null_is_safe(self, sanitizer: DicomSanitizer) -> None:
        """Test mostly null preamble is considered safe."""
        preamble = b"AB" + b"\x00" * 126
        assert sanitizer.is_preamble_safe(preamble) is True

    def test_pe_preamble_is_unsafe(self, sanitizer: DicomSanitizer) -> None:
        """Test PE preamble is considered unsafe."""
        preamble = b"MZ" + b"\x00" * 126
        assert sanitizer.is_preamble_safe(preamble) is False

    def test_elf_preamble_is_unsafe(self, sanitizer: DicomSanitizer) -> None:
        """Test ELF preamble is considered unsafe."""
        preamble = b"\x7fELF" + b"\x00" * 124
        assert sanitizer.is_preamble_safe(preamble) is False

    def test_unknown_content_is_unsafe(self, sanitizer: DicomSanitizer) -> None:
        """Test unknown content is considered unsafe."""
        preamble = b"RANDOM DATA " + b"X" * 116
        assert sanitizer.is_preamble_safe(preamble) is False


class TestSanitizeFile:
    """Tests for file sanitization."""

    @pytest.fixture
    def sanitizer(self) -> DicomSanitizer:
        """Create sanitizer with backup enabled."""
        return DicomSanitizer(backup=True)

    def test_sanitize_pe_polyglot(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test sanitizing PE/DICOM polyglot."""
        input_file = tmp_path / "pe_polyglot.dcm"
        output_file = tmp_path / "sanitized.dcm"
        content = b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file, output_file)

        assert result.action == SanitizeAction.CLEARED
        assert result.original_preamble_type == "PE (Windows)"
        assert result.output_path == output_file
        # Verify output has null preamble
        sanitized = output_file.read_bytes()
        assert sanitized[:128] == b"\x00" * 128
        assert sanitized[128:132] == b"DICM"

    def test_sanitize_elf_polyglot(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test sanitizing ELF/DICOM polyglot."""
        input_file = tmp_path / "elf_polyglot.dcm"
        output_file = tmp_path / "sanitized.dcm"
        content = b"\x7fELF" + b"\x00" * 124 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file, output_file)

        assert result.action == SanitizeAction.CLEARED
        assert result.original_preamble_type == "ELF (Linux)"

    def test_skip_safe_preamble(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test safe preamble is skipped."""
        input_file = tmp_path / "safe.dcm"
        output_file = tmp_path / "sanitized.dcm"
        content = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file, output_file)

        assert result.action == SanitizeAction.SKIPPED
        assert "already safe" in result.message.lower()

    def test_force_sanitize_safe_preamble(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test force flag sanitizes even safe preambles."""
        input_file = tmp_path / "safe.dcm"
        output_file = tmp_path / "sanitized.dcm"
        # TIFF header is safe but force=True should still clear it
        content = b"II\x2a\x00" + b"\x00" * 124 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file, output_file, force=True)

        assert result.action == SanitizeAction.CLEARED
        # Output should have null preamble
        sanitized = output_file.read_bytes()
        assert sanitized[:4] == b"\x00\x00\x00\x00"

    def test_not_dicom_file(self, sanitizer: DicomSanitizer, tmp_path: Path) -> None:
        """Test non-DICOM file is rejected."""
        input_file = tmp_path / "not_dicom.dcm"
        content = b"\x00" * 128 + b"NOTD" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file)

        assert result.action == SanitizeAction.NOT_DICOM
        assert "DICM magic" in result.message

    def test_file_too_small(self, sanitizer: DicomSanitizer, tmp_path: Path) -> None:
        """Test too-small file is rejected."""
        input_file = tmp_path / "small.dcm"
        input_file.write_bytes(b"\x00" * 50)

        result = sanitizer.sanitize_file(input_file)

        assert result.action == SanitizeAction.NOT_DICOM
        assert "too small" in result.message.lower()

    def test_read_error(self, sanitizer: DicomSanitizer, tmp_path: Path) -> None:
        """Test read error is handled."""
        input_file = tmp_path / "unreadable.dcm"
        input_file.write_bytes(b"\x00" * 232)

        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = sanitizer.sanitize_file(input_file)

        assert result.action == SanitizeAction.FAILED
        assert "Failed to read" in result.message

    def test_in_place_creates_backup(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test in-place sanitization creates backup."""
        input_file = tmp_path / "polyglot.dcm"
        content = b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file)  # No output_path = in-place

        assert result.action == SanitizeAction.CLEARED
        # Check backup was created
        backup_file = input_file.with_suffix(".dcm.bak")
        assert backup_file.exists()
        # Backup should have original content
        assert backup_file.read_bytes() == content

    def test_in_place_no_backup(self, tmp_path: Path) -> None:
        """Test in-place sanitization without backup."""
        sanitizer = DicomSanitizer(backup=False)
        input_file = tmp_path / "polyglot.dcm"
        content = b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file)

        assert result.action == SanitizeAction.CLEARED
        # No backup should exist
        backup_file = input_file.with_suffix(".dcm.bak")
        assert not backup_file.exists()

    def test_output_to_different_directory(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test output to different directory creates parent dirs."""
        input_file = tmp_path / "input.dcm"
        output_dir = tmp_path / "output" / "subdir"
        output_file = output_dir / "sanitized.dcm"
        content = b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        input_file.write_bytes(content)

        result = sanitizer.sanitize_file(input_file, output_file)

        assert result.action == SanitizeAction.CLEARED
        assert output_file.exists()


class TestSanitizeDirectory:
    """Tests for directory sanitization."""

    @pytest.fixture
    def sanitizer(self) -> DicomSanitizer:
        """Create sanitizer instance."""
        return DicomSanitizer(backup=False)

    def test_sanitize_empty_directory(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test sanitizing empty directory."""
        results = sanitizer.sanitize_directory(tmp_path)
        assert results == []

    def test_sanitize_directory_with_files(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test sanitizing directory with polyglot files."""
        # Create PE polyglot
        pe_file = tmp_path / "pe.dcm"
        pe_file.write_bytes(b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100)
        # Create safe file
        safe_file = tmp_path / "safe.dcm"
        safe_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        results = sanitizer.sanitize_directory(tmp_path)

        # Should have results for both files (may have duplicates due to case-insensitive extensions)
        unique_paths = {r.input_path for r in results}
        assert len(unique_paths) >= 2
        # Check at least one was cleared and one was skipped
        actions = {r.action for r in results}
        assert SanitizeAction.CLEARED in actions
        assert SanitizeAction.SKIPPED in actions

    def test_sanitize_directory_recursive(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test recursive directory sanitization."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        (tmp_path / "root.dcm").write_bytes(
            b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        )
        (subdir / "sub.dcm").write_bytes(
            b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        )

        results = sanitizer.sanitize_directory(tmp_path, recursive=True)

        unique_paths = {r.input_path for r in results}
        assert len(unique_paths) >= 2

    def test_sanitize_directory_non_recursive(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test non-recursive directory sanitization."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        (tmp_path / "root.dcm").write_bytes(
            b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        )
        (subdir / "sub.dcm").write_bytes(
            b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        )

        results = sanitizer.sanitize_directory(tmp_path, recursive=False)

        # Should only find root file
        assert all(r.input_path.parent == tmp_path for r in results)

    def test_sanitize_directory_with_output_dir(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test sanitizing to output directory."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        (input_dir / "test.dcm").write_bytes(
            b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100
        )

        results = sanitizer.sanitize_directory(input_dir, output_dir=output_dir)

        # Output file should exist
        output_file = output_dir / "test.dcm"
        assert any(
            r.output_path == output_file
            for r in results
            if r.action == SanitizeAction.CLEARED
        )

    def test_sanitize_directory_force(
        self, sanitizer: DicomSanitizer, tmp_path: Path
    ) -> None:
        """Test force flag in directory sanitization."""
        (tmp_path / "safe.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        results = sanitizer.sanitize_directory(tmp_path, force=True)

        # With force, even safe files should be cleared
        assert any(r.action == SanitizeAction.CLEARED for r in results)


class TestWriteErrors:
    """Tests for write error handling."""

    def test_write_error_handled(self, tmp_path: Path) -> None:
        """Test write error is handled gracefully."""
        sanitizer = DicomSanitizer(backup=False)
        input_file = tmp_path / "test.dcm"
        output_file = tmp_path / "output.dcm"
        input_file.write_bytes(b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100)

        # Mock open to fail on write
        original_open = open
        call_count = 0

        def mock_open(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Allow read
                return original_open(*args, **kwargs)
            # Fail on write
            raise OSError("Disk full")

        with patch("builtins.open", mock_open):
            result = sanitizer.sanitize_file(input_file, output_file)

        assert result.action == SanitizeAction.FAILED
        assert "Failed to write" in result.message

    def test_backup_error_handled(self, tmp_path: Path) -> None:
        """Test backup creation error is handled."""
        sanitizer = DicomSanitizer(backup=True)
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"MZ" + b"\x00" * 126 + b"DICM" + b"\x00" * 100)

        with patch("shutil.copy2", side_effect=OSError("Permission denied")):
            result = sanitizer.sanitize_file(input_file)

        assert result.action == SanitizeAction.FAILED
        assert "backup" in result.message.lower()
