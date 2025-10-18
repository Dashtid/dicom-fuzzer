"""
Comprehensive tests for utils/helpers.py module.

Focuses on critical utility functions for 70%+ coverage.
"""

import pytest
import tempfile
from pathlib import Path
from pydicom.tag import Tag

from dicom_fuzzer.utils.helpers import (
    validate_file_path,
    ensure_directory,
    safe_file_read,
    tag_to_hex,
    hex_to_tag,
    is_private_tag,
    KB,
    MB,
    GB,
    DICOM_DATE_FORMAT,
    DICOM_TIME_FORMAT,
    DICOM_DATETIME_FORMAT,
)


class TestConstants:
    """Test module constants."""

    def test_file_size_constants(self):
        """Test file size constants are correct."""
        assert KB == 1024
        assert MB == 1024 * 1024
        assert GB == 1024 * 1024 * 1024

    def test_dicom_format_constants(self):
        """Test DICOM date/time format constants."""
        assert DICOM_DATE_FORMAT == "%Y%m%d"
        assert DICOM_TIME_FORMAT == "%H%M%S"
        assert DICOM_DATETIME_FORMAT == "%Y%m%d%H%M%S"


class TestValidateFilePath:
    """Tests for validate_file_path function."""

    def test_valid_existing_file(self, tmp_path):
        """Test validation of existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = validate_file_path(test_file, must_exist=True)

        assert result.exists()
        assert result.is_file()
        assert result.is_absolute()

    def test_nonexistent_file_must_exist_false(self, tmp_path):
        """Test nonexistent file with must_exist=False."""
        test_file = tmp_path / "nonexistent.txt"

        result = validate_file_path(test_file, must_exist=False)

        assert isinstance(result, Path)
        assert result.is_absolute()

    def test_nonexistent_file_must_exist_true(self, tmp_path):
        """Test nonexistent file with must_exist=True raises error."""
        test_file = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError, match="File not found"):
            validate_file_path(test_file, must_exist=True)

    def test_directory_path_raises_error(self, tmp_path):
        """Test that directory path raises ValueError."""
        with pytest.raises(ValueError, match="Path is not a file"):
            validate_file_path(tmp_path, must_exist=True)

    def test_max_size_validation_passes(self, tmp_path):
        """Test file within max_size passes."""
        test_file = tmp_path / "small.txt"
        test_file.write_bytes(b"x" * 100)  # 100 bytes

        result = validate_file_path(test_file, max_size=200)

        assert result.exists()

    def test_max_size_validation_fails(self, tmp_path):
        """Test file exceeding max_size raises error."""
        test_file = tmp_path / "large.txt"
        test_file.write_bytes(b"x" * 1000)  # 1000 bytes

        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_file_path(test_file, max_size=500)

    def test_string_path_input(self, tmp_path):
        """Test that string path is accepted."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = validate_file_path(str(test_file))

        assert isinstance(result, Path)
        assert result.exists()

    def test_path_normalization(self, tmp_path):
        """Test path is resolved/normalized."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = validate_file_path(test_file)

        assert result.is_absolute()
        assert result == test_file.resolve()


class TestEnsureDirectory:
    """Tests for ensure_directory function."""

    def test_create_new_directory(self, tmp_path):
        """Test creating new directory."""
        new_dir = tmp_path / "new_directory"

        result = ensure_directory(new_dir)

        assert result.exists()
        assert result.is_dir()

    def test_existing_directory(self, tmp_path):
        """Test ensuring existing directory."""
        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()

        result = ensure_directory(existing_dir)

        assert result.exists()
        assert result.is_dir()

    def test_nested_directory_creation(self, tmp_path):
        """Test creating nested directories."""
        nested_dir = tmp_path / "level1" / "level2" / "level3"

        result = ensure_directory(nested_dir)

        assert result.exists()
        assert result.is_dir()
        assert (tmp_path / "level1").exists()
        assert (tmp_path / "level1" / "level2").exists()

    def test_string_path_input(self, tmp_path):
        """Test string path input."""
        new_dir = tmp_path / "string_dir"

        result = ensure_directory(str(new_dir))

        assert isinstance(result, Path)
        assert result.exists()

    def test_returns_absolute_path(self, tmp_path):
        """Test returned path is absolute."""
        new_dir = tmp_path / "test_dir"

        result = ensure_directory(new_dir)

        assert result.is_absolute()


class TestSafeFileRead:
    """Tests for safe_file_read function."""

    def test_read_binary_file(self, tmp_path):
        """Test reading binary file."""
        test_file = tmp_path / "test.bin"
        test_data = b"binary data content"
        test_file.write_bytes(test_data)

        result = safe_file_read(test_file, binary=True)

        assert result == test_data
        assert isinstance(result, bytes)

    def test_read_text_file(self, tmp_path):
        """Test reading text file."""
        test_file = tmp_path / "test.txt"
        test_data = "text content"
        test_file.write_text(test_data)

        result = safe_file_read(test_file, binary=False)

        assert result == test_data
        assert isinstance(result, str)

    def test_max_size_enforcement(self, tmp_path):
        """Test max_size enforcement."""
        test_file = tmp_path / "large.bin"
        test_file.write_bytes(b"x" * 1000)

        with pytest.raises(ValueError, match="exceeds maximum"):
            safe_file_read(test_file, max_size=500)

    def test_default_max_size(self, tmp_path):
        """Test default max_size (100MB)."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"small file")

        result = safe_file_read(test_file)

        assert isinstance(result, bytes)

    def test_nonexistent_file_raises_error(self, tmp_path):
        """Test reading nonexistent file raises error."""
        test_file = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            safe_file_read(test_file)


class TestTagToHex:
    """Tests for tag_to_hex function."""

    def test_basic_tag_conversion(self):
        """Test basic tag to hex conversion."""
        tag = Tag(0x0008, 0x0016)

        result = tag_to_hex(tag)

        assert result == "(0008, 0016)"

    def test_various_tags(self):
        """Test various tag conversions."""
        test_cases = [
            (Tag(0x0010, 0x0010), "(0010, 0010)"),  # Patient Name
            (Tag(0x0020, 0x000D), "(0020, 000D)"),  # Study Instance UID
            (Tag(0x7FE0, 0x0010), "(7FE0, 0010)"),  # Pixel Data
        ]

        for tag, expected in test_cases:
            assert tag_to_hex(tag) == expected

    def test_uppercase_hex(self):
        """Test hex output is uppercase."""
        tag = Tag(0xabcd, 0xef01)

        result = tag_to_hex(tag)

        assert result == "(ABCD, EF01)"
        assert result.isupper() or "," in result


class TestHexToTag:
    """Tests for hex_to_tag function."""

    def test_parentheses_format(self):
        """Test parsing (0008,0016) format."""
        hex_string = "(0008,0016)"

        result = hex_to_tag(hex_string)

        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_no_parentheses_format(self):
        """Test parsing 00080016 format."""
        hex_string = "00080016"

        result = hex_to_tag(hex_string)

        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_with_spaces(self):
        """Test parsing with spaces."""
        hex_string = "(0008, 0016)"

        result = hex_to_tag(hex_string)

        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_invalid_length(self):
        """Test invalid hex string length raises error."""
        with pytest.raises(ValueError, match="Invalid hex string length"):
            hex_to_tag("0008")

    def test_invalid_hex_characters(self):
        """Test invalid hex characters raise error."""
        with pytest.raises(ValueError, match="Invalid hex string format"):
            hex_to_tag("ZZZZZZZZ")

    def test_uppercase_hex(self):
        """Test uppercase hex is parsed correctly."""
        hex_string = "ABCDEF01"

        result = hex_to_tag(hex_string)

        assert result.group == 0xABCD
        assert result.element == 0xEF01

    def test_lowercase_hex(self):
        """Test lowercase hex is parsed correctly."""
        hex_string = "abcdef01"

        result = hex_to_tag(hex_string)

        assert result.group == 0xABCD
        assert result.element == 0xEF01

    def test_roundtrip_conversion(self):
        """Test tag -> hex -> tag roundtrip."""
        original_tag = Tag(0x0010, 0x0020)

        hex_string = tag_to_hex(original_tag)
        result_tag = hex_to_tag(hex_string)

        assert result_tag == original_tag


class TestIsPrivateTag:
    """Tests for is_private_tag function."""

    def test_standard_tag_not_private(self):
        """Test standard tags are not private."""
        # Standard tags have even group numbers
        tag = Tag(0x0010, 0x0010)  # Patient Name

        result = is_private_tag(tag)

        assert result is False

    def test_private_tag_is_private(self):
        """Test private tags are detected."""
        # Private tags have odd group numbers
        tag = Tag(0x0009, 0x0010)  # Private tag

        result = is_private_tag(tag)

        assert result is True

    def test_various_standard_tags(self):
        """Test various standard tags."""
        standard_tags = [
            Tag(0x0008, 0x0016),  # SOP Class UID
            Tag(0x0020, 0x000D),  # Study Instance UID
            Tag(0x7FE0, 0x0010),  # Pixel Data
        ]

        for tag in standard_tags:
            assert is_private_tag(tag) is False

    def test_various_private_tags(self):
        """Test various private tags."""
        private_tags = [
            Tag(0x0009, 0x0010),
            Tag(0x0019, 0x0010),
            Tag(0x4009, 0x0010),
        ]

        for tag in private_tags:
            assert is_private_tag(tag) is True


class TestIntegrationScenarios:
    """Integration tests for helper functions."""

    def test_file_validation_and_read_workflow(self, tmp_path):
        """Test complete file validation and read workflow."""
        # Create test file
        test_file = tmp_path / "data.bin"
        test_data = b"test data content"
        test_file.write_bytes(test_data)

        # Validate
        validated_path = validate_file_path(test_file, max_size=1 * MB)

        # Read
        content = safe_file_read(validated_path, max_size=1 * MB)

        assert content == test_data

    def test_directory_and_file_creation(self, tmp_path):
        """Test directory creation and file handling."""
        # Ensure nested directory
        output_dir = tmp_path / "output" / "subdir"
        ensure_directory(output_dir)

        # Create file in directory
        output_file = output_dir / "output.txt"
        output_file.write_text("output content")

        # Validate and read
        validated = validate_file_path(output_file)
        content = safe_file_read(validated, binary=False)

        assert content == "output content"

    def test_tag_conversion_workflow(self):
        """Test tag conversion workflow."""
        # Create tag
        original = Tag(0x0010, 0x0010)

        # Convert to hex
        hex_str = tag_to_hex(original)

        # Parse back
        parsed = hex_to_tag(hex_str)

        # Verify roundtrip
        assert parsed == original
        assert is_private_tag(parsed) is False

    def test_private_tag_detection_workflow(self):
        """Test private tag detection workflow."""
        # Test with multiple tag formats
        private_hex = "(0009,0010)"
        standard_hex = "(0010,0010)"

        private_tag = hex_to_tag(private_hex)
        standard_tag = hex_to_tag(standard_hex)

        assert is_private_tag(private_tag) is True
        assert is_private_tag(standard_tag) is False
