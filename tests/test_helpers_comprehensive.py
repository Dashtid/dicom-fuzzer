"""
Comprehensive tests for utils/helpers.py module.

Focuses on critical utility functions for 70%+ coverage.
"""

from pathlib import Path

import pytest
from pydicom.tag import Tag

from dicom_fuzzer.utils.helpers import (
    DICOM_DATE_FORMAT,
    DICOM_DATETIME_FORMAT,
    DICOM_TIME_FORMAT,
    GB,
    KB,
    MB,
    ensure_directory,
    hex_to_tag,
    is_private_tag,
    safe_file_read,
    tag_to_hex,
    validate_file_path,
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
        tag = Tag(0xABCD, 0xEF01)

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


class TestRandomDataGeneration:
    """Tests for random data generation functions."""

    def test_random_bytes(self):
        """Test random bytes generation."""
        from dicom_fuzzer.utils.helpers import random_bytes

        data = random_bytes(100)
        assert isinstance(data, bytes)
        assert len(data) == 100
        # Each byte should be 0-255
        for byte in data:
            assert 0 <= byte <= 255

    def test_random_dicom_date(self):
        """Test random DICOM date generation."""
        from dicom_fuzzer.utils.helpers import random_dicom_date

        date = random_dicom_date(1980, 2000)
        assert isinstance(date, str)
        assert len(date) == 8  # YYYYMMDD

        # Should be valid year
        year = int(date[:4])
        assert 1980 <= year <= 2000

    def test_random_dicom_date_default_end_year(self):
        """Test random DICOM date with default end year."""
        from datetime import datetime

        from dicom_fuzzer.utils.helpers import random_dicom_date

        date = random_dicom_date(1950)
        year = int(date[:4])
        current_year = datetime.now().year
        assert 1950 <= year <= current_year

    def test_random_dicom_time(self):
        """Test random DICOM time generation."""
        from dicom_fuzzer.utils.helpers import random_dicom_time

        time_str = random_dicom_time()
        assert isinstance(time_str, str)
        assert len(time_str) == 6  # HHMMSS

        # Parse and validate components
        hour = int(time_str[:2])
        minute = int(time_str[2:4])
        second = int(time_str[4:6])

        assert 0 <= hour <= 23
        assert 0 <= minute <= 59
        assert 0 <= second <= 59

    def test_random_dicom_datetime(self):
        """Test random DICOM datetime generation."""
        from dicom_fuzzer.utils.helpers import random_dicom_datetime

        datetime_str = random_dicom_datetime(1980, 2000)
        assert isinstance(datetime_str, str)
        assert len(datetime_str) == 14  # YYYYMMDDHHMMSS

    def test_random_person_name(self):
        """Test random person name generation."""
        from dicom_fuzzer.utils.helpers import random_person_name

        name = random_person_name()
        assert isinstance(name, str)
        assert "^" in name  # DICOM format uses ^ separator

        # Should have at least Last^First
        parts = name.split("^")
        assert len(parts) >= 2

    def test_random_patient_id(self):
        """Test random patient ID generation."""
        from dicom_fuzzer.utils.helpers import random_patient_id

        patient_id = random_patient_id()
        assert isinstance(patient_id, str)
        assert patient_id.startswith("PAT")

        # Extract number part
        number = int(patient_id[3:])
        assert 100000 <= number <= 999999

    def test_random_accession_number(self):
        """Test random accession number generation."""
        from dicom_fuzzer.utils.helpers import random_accession_number

        accession = random_accession_number()
        assert isinstance(accession, str)
        assert accession.startswith("ACC")

        # Extract number part
        number = int(accession[3:])
        assert 1000000 <= number <= 9999999


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_clamp_value_in_range(self):
        """Test clamping value already in range."""
        from dicom_fuzzer.utils.helpers import clamp

        assert clamp(5, 0, 10) == 5
        assert clamp(0, 0, 10) == 0
        assert clamp(10, 0, 10) == 10

    def test_clamp_value_below_min(self):
        """Test clamping value below minimum."""
        from dicom_fuzzer.utils.helpers import clamp

        assert clamp(-5, 0, 10) == 0
        assert clamp(-100, 0, 10) == 0

    def test_clamp_value_above_max(self):
        """Test clamping value above maximum."""
        from dicom_fuzzer.utils.helpers import clamp

        assert clamp(15, 0, 10) == 10
        assert clamp(1000, 0, 10) == 10

    def test_in_range_inclusive(self):
        """Test in_range with inclusive bounds."""
        from dicom_fuzzer.utils.helpers import in_range

        assert in_range(5, 0, 10, inclusive=True) is True
        assert in_range(0, 0, 10, inclusive=True) is True
        assert in_range(10, 0, 10, inclusive=True) is True
        assert in_range(-1, 0, 10, inclusive=True) is False
        assert in_range(11, 0, 10, inclusive=True) is False

    def test_in_range_exclusive(self):
        """Test in_range with exclusive bounds."""
        from dicom_fuzzer.utils.helpers import in_range

        assert in_range(5, 0, 10, inclusive=False) is True
        assert in_range(0, 0, 10, inclusive=False) is False
        assert in_range(10, 0, 10, inclusive=False) is False

    def test_format_bytes_small(self):
        """Test formatting small byte sizes."""
        from dicom_fuzzer.utils.helpers import format_bytes

        assert format_bytes(100) == "100 B"
        assert format_bytes(500) == "500 B"

    def test_format_bytes_kilobytes(self):
        """Test formatting kilobyte sizes."""
        from dicom_fuzzer.utils.helpers import KB, format_bytes

        result = format_bytes(1.5 * KB)
        assert "KB" in result
        assert "1.50" in result

    def test_format_bytes_megabytes(self):
        """Test formatting megabyte sizes."""
        from dicom_fuzzer.utils.helpers import MB, format_bytes

        result = format_bytes(2.5 * MB)
        assert "MB" in result
        assert "2.50" in result

    def test_format_bytes_gigabytes(self):
        """Test formatting gigabyte sizes."""
        from dicom_fuzzer.utils.helpers import GB, format_bytes

        result = format_bytes(1.2 * GB)
        assert "GB" in result
        assert "1.20" in result

    def test_format_duration_seconds(self):
        """Test formatting duration in seconds."""
        from dicom_fuzzer.utils.helpers import format_duration

        result = format_duration(45.5)
        assert "45.50s" in result

    def test_format_duration_minutes(self):
        """Test formatting duration in minutes."""
        from dicom_fuzzer.utils.helpers import format_duration

        result = format_duration(125.0)  # 2m 5s
        assert "2m" in result
        assert "5.0s" in result

    def test_format_duration_hours(self):
        """Test formatting duration in hours."""
        from dicom_fuzzer.utils.helpers import format_duration

        result = format_duration(3665.0)  # 1h 1m 5s
        assert "1h" in result
        assert "1m" in result
        assert "5s" in result

    def test_timing_context_manager(self):
        """Test timing context manager."""
        import time

        from dicom_fuzzer.utils.helpers import timing

        with timing("test_operation") as t:
            time.sleep(0.1)

        assert "duration_ms" in t
        assert "duration_s" in t
        assert t["duration_ms"] >= 100  # At least 100ms
        assert t["duration_s"] >= 0.1  # At least 0.1s

    def test_timing_with_exception(self):
        """Test timing context manager with exception."""
        from dicom_fuzzer.utils.helpers import timing

        try:
            with timing("failing_operation") as t:
                raise ValueError("test error")
        except ValueError:
            pass

        # Should still record timing even with exception
        assert "duration_ms" in t
        assert "duration_s" in t

    def test_chunk_list_evenly_divisible(self):
        """Test chunking list with even division."""
        from dicom_fuzzer.utils.helpers import chunk_list

        result = chunk_list([1, 2, 3, 4, 5, 6], 2)
        assert result == [[1, 2], [3, 4], [5, 6]]

    def test_chunk_list_with_remainder(self):
        """Test chunking list with remainder."""
        from dicom_fuzzer.utils.helpers import chunk_list

        result = chunk_list([1, 2, 3, 4, 5], 2)
        assert result == [[1, 2], [3, 4], [5]]

    def test_chunk_list_single_chunk(self):
        """Test chunking list into single chunk."""
        from dicom_fuzzer.utils.helpers import chunk_list

        result = chunk_list([1, 2, 3], 10)
        assert result == [[1, 2, 3]]

    def test_safe_divide_normal(self):
        """Test safe division with normal values."""
        from dicom_fuzzer.utils.helpers import safe_divide

        assert safe_divide(10, 2) == 5.0
        assert safe_divide(7, 2) == 3.5

    def test_safe_divide_by_zero(self):
        """Test safe division by zero."""
        from dicom_fuzzer.utils.helpers import safe_divide

        assert safe_divide(10, 0) == 0.0
        assert safe_divide(10, 0, default=999) == 999

    def test_truncate_string_no_truncation(self):
        """Test truncating string that fits."""
        from dicom_fuzzer.utils.helpers import truncate_string

        result = truncate_string("hello", 10)
        assert result == "hello"

    def test_truncate_string_with_suffix(self):
        """Test truncating string with suffix."""
        from dicom_fuzzer.utils.helpers import truncate_string

        result = truncate_string("hello world", 8)
        assert result == "hello..."
        assert len(result) == 8

    def test_truncate_string_max_length_smaller_than_suffix(self):
        """Test truncating when max_length < suffix length."""
        from dicom_fuzzer.utils.helpers import truncate_string

        result = truncate_string("hello world", 2)
        assert result == "he"
        assert len(result) == 2
