"""Comprehensive tests for utils/helpers.py

Tests cover file operations, DICOM utilities, random data generation,
formatting functions, and other utility functions.
"""

import random
import string
import time
from unittest.mock import Mock

import pytest
from pydicom.tag import Tag

from dicom_fuzzer.utils.helpers import (
    DICOM_DATE_FORMAT,
    DICOM_DATETIME_FORMAT,
    DICOM_TIME_FORMAT,
    GB,
    KB,
    MB,
    chunk_list,
    clamp,
    ensure_directory,
    format_bytes,
    format_duration,
    hex_to_tag,
    in_range,
    is_private_tag,
    random_accession_number,
    random_bytes,
    random_dicom_date,
    random_dicom_datetime,
    random_dicom_time,
    random_patient_id,
    random_person_name,
    random_string,
    safe_divide,
    safe_file_read,
    tag_to_hex,
    timing,
    truncate_string,
    validate_file_path,
)

# ============================================================================
# Test Constants
# ============================================================================


class TestConstants:
    """Test module constants."""

    def test_size_constants(self):
        """Test KB, MB, GB constants."""
        assert KB == 1024
        assert MB == 1024 * 1024
        assert GB == 1024 * 1024 * 1024

    def test_date_format_constants(self):
        """Test DICOM date/time format constants."""
        assert DICOM_DATE_FORMAT == "%Y%m%d"
        assert DICOM_TIME_FORMAT == "%H%M%S"
        assert DICOM_DATETIME_FORMAT == "%Y%m%d%H%M%S"


# ============================================================================
# Test File Operations
# ============================================================================


class TestValidateFilePath:
    """Test validate_file_path function."""

    def test_validate_existing_file(self, tmp_path):
        """Test validating existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        result = validate_file_path(test_file, must_exist=True)

        assert result is not None
        assert result == test_file.resolve()

    def test_validate_nonexistent_file_must_exist(self, tmp_path):
        """Test validating nonexistent file when must_exist=True."""
        test_file = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            validate_file_path(test_file, must_exist=True)

    def test_validate_nonexistent_file_optional(self, tmp_path):
        """Test validating nonexistent file when must_exist=False."""
        test_file = tmp_path / "nonexistent.txt"

        result = validate_file_path(test_file, must_exist=False)

        assert result is not None
        assert result == test_file.resolve()

    def test_validate_directory_raises_error(self, tmp_path):
        """Test that validating a directory raises ValueError."""
        with pytest.raises(ValueError, match="not a file"):
            validate_file_path(tmp_path, must_exist=True)

    def test_validate_file_max_size_within_limit(self, tmp_path):
        """Test validating file within max size."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("small content")

        result = validate_file_path(test_file, must_exist=True, max_size=1000)

        assert result is not None
        assert result == test_file.resolve()

    def test_validate_file_exceeds_max_size(self, tmp_path):
        """Test validating file exceeding max size."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("x" * 100)

        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_file_path(test_file, must_exist=True, max_size=50)

    def test_validate_file_exactly_at_max_size(self, tmp_path):
        """Test validating file exactly at max size boundary (should pass)."""
        test_file = tmp_path / "exact.txt"
        test_file.write_bytes(b"x" * 50)  # Exactly 50 bytes

        result = validate_file_path(test_file, must_exist=True, max_size=50)

        assert result is not None, "File at exact max_size should be valid"
        assert result == test_file.resolve()

    def test_validate_file_one_byte_over_max_size(self, tmp_path):
        """Test validating file one byte over max size (should fail)."""
        test_file = tmp_path / "over.txt"
        test_file.write_bytes(b"x" * 51)  # 51 bytes, one over

        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_file_path(test_file, must_exist=True, max_size=50)

    def test_validate_string_path(self, tmp_path):
        """Test validating string path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = validate_file_path(str(test_file), must_exist=True)

        assert result is not None
        assert result == test_file.resolve()


class TestEnsureDirectory:
    """Test ensure_directory function."""

    def test_ensure_existing_directory(self, tmp_path):
        """Test ensuring existing directory."""
        result = ensure_directory(tmp_path)

        assert result is not None
        assert result == tmp_path.resolve()
        assert result.exists()

    def test_ensure_new_directory(self, tmp_path):
        """Test creating new directory."""
        new_dir = tmp_path / "new_dir"

        result = ensure_directory(new_dir)

        assert result is not None
        assert result == new_dir.resolve()
        assert result.exists()
        assert result.is_dir()

    def test_ensure_nested_directory(self, tmp_path):
        """Test creating nested directories."""
        nested = tmp_path / "a" / "b" / "c"

        result = ensure_directory(nested)

        assert result is not None
        assert result == nested.resolve()
        assert result.exists()

    def test_ensure_string_path(self, tmp_path):
        """Test with string path."""
        new_dir = tmp_path / "str_dir"

        result = ensure_directory(str(new_dir))

        assert result is not None
        assert result == new_dir.resolve()
        assert result.exists()


class TestSafeFileRead:
    """Test safe_file_read function."""

    def test_read_binary(self, tmp_path):
        """Test reading file in binary mode."""
        test_file = tmp_path / "test.bin"
        content = b"\x00\x01\x02\x03"
        test_file.write_bytes(content)

        result = safe_file_read(test_file, binary=True)

        assert result is not None
        assert result == content
        assert isinstance(result, bytes)

    def test_read_text(self, tmp_path):
        """Test reading file in text mode."""
        test_file = tmp_path / "test.txt"
        content = "Hello World"
        test_file.write_text(content)

        result = safe_file_read(test_file, binary=False)

        assert result is not None
        assert result == content
        assert isinstance(result, str)

    def test_read_exceeds_max_size(self, tmp_path):
        """Test reading file that exceeds max size."""
        test_file = tmp_path / "large.txt"
        test_file.write_text("x" * 1000)

        with pytest.raises(ValueError, match="exceeds maximum"):
            safe_file_read(test_file, max_size=500)


# ============================================================================
# Test DICOM Tag Operations
# ============================================================================


class TestTagToHex:
    """Test tag_to_hex function."""

    def test_tag_to_hex_basic(self):
        """Test converting tag to hex."""
        tag = Tag(0x0008, 0x0016)

        result = tag_to_hex(tag)

        assert result is not None
        assert isinstance(result, str)
        assert result == "(0008, 0016)"

    def test_tag_to_hex_private(self):
        """Test converting private tag to hex."""
        tag = Tag(0x0009, 0x0010)

        result = tag_to_hex(tag)

        assert result is not None
        assert isinstance(result, str)
        assert result == "(0009, 0010)"

    def test_tag_to_hex_pixel_data(self):
        """Test converting PixelData tag."""
        tag = Tag(0x7FE0, 0x0010)

        result = tag_to_hex(tag)

        assert result is not None
        assert isinstance(result, str)
        assert result == "(7FE0, 0010)"


class TestHexToTag:
    """Test hex_to_tag function."""

    def test_hex_to_tag_parentheses(self):
        """Test parsing hex with parentheses."""
        result = hex_to_tag("(0008,0016)")

        assert result is not None
        assert hasattr(result, "group")
        assert hasattr(result, "element")
        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_hex_to_tag_spaces(self):
        """Test parsing hex with spaces."""
        result = hex_to_tag("( 0008, 0016 )")

        assert result is not None
        assert hasattr(result, "group")
        assert hasattr(result, "element")
        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_hex_to_tag_plain(self):
        """Test parsing plain hex string."""
        result = hex_to_tag("00080016")

        assert result is not None
        assert hasattr(result, "group")
        assert hasattr(result, "element")
        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_hex_to_tag_invalid_length_too_short(self):
        """Test hex string too short (7 chars) raises error."""
        with pytest.raises(ValueError, match="Invalid hex string length"):
            hex_to_tag("0008001")  # 7 chars

    def test_hex_to_tag_invalid_length_too_long(self):
        """Test hex string too long (9 chars) raises error."""
        with pytest.raises(ValueError, match="Invalid hex string length"):
            hex_to_tag("000800160")  # 9 chars

    def test_hex_to_tag_exactly_8_chars_valid(self):
        """Test exactly 8 chars is valid boundary."""
        result = hex_to_tag("00080016")  # Exactly 8 chars
        assert result is not None
        assert result.group == 0x0008
        assert result.element == 0x0016

    def test_hex_to_tag_invalid_hex(self):
        """Test invalid hex characters raise error."""
        with pytest.raises(ValueError, match="Invalid hex string format"):
            hex_to_tag("GGGG0016")


class TestIsPrivateTag:
    """Test is_private_tag function."""

    def test_standard_tag_not_private(self):
        """Test standard tag is not private."""
        tag = Tag(0x0008, 0x0016)

        assert is_private_tag(tag) is False

    def test_private_tag_odd_group(self):
        """Test private tag with odd group number."""
        tag = Tag(0x0009, 0x0010)

        assert is_private_tag(tag) is True

    def test_another_private_tag(self):
        """Test another private tag."""
        tag = Tag(0x0011, 0x1010)

        assert is_private_tag(tag) is True


# ============================================================================
# Test Random Data Generation
# ============================================================================


class TestRandomString:
    """Test random_string function."""

    def test_random_string_length(self):
        """Test random string has correct length."""
        result = random_string(10)

        assert result is not None
        assert isinstance(result, str)
        assert len(result) == 10

    def test_random_string_default_charset(self):
        """Test random string uses alphanumeric by default."""
        result = random_string(100)

        for char in result:
            assert char in string.ascii_letters + string.digits

    def test_random_string_custom_charset(self):
        """Test random string with custom charset."""
        charset = "ABC"
        result = random_string(10, charset=charset)

        for char in result:
            assert char in charset

    def test_random_string_empty(self):
        """Test random string with zero length."""
        result = random_string(0)

        assert result is not None
        assert isinstance(result, str)
        assert result == ""


class TestRandomBytes:
    """Test random_bytes function."""

    def test_random_bytes_length(self):
        """Test random bytes has correct length."""
        result = random_bytes(100)

        assert len(result) == 100
        assert isinstance(result, bytes)

    def test_random_bytes_empty(self):
        """Test random bytes with zero length."""
        result = random_bytes(0)

        assert result is not None
        assert isinstance(result, bytes)
        assert result == b""


class TestRandomDicomDate:
    """Test random_dicom_date function."""

    def test_random_date_format(self):
        """Test random date has correct format."""
        result = random_dicom_date()

        assert result is not None
        assert isinstance(result, str)
        assert len(result) == 8
        assert result.isdigit()

    def test_random_date_range(self):
        """Test random date is within range."""
        result = random_dicom_date(2020, 2020)

        assert result is not None
        assert isinstance(result, str)
        assert result.startswith("2020")

    def test_random_date_default_end_year(self):
        """Test random date uses current year as default end."""
        from datetime import datetime

        result = random_dicom_date(2020)
        year = int(result[:4])

        assert 2020 <= year <= datetime.now().year


class TestRandomDicomTime:
    """Test random_dicom_time function."""

    def test_random_time_format(self):
        """Test random time has correct format."""
        result = random_dicom_time()

        assert result is not None
        assert isinstance(result, str)
        assert len(result) == 6
        assert result.isdigit()

    def test_random_time_valid_values(self):
        """Test random time has valid hour/minute/second."""
        result = random_dicom_time()

        hour = int(result[:2])
        minute = int(result[2:4])
        second = int(result[4:6])

        assert 0 <= hour <= 23
        assert 0 <= minute <= 59
        assert 0 <= second <= 59


class TestRandomDicomDatetime:
    """Test random_dicom_datetime function."""

    def test_random_datetime_format(self):
        """Test random datetime has correct format."""
        result = random_dicom_datetime()

        assert result is not None
        assert isinstance(result, str)
        assert len(result) == 14
        assert result.isdigit()


class TestRandomPersonName:
    """Test random_person_name function."""

    def test_random_name_format(self):
        """Test random name has correct format."""
        result = random_person_name()

        assert result is not None
        assert isinstance(result, str)
        assert "^" in result
        parts = result.split("^")
        assert len(parts) >= 2

    def test_random_name_sometimes_has_middle(self):
        """Test random name sometimes includes middle initial."""
        random.seed(42)
        results = [random_person_name() for _ in range(100)]

        # Some should have 3 parts (with middle initial)
        has_middle = [r for r in results if len(r.split("^")) == 3]
        assert len(has_middle) > 0


class TestRandomPatientId:
    """Test random_patient_id function."""

    def test_random_patient_id_format(self):
        """Test random patient ID format."""
        result = random_patient_id()

        assert result is not None
        assert isinstance(result, str)
        assert result.startswith("PAT")
        assert len(result) == 9  # "PAT" + 6 digits


class TestRandomAccessionNumber:
    """Test random_accession_number function."""

    def test_random_accession_format(self):
        """Test random accession number format."""
        result = random_accession_number()

        assert result is not None
        assert isinstance(result, str)
        assert result.startswith("ACC")
        assert len(result) == 10  # "ACC" + 7 digits


# ============================================================================
# Test Numeric Utilities
# ============================================================================


class TestClamp:
    """Test clamp function."""

    def test_clamp_below_min(self):
        """Test clamping value below minimum."""
        assert clamp(-10, 0, 100) == 0

    def test_clamp_above_max(self):
        """Test clamping value above maximum."""
        assert clamp(150, 0, 100) == 100

    def test_clamp_within_range(self):
        """Test clamping value within range."""
        assert clamp(50, 0, 100) == 50

    def test_clamp_at_min(self):
        """Test clamping value at minimum."""
        assert clamp(0, 0, 100) == 0

    def test_clamp_at_max(self):
        """Test clamping value at maximum."""
        assert clamp(100, 0, 100) == 100

    def test_clamp_float(self):
        """Test clamping float values."""
        assert clamp(0.5, 0.0, 1.0) == 0.5
        assert clamp(-0.5, 0.0, 1.0) == 0.0


class TestInRange:
    """Test in_range function."""

    def test_in_range_inclusive(self):
        """Test inclusive range check."""
        assert in_range(50, 0, 100, inclusive=True) is True
        assert in_range(0, 0, 100, inclusive=True) is True
        assert in_range(100, 0, 100, inclusive=True) is True

    def test_in_range_exclusive(self):
        """Test exclusive range check."""
        assert in_range(50, 0, 100, inclusive=False) is True
        assert in_range(0, 0, 100, inclusive=False) is False
        assert in_range(100, 0, 100, inclusive=False) is False

    def test_out_of_range(self):
        """Test value out of range."""
        assert in_range(-1, 0, 100) is False
        assert in_range(101, 0, 100) is False


class TestSafeDivide:
    """Test safe_divide function."""

    def test_safe_divide_normal(self):
        """Test normal division."""
        assert safe_divide(10, 2) == 5.0

    def test_safe_divide_by_zero(self):
        """Test division by zero returns default."""
        assert safe_divide(10, 0) == 0.0

    def test_safe_divide_custom_default(self):
        """Test division by zero with custom default."""
        assert safe_divide(10, 0, default=-1.0) == -1.0


# ============================================================================
# Test Formatting Functions
# ============================================================================


class TestFormatBytes:
    """Test format_bytes function."""

    def test_format_bytes_bytes(self):
        """Test formatting bytes."""
        result = format_bytes(512)
        assert result is not None
        assert isinstance(result, str)
        assert result == "512 B"

    def test_format_kilobytes(self):
        """Test formatting kilobytes."""
        result = format_bytes(2 * KB)
        assert result is not None
        assert isinstance(result, str)
        assert "2.00 KB" in result

    def test_format_megabytes(self):
        """Test formatting megabytes."""
        result = format_bytes(5 * MB)
        assert result is not None
        assert isinstance(result, str)
        assert "5.00 MB" in result

    def test_format_gigabytes(self):
        """Test formatting gigabytes."""
        result = format_bytes(2 * GB)
        assert result is not None
        assert isinstance(result, str)
        assert "2.00 GB" in result

    def test_format_bytes_boundary_just_under_kb(self):
        """Test boundary just under 1KB stays in bytes."""
        result = format_bytes(KB - 1)  # 1023 bytes
        assert result == "1023 B", f"Expected '1023 B', got '{result}'"
        assert "KB" not in result

    def test_format_bytes_boundary_exactly_kb(self):
        """Test boundary exactly at 1KB switches to KB."""
        result = format_bytes(KB)  # 1024 bytes
        assert "KB" in result, f"Expected KB format, got '{result}'"
        assert "1.00 KB" in result

    def test_format_bytes_boundary_just_under_mb(self):
        """Test boundary just under 1MB stays in KB."""
        result = format_bytes(MB - 1)  # 1048575 bytes
        assert "KB" in result, f"Expected KB format, got '{result}'"
        assert "MB" not in result

    def test_format_bytes_boundary_exactly_mb(self):
        """Test boundary exactly at 1MB switches to MB."""
        result = format_bytes(MB)  # 1048576 bytes
        assert "MB" in result, f"Expected MB format, got '{result}'"
        assert "1.00 MB" in result

    def test_format_bytes_boundary_exactly_gb(self):
        """Test boundary exactly at 1GB switches to GB."""
        result = format_bytes(GB)  # 1073741824 bytes
        assert "GB" in result, f"Expected GB format, got '{result}'"
        assert "1.00 GB" in result

    def test_format_bytes_zero(self):
        """Test zero bytes."""
        result = format_bytes(0)
        assert result == "0 B", f"Expected '0 B', got '{result}'"


class TestFormatDuration:
    """Test format_duration function."""

    def test_format_seconds(self):
        """Test formatting seconds."""
        result = format_duration(30.5)
        assert result is not None
        assert isinstance(result, str)
        assert "30.50s" in result

    def test_format_minutes(self):
        """Test formatting minutes."""
        result = format_duration(90)
        assert result is not None
        assert isinstance(result, str)
        assert "1m" in result

    def test_format_hours(self):
        """Test formatting hours."""
        result = format_duration(3661)
        assert result is not None
        assert isinstance(result, str)
        assert "1h" in result
        assert "1m" in result

    def test_format_duration_boundary_just_under_60(self):
        """Test boundary just under 60 seconds stays in seconds."""
        result = format_duration(59.99)
        assert "s" in result
        assert "m" not in result, f"Expected seconds format, got '{result}'"

    def test_format_duration_boundary_exactly_60(self):
        """Test boundary exactly at 60 seconds switches to minutes."""
        result = format_duration(60)
        assert "m" in result, f"Expected minutes format, got '{result}'"
        assert "1m" in result

    def test_format_duration_boundary_just_under_3600(self):
        """Test boundary just under 3600 seconds stays in minutes."""
        result = format_duration(3599)
        assert "m" in result
        assert "h" not in result, f"Expected minutes format, got '{result}'"

    def test_format_duration_boundary_exactly_3600(self):
        """Test boundary exactly at 3600 seconds switches to hours."""
        result = format_duration(3600)
        assert "h" in result, f"Expected hours format, got '{result}'"
        assert "1h" in result

    def test_format_duration_zero(self):
        """Test zero seconds."""
        result = format_duration(0)
        assert result == "0.00s", f"Expected '0.00s', got '{result}'"


class TestTruncateString:
    """Test truncate_string function."""

    def test_truncate_short_string(self):
        """Test truncating string shorter than max."""
        result = truncate_string("hello", 10)
        assert result is not None
        assert isinstance(result, str)
        assert result == "hello"

    def test_truncate_long_string(self):
        """Test truncating long string."""
        result = truncate_string("hello world", 8)
        assert result is not None
        assert isinstance(result, str)
        assert result == "hello..."
        assert len(result) == 8

    def test_truncate_custom_suffix(self):
        """Test truncating with custom suffix."""
        result = truncate_string("hello world", 9, suffix="!")
        assert result is not None
        assert isinstance(result, str)
        assert result.endswith("!")

    def test_truncate_very_short_max(self):
        """Test truncating with very short max length."""
        result = truncate_string("hello", 2)
        assert result is not None
        assert isinstance(result, str)
        assert result == "he"

    def test_truncate_string_exactly_at_max(self):
        """Test string exactly at max length returns unchanged."""
        result = truncate_string("hello", 5)
        assert result == "hello", "String exactly at max should be unchanged"
        assert "..." not in result

    def test_truncate_string_one_over_max(self):
        """Test string one char over max gets truncated."""
        result = truncate_string("hello!", 5)
        assert len(result) == 5
        assert result.endswith("...")

    def test_truncate_max_equals_suffix_length(self):
        """Test max length equals suffix length (suffix takes all space)."""
        result = truncate_string("hello world", 3, suffix="...")
        # When max_length == len(suffix), truncate_at = 0, so result is just suffix
        assert result == "...", f"Expected '...', got '{result}'"
        assert len(result) == 3

    def test_truncate_max_less_than_suffix_length(self):
        """Test max length less than suffix length (no room for suffix)."""
        result = truncate_string("hello world", 2, suffix="...")
        # When max_length < len(suffix), truncate without suffix
        assert result == "he", f"Expected 'he', got '{result}'"
        assert len(result) == 2

    def test_truncate_max_one_more_than_suffix(self):
        """Test max length is one more than suffix length."""
        result = truncate_string("hello world", 4, suffix="...")
        assert len(result) == 4
        assert result == "h..."  # 1 char + 3 char suffix

    def test_truncate_empty_string(self):
        """Test truncating empty string."""
        result = truncate_string("", 5)
        assert result == "", "Empty string should remain empty"

    def test_truncate_empty_suffix(self):
        """Test truncating with empty suffix."""
        result = truncate_string("hello world", 5, suffix="")
        assert result == "hello"
        assert len(result) == 5


# ============================================================================
# Test Timing Context Manager
# ============================================================================


class TestTiming:
    """Test timing context manager."""

    def test_timing_returns_duration(self):
        """Test timing returns duration."""
        with timing() as t:
            time.sleep(0.01)

        assert "duration_ms" in t
        assert "duration_s" in t
        assert t["duration_ms"] >= 10  # At least 10ms

    def test_timing_with_logger(self):
        """Test timing logs with logger."""
        mock_logger = Mock()

        with timing("test_op", logger=mock_logger) as t:
            pass

        mock_logger.info.assert_called_once()

    def test_timing_with_operation_name(self):
        """Test timing with operation name."""
        mock_logger = Mock()

        with timing("my_operation", logger=mock_logger):
            pass

        call_args = mock_logger.info.call_args
        assert "my_operation" in str(call_args)


# ============================================================================
# Test List Utilities
# ============================================================================


class TestChunkList:
    """Test chunk_list function."""

    def test_chunk_list_even(self):
        """Test chunking list with even division."""
        result = chunk_list([1, 2, 3, 4], 2)

        assert result is not None
        assert isinstance(result, list)
        assert result == [[1, 2], [3, 4]]

    def test_chunk_list_uneven(self):
        """Test chunking list with uneven division."""
        result = chunk_list([1, 2, 3, 4, 5], 2)

        assert result is not None
        assert isinstance(result, list)
        assert result == [[1, 2], [3, 4], [5]]

    def test_chunk_list_single(self):
        """Test chunking with size 1."""
        result = chunk_list([1, 2, 3], 1)

        assert result is not None
        assert isinstance(result, list)
        assert result == [[1], [2], [3]]

    def test_chunk_list_larger_than_list(self):
        """Test chunking with size larger than list."""
        result = chunk_list([1, 2], 5)

        assert result is not None
        assert isinstance(result, list)
        assert result == [[1, 2]]

    def test_chunk_list_empty(self):
        """Test chunking empty list."""
        result = chunk_list([], 3)

        assert result is not None
        assert isinstance(result, list)
        assert result == []
