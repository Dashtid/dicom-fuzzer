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

    def test_hex_to_tag_invalid_length(self):
        """Test invalid hex length raises error."""
        with pytest.raises(ValueError, match="Invalid hex string length"):
            hex_to_tag("0008001")

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


# ============================================================================
# Mutation-Killing Tests
# These tests use controlled inputs and exact assertions to catch mutations
# ============================================================================


class TestFormatBytesMutationKilling:
    """Exact value tests to catch arithmetic mutations in format_bytes."""

    def test_bytes_exact(self):
        """Test exact byte formatting."""
        assert format_bytes(0) == "0 B"
        assert format_bytes(1) == "1 B"
        assert format_bytes(512) == "512 B"
        assert format_bytes(1023) == "1023 B"

    def test_kb_boundary(self):
        """Test KB boundary - catches size < KB mutation."""
        # Just under KB threshold
        assert format_bytes(1023) == "1023 B"
        # Exactly at KB threshold
        assert format_bytes(1024) == "1.00 KB"
        # Just over KB threshold
        assert format_bytes(1025) == "1.00 KB"

    def test_kb_exact_values(self):
        """Test exact KB calculations."""
        assert format_bytes(2048) == "2.00 KB"
        assert format_bytes(2560) == "2.50 KB"
        assert format_bytes(3072) == "3.00 KB"

    def test_mb_boundary(self):
        """Test MB boundary - catches size < MB mutation."""
        # Just under MB threshold
        assert format_bytes(1048575) == "1024.00 KB"
        # Exactly at MB threshold
        assert format_bytes(1048576) == "1.00 MB"

    def test_mb_exact_values(self):
        """Test exact MB calculations."""
        assert format_bytes(5 * MB) == "5.00 MB"
        assert format_bytes(int(2.5 * MB)) == "2.50 MB"

    def test_gb_boundary(self):
        """Test GB boundary - catches size < GB mutation."""
        # Just under GB threshold
        assert format_bytes(GB - 1) == "1024.00 MB"
        # Exactly at GB threshold
        assert format_bytes(GB) == "1.00 GB"

    def test_gb_exact_values(self):
        """Test exact GB calculations."""
        assert format_bytes(2 * GB) == "2.00 GB"
        assert format_bytes(int(1.5 * GB)) == "1.50 GB"


class TestFormatDurationMutationKilling:
    """Exact value tests to catch arithmetic mutations in format_duration."""

    def test_seconds_exact(self):
        """Test exact second formatting."""
        assert format_duration(0) == "0.00s"
        assert format_duration(30.5) == "30.50s"
        assert format_duration(59.99) == "59.99s"

    def test_minute_boundary(self):
        """Test minute boundary - catches seconds < 60 mutation."""
        assert format_duration(59.99) == "59.99s"
        assert format_duration(60) == "1m 0.0s"
        assert format_duration(60.5) == "1m 0.5s"

    def test_minutes_exact(self):
        """Test exact minute calculations."""
        assert format_duration(90) == "1m 30.0s"
        assert format_duration(120) == "2m 0.0s"
        assert format_duration(150.5) == "2m 30.5s"

    def test_hour_boundary(self):
        """Test hour boundary - catches seconds < 3600 mutation."""
        assert format_duration(3599) == "59m 59.0s"
        assert format_duration(3600) == "1h 0m 0s"
        assert format_duration(3601) == "1h 0m 1s"

    def test_hours_exact(self):
        """Test exact hour calculations."""
        assert format_duration(3661) == "1h 1m 1s"
        assert format_duration(7200) == "2h 0m 0s"
        assert format_duration(7325) == "2h 2m 5s"

    def test_modulo_arithmetic(self):
        """Test modulo operations in hour calculation."""
        # 3723 = 1h 2m 3s = 3600 + 120 + 3
        assert format_duration(3723) == "1h 2m 3s"
        # 7384 = 2h 3m 4s = 7200 + 180 + 4
        assert format_duration(7384) == "2h 3m 4s"


class TestRandomPersonNameMutationKilling:
    """Deterministic tests for random_person_name using controlled random."""

    def test_name_structure_deterministic(self):
        """Test name structure with controlled randomness.

        Function order: first=choice(first_names), last=choice(last_names)
        Returns: "{last}^{first}^{middle}"
        """
        from unittest.mock import patch
        import dicom_fuzzer.utils.helpers as helpers_module

        # Control calls: first_name, last_name, middle_initial
        call_count = [0]
        choices = ["John", "Smith", "X"]  # first, last, middle

        def mock_choice(seq):
            result = choices[call_count[0] % len(choices)]
            call_count[0] += 1
            return result

        # Force middle initial path (random() < 0.3)
        with patch.object(helpers_module.random, "choice", side_effect=mock_choice):
            with patch.object(helpers_module.random, "random", return_value=0.1):
                result = random_person_name()

        # Function returns f"{last}^{first}^{middle}" = "Smith^John^X"
        assert result == "Smith^John^X", f"Expected 'Smith^John^X', got '{result}'"

    def test_name_no_middle(self):
        """Test name without middle initial."""
        from unittest.mock import patch
        import dicom_fuzzer.utils.helpers as helpers_module

        choices = ["Jane", "Johnson"]  # first_name, last_name

        def mock_choice(seq):
            return choices.pop(0) if choices else "X"

        # Force no middle initial (random() >= 0.3)
        with patch.object(helpers_module.random, "choice", side_effect=mock_choice):
            with patch.object(helpers_module.random, "random", return_value=0.5):
                result = random_person_name()

        # Function returns f"{last}^{first}" = "Johnson^Jane"
        assert result == "Johnson^Jane", f"Expected 'Johnson^Jane', got '{result}'"

    def test_name_parts_come_from_lists(self):
        """Verify names come from predefined lists."""
        first_names = {
            "John", "Jane", "Michael", "Sarah", "David",
            "Emma", "James", "Mary", "Robert", "Patricia"
        }
        last_names = {
            "Smith", "Johnson", "Williams", "Brown", "Jones",
            "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"
        }

        for _ in range(50):
            result = random_person_name()
            parts = result.split("^")
            assert parts[0] in last_names, f"Last name '{parts[0]}' not in list"
            assert parts[1] in first_names, f"First name '{parts[1]}' not in list"


class TestRandomDicomDateMutationKilling:
    """Deterministic tests for random_dicom_date."""

    def test_date_arithmetic(self):
        """Test date generation with controlled random values.

        The function works by:
        1. Calculating days_between = (end_date - start_date).days
        2. Calling randint(0, days_between) to get a random day offset
        3. Adding that offset to start_date

        For 2020 (leap year): Jan 1 + 166 days = June 15
        (31 Jan + 29 Feb + 31 Mar + 30 Apr + 31 May + 14 = 166)
        """
        from unittest.mock import patch
        import dicom_fuzzer.utils.helpers as helpers_module

        # Day 166 from Jan 1, 2020 = June 15, 2020
        with patch.object(helpers_module.random, "randint", return_value=166):
            result = random_dicom_date(2020, 2020)

        assert result == "20200615", f"Expected '20200615', got '{result}'"

    def test_date_year_range(self):
        """Test year is within specified range."""
        from unittest.mock import patch
        import dicom_fuzzer.utils.helpers as helpers_module

        # Always return first valid value for year, last for others
        def mock_randint(a, b):
            return a

        with patch.object(helpers_module.random, "randint", side_effect=mock_randint):
            result = random_dicom_date(1990, 2020)

        assert result.startswith("1990"), f"Expected year 1990, got {result[:4]}"

    def test_date_month_day_bounds(self):
        """Test month and day are within valid bounds."""
        for _ in range(50):
            result = random_dicom_date(2020, 2020)
            month = int(result[4:6])
            day = int(result[6:8])
            assert 1 <= month <= 12, f"Month {month} out of range"
            assert 1 <= day <= 31, f"Day {day} out of range"


class TestRandomDicomTimeMutationKilling:
    """Deterministic tests for random_dicom_time."""

    def test_time_arithmetic(self):
        """Test time generation with controlled random values."""
        from unittest.mock import patch
        import dicom_fuzzer.utils.helpers as helpers_module

        randint_values = iter([14, 30, 45])  # hour, minute, second

        with patch.object(helpers_module.random, "randint", side_effect=lambda a, b: next(randint_values)):
            result = random_dicom_time()

        assert result == "143045", f"Expected '143045', got '{result}'"

    def test_time_bounds(self):
        """Test time components are within valid bounds."""
        for _ in range(50):
            result = random_dicom_time()
            hour = int(result[:2])
            minute = int(result[2:4])
            second = int(result[4:6])
            assert 0 <= hour <= 23, f"Hour {hour} out of range"
            assert 0 <= minute <= 59, f"Minute {minute} out of range"
            assert 0 <= second <= 59, f"Second {second} out of range"


class TestRandomBytesMutationKilling:
    """Tests for random_bytes to catch range mutations."""

    def test_bytes_are_in_valid_range(self):
        """Test all bytes are in 0-255 range."""
        result = random_bytes(1000)
        for b in result:
            assert 0 <= b <= 255, f"Byte {b} out of range"

    def test_bytes_distribution(self):
        """Test bytes have reasonable distribution (not all same value)."""
        result = random_bytes(100)
        unique_values = set(result)
        # With 100 random bytes, should have multiple unique values
        assert len(unique_values) > 10, "Random bytes lack diversity"


class TestRandomStringMutationKilling:
    """Tests for random_string to catch length and charset mutations."""

    def test_exact_length(self):
        """Test string has exact requested length."""
        for length in [0, 1, 5, 10, 100]:
            result = random_string(length)
            assert len(result) == length, f"Expected length {length}, got {len(result)}"

    def test_charset_enforcement(self):
        """Test all characters come from charset."""
        charset = "ABC123"
        result = random_string(100, charset=charset)
        for char in result:
            assert char in charset, f"Char '{char}' not in charset"
