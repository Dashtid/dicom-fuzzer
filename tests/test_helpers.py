"""
Comprehensive tests for utility helpers with property-based testing.
"""

import time
from pathlib import Path

import pytest
from hypothesis import given, strategies as st
from pydicom.tag import Tag

from utils.helpers import (
    validate_file_path,
    ensure_directory,
    safe_file_read,
    tag_to_hex,
    hex_to_tag,
    is_private_tag,
    random_string,
    random_bytes,
    random_dicom_date,
    random_dicom_time,
    random_dicom_datetime,
    random_person_name,
    random_patient_id,
    random_accession_number,
    clamp,
    in_range,
    format_bytes,
    format_duration,
    timing,
    chunk_list,
    safe_divide,
    truncate_string,
    KB, MB, GB
)


class TestFileOperations:
    """Test file operation utilities."""

    def test_validate_existing_file(self, small_file):
        """Test validation of existing file."""
        result = validate_file_path(small_file, must_exist=True)
        assert result.exists()
        assert result.is_file()

    def test_validate_nonexistent_file_fails(self, temp_dir):
        """Test validation fails for non-existent file when required."""
        nonexistent = temp_dir / "doesnt_exist.txt"

        with pytest.raises(FileNotFoundError):
            validate_file_path(nonexistent, must_exist=True)

    def test_validate_nonexistent_file_allowed(self, temp_dir):
        """Test validation allows non-existent file when not required."""
        nonexistent = temp_dir / "doesnt_exist.txt"
        result = validate_file_path(nonexistent, must_exist=False)

        assert isinstance(result, Path)

    def test_validate_file_size_limit(self, large_file):
        """Test file size limit validation."""
        # 10 MB file, limit to 5 MB
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_file_path(large_file, must_exist=True, max_size=5 * MB)

    def test_validate_directory_fails(self, temp_dir):
        """Test validation fails for directory."""
        with pytest.raises(ValueError, match="not a file"):
            validate_file_path(temp_dir, must_exist=True)

    def test_ensure_directory_creates(self, temp_dir):
        """Test ensure_directory creates nested directories."""
        new_dir = temp_dir / "level1" / "level2" / "level3"
        result = ensure_directory(new_dir)

        assert result.exists()
        assert result.is_dir()

    def test_ensure_directory_idempotent(self, temp_dir):
        """Test ensure_directory is idempotent."""
        new_dir = temp_dir / "test_dir"
        result1 = ensure_directory(new_dir)
        result2 = ensure_directory(new_dir)

        assert result1 == result2
        assert result1.exists()

    def test_safe_file_read_binary(self, small_file):
        """Test safe binary file reading."""
        content = safe_file_read(small_file, binary=True)

        assert isinstance(content, bytes)
        assert len(content) > 0

    def test_safe_file_read_text(self, small_file):
        """Test safe text file reading."""
        content = safe_file_read(small_file, binary=False)

        assert isinstance(content, str)
        assert "Test content" in content

    def test_safe_file_read_size_limit(self, large_file):
        """Test safe file read respects size limit."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            safe_file_read(large_file, max_size=1 * MB)


class TestDICOMTagOperations:
    """Test DICOM tag utilities."""

    def test_tag_to_hex_format(self):
        """Test tag to hex conversion format."""
        tag = Tag(0x0008, 0x0016)
        result = tag_to_hex(tag)

        assert result == "(0008,0016)"

    def test_hex_to_tag_with_parentheses(self):
        """Test hex string parsing with parentheses."""
        tag = hex_to_tag("(0008,0016)")

        assert tag.group == 0x0008
        assert tag.element == 0x0016

    def test_hex_to_tag_without_parentheses(self):
        """Test hex string parsing without parentheses."""
        tag = hex_to_tag("00080016")

        assert tag.group == 0x0008
        assert tag.element == 0x0016

    def test_hex_to_tag_invalid_length(self):
        """Test hex parsing fails with invalid length."""
        with pytest.raises(ValueError, match="Invalid hex string length"):
            hex_to_tag("0008")

    def test_hex_to_tag_invalid_chars(self):
        """Test hex parsing fails with invalid characters."""
        with pytest.raises(ValueError, match="Invalid hex string format"):
            hex_to_tag("GGGG0016")

    def test_tag_roundtrip(self):
        """Test tag conversion roundtrip."""
        original = Tag(0x0010, 0x0010)
        hex_str = tag_to_hex(original)
        recovered = hex_to_tag(hex_str)

        assert recovered == original

    def test_is_private_tag_odd_group(self):
        """Test private tag detection for odd group numbers."""
        private_tag = Tag(0x0009, 0x0010)
        assert is_private_tag(private_tag) is True

    def test_is_private_tag_even_group(self):
        """Test standard tag detection for even group numbers."""
        standard_tag = Tag(0x0008, 0x0016)
        assert is_private_tag(standard_tag) is False

    @given(st.integers(min_value=0x0000, max_value=0xFFFF))
    def test_private_tag_property(self, group):
        """Property test: private tags always have odd group numbers."""
        tag = Tag(group, 0x0010)
        is_private = is_private_tag(tag)

        assert is_private == (group % 2 == 1)


class TestRandomDataGeneration:
    """Test random data generation utilities."""

    def test_random_string_length(self):
        """Test random string generates correct length."""
        length = 20
        result = random_string(length)

        assert len(result) == length

    @given(st.integers(min_value=1, max_value=100))
    def test_random_string_length_property(self, length):
        """Property test: random string always has correct length."""
        result = random_string(length)
        assert len(result) == length

    def test_random_bytes_length(self):
        """Test random bytes generates correct length."""
        length = 16
        result = random_bytes(length)

        assert len(result) == length
        assert isinstance(result, bytes)

    @given(st.integers(min_value=1, max_value=100))
    def test_random_bytes_length_property(self, length):
        """Property test: random bytes always has correct length."""
        result = random_bytes(length)
        assert len(result) == length

    def test_random_dicom_date_format(self):
        """Test DICOM date format is correct."""
        result = random_dicom_date(1980, 2000)

        assert len(result) == 8
        assert result.isdigit()

        # Parse year, month, day
        year = int(result[:4])
        month = int(result[4:6])
        day = int(result[6:8])

        assert 1980 <= year <= 2000
        assert 1 <= month <= 12
        assert 1 <= day <= 31

    def test_random_dicom_time_format(self):
        """Test DICOM time format is correct."""
        result = random_dicom_time()

        assert len(result) == 6
        assert result.isdigit()

        # Parse hour, minute, second
        hour = int(result[:2])
        minute = int(result[2:4])
        second = int(result[4:6])

        assert 0 <= hour <= 23
        assert 0 <= minute <= 59
        assert 0 <= second <= 59

    def test_random_dicom_datetime_format(self):
        """Test DICOM datetime format is correct."""
        result = random_dicom_datetime(1990, 2010)

        assert len(result) == 14
        assert result.isdigit()

    def test_random_person_name_format(self):
        """Test person name follows DICOM format."""
        result = random_person_name()

        # Should contain at least last^first
        assert '^' in result
        parts = result.split('^')
        assert len(parts) >= 2
        assert all(part.isalpha() for part in parts)

    def test_random_patient_id_format(self):
        """Test patient ID format."""
        result = random_patient_id()

        assert result.startswith("PAT")
        assert len(result) == 9  # PAT + 6 digits
        assert result[3:].isdigit()

    def test_random_accession_number_format(self):
        """Test accession number format."""
        result = random_accession_number()

        assert result.startswith("ACC")
        assert len(result) == 10  # ACC + 7 digits
        assert result[3:].isdigit()


class TestValidationHelpers:
    """Test validation helper functions."""

    def test_clamp_within_range(self):
        """Test clamping value within range."""
        assert clamp(5, 0, 10) == 5

    def test_clamp_below_min(self):
        """Test clamping value below minimum."""
        assert clamp(-5, 0, 10) == 0

    def test_clamp_above_max(self):
        """Test clamping value above maximum."""
        assert clamp(15, 0, 10) == 10

    @given(
        st.floats(allow_nan=False, allow_infinity=False),
        st.floats(allow_nan=False, allow_infinity=False),
        st.floats(allow_nan=False, allow_infinity=False)
    )
    def test_clamp_property(self, value, min_val, max_val):
        """Property test: clamped value is always within bounds."""
        if min_val > max_val:
            min_val, max_val = max_val, min_val

        result = clamp(value, min_val, max_val)

        assert min_val <= result <= max_val

    def test_in_range_inclusive(self):
        """Test inclusive range checking."""
        assert in_range(5, 0, 10, inclusive=True) is True
        assert in_range(0, 0, 10, inclusive=True) is True
        assert in_range(10, 0, 10, inclusive=True) is True
        assert in_range(-1, 0, 10, inclusive=True) is False
        assert in_range(11, 0, 10, inclusive=True) is False

    def test_in_range_exclusive(self):
        """Test exclusive range checking."""
        assert in_range(5, 0, 10, inclusive=False) is True
        assert in_range(0, 0, 10, inclusive=False) is False
        assert in_range(10, 0, 10, inclusive=False) is False


class TestFormattingHelpers:
    """Test formatting helper functions."""

    def test_format_bytes_b(self):
        """Test byte formatting for bytes."""
        assert format_bytes(512) == "512 B"

    def test_format_bytes_kb(self):
        """Test byte formatting for kilobytes."""
        assert format_bytes(1536) == "1.50 KB"

    def test_format_bytes_mb(self):
        """Test byte formatting for megabytes."""
        assert format_bytes(5 * MB) == "5.00 MB"

    def test_format_bytes_gb(self):
        """Test byte formatting for gigabytes."""
        assert format_bytes(2 * GB) == "2.00 GB"

    def test_format_duration_seconds(self):
        """Test duration formatting for seconds."""
        result = format_duration(5.5)
        assert "5.50s" in result

    def test_format_duration_minutes(self):
        """Test duration formatting for minutes."""
        result = format_duration(125.5)
        assert "2m" in result
        assert "5.5s" in result

    def test_format_duration_hours(self):
        """Test duration formatting for hours."""
        result = format_duration(3665.0)
        assert "1h" in result
        assert "1m" in result

    def test_truncate_string_no_truncation(self):
        """Test string truncation when under limit."""
        text = "Short text"
        result = truncate_string(text, 20)

        assert result == text

    def test_truncate_string_with_truncation(self):
        """Test string truncation when over limit."""
        text = "This is a very long text that needs truncation"
        result = truncate_string(text, 20, suffix="...")

        assert len(result) == 20
        assert result.endswith("...")

    @given(st.text(min_size=1), st.integers(min_value=1, max_value=100))
    def test_truncate_string_property(self, text, max_length):
        """Property test: truncated string never exceeds max length."""
        result = truncate_string(text, max_length)
        assert len(result) <= max_length


class TestPerformanceUtilities:
    """Test performance utility functions."""

    def test_timing_context_manager(self):
        """Test timing context manager measures duration."""
        with timing("test_operation") as t:
            time.sleep(0.1)

        assert "duration_ms" in t
        assert "duration_s" in t
        assert t["duration_ms"] >= 100  # At least 100ms
        assert t["duration_s"] >= 0.1   # At least 0.1s

    def test_timing_with_logger(self, tmp_path, reset_structlog):
        """Test timing logs to provided logger."""
        from utils.logger import configure_logging, get_logger

        log_file = tmp_path / "timing.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")

        with timing("test_op", logger=logger):
            time.sleep(0.05)

        # Logger should have logged the timing
        assert log_file.exists()
        content = log_file.read_text()
        assert "test_op" in content

    def test_chunk_list_even_chunks(self):
        """Test list chunking with even division."""
        lst = [1, 2, 3, 4, 5, 6]
        result = chunk_list(lst, 2)

        assert result == [[1, 2], [3, 4], [5, 6]]

    def test_chunk_list_uneven_chunks(self):
        """Test list chunking with remainder."""
        lst = [1, 2, 3, 4, 5]
        result = chunk_list(lst, 2)

        assert result == [[1, 2], [3, 4], [5]]

    def test_chunk_list_empty(self):
        """Test chunking empty list."""
        result = chunk_list([], 2)
        assert result == []

    @given(st.lists(st.integers()), st.integers(min_value=1, max_value=100))
    def test_chunk_list_property(self, lst, chunk_size):
        """Property test: all elements preserved in chunks."""
        chunks = chunk_list(lst, chunk_size)
        flattened = [item for chunk in chunks for item in chunk]

        assert flattened == lst

    def test_safe_divide_normal(self):
        """Test safe division with non-zero denominator."""
        result = safe_divide(10, 2)
        assert result == 5.0

    def test_safe_divide_by_zero(self):
        """Test safe division by zero returns default."""
        result = safe_divide(10, 0, default=0.0)
        assert result == 0.0

    def test_safe_divide_custom_default(self):
        """Test safe division with custom default."""
        result = safe_divide(10, 0, default=-1.0)
        assert result == -1.0

    @given(st.floats(allow_nan=False, allow_infinity=False))
    def test_safe_divide_never_raises(self, numerator):
        """Property test: safe_divide never raises exception."""
        result = safe_divide(numerator, 0.0)
        assert result == 0.0  # Default


class TestIntegration:
    """Integration tests for helper utilities."""

    def test_file_workflow(self, temp_dir):
        """Test complete file operation workflow."""
        # Create directory structure
        nested_dir = temp_dir / "level1" / "level2"
        ensure_directory(nested_dir)

        # Create test file
        test_file = nested_dir / "test.txt"
        test_content = b"Test data"
        test_file.write_bytes(test_content)

        # Validate and read
        validated_path = validate_file_path(test_file, must_exist=True)
        content = safe_file_read(validated_path, binary=True)

        assert content == test_content

    def test_dicom_tag_workflow(self):
        """Test complete DICOM tag operation workflow."""
        # Create tag, convert to hex, parse back
        original_tag = Tag(0x0010, 0x0020)
        hex_representation = tag_to_hex(original_tag)
        parsed_tag = hex_to_tag(hex_representation)

        assert parsed_tag == original_tag
        assert is_private_tag(original_tag) is False

    def test_random_data_workflow(self):
        """Test random data generation workflow."""
        # Generate various random data
        patient_name = random_person_name()
        patient_id = random_patient_id()
        birth_date = random_dicom_date(1950, 2000)
        accession = random_accession_number()

        # Verify all are valid
        assert '^' in patient_name
        assert patient_id.startswith("PAT")
        assert len(birth_date) == 8
        assert accession.startswith("ACC")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
