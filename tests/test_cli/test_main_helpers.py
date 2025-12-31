"""Tests for main.py helper functions.

Tests cover pure utility functions: format_file_size, format_duration,
validate_strategy, parse_strategies.
"""

from dicom_fuzzer.cli.main import (
    format_duration,
    format_file_size,
    parse_strategies,
    validate_strategy,
)


class TestFormatFileSize:
    """Test format_file_size function."""

    def test_format_bytes(self):
        """Test formatting bytes (< 1 KB)."""
        assert format_file_size(0) == "0 B"
        assert format_file_size(1) == "1 B"
        assert format_file_size(512) == "512 B"
        assert format_file_size(1023) == "1023 B"

    def test_format_kilobytes(self):
        """Test formatting kilobytes (1 KB - 1 MB)."""
        assert format_file_size(1024) == "1.0 KB"
        assert format_file_size(1536) == "1.5 KB"
        assert format_file_size(10240) == "10.0 KB"
        assert format_file_size(1048575) == "1024.0 KB"

    def test_format_megabytes(self):
        """Test formatting megabytes (1 MB - 1 GB)."""
        assert format_file_size(1048576) == "1.0 MB"
        assert format_file_size(1572864) == "1.5 MB"
        assert format_file_size(104857600) == "100.0 MB"

    def test_format_gigabytes(self):
        """Test formatting gigabytes (>= 1 GB)."""
        assert format_file_size(1073741824) == "1.0 GB"
        assert format_file_size(1610612736) == "1.5 GB"
        assert format_file_size(10737418240) == "10.0 GB"

    def test_format_edge_cases(self):
        """Test edge cases at boundaries."""
        # Just under 1 KB
        assert format_file_size(1023) == "1023 B"
        # Exactly 1 KB
        assert format_file_size(1024) == "1.0 KB"
        # Just under 1 MB
        assert "KB" in format_file_size(1048575)
        # Exactly 1 MB
        assert format_file_size(1048576) == "1.0 MB"


class TestFormatDuration:
    """Test format_duration function."""

    def test_format_seconds_only(self):
        """Test formatting durations under 1 minute."""
        assert format_duration(0) == "0s"
        assert format_duration(1) == "1s"
        assert format_duration(30) == "30s"
        assert format_duration(59) == "59s"

    def test_format_minutes_seconds(self):
        """Test formatting durations between 1 minute and 1 hour."""
        assert format_duration(60) == "1m 0s"
        assert format_duration(90) == "1m 30s"
        assert format_duration(125) == "2m 5s"
        assert format_duration(3599) == "59m 59s"

    def test_format_hours_minutes_seconds(self):
        """Test formatting durations over 1 hour."""
        assert format_duration(3600) == "1h 0m 0s"
        assert format_duration(3661) == "1h 1m 1s"
        assert format_duration(7325) == "2h 2m 5s"
        assert format_duration(86400) == "24h 0m 0s"

    def test_format_fractional_seconds(self):
        """Test that fractional seconds are truncated."""
        assert format_duration(1.5) == "1s"
        assert format_duration(59.9) == "59s"
        assert format_duration(90.7) == "1m 30s"


class TestValidateStrategy:
    """Test validate_strategy function."""

    def test_valid_strategies(self):
        """Test valid strategy names."""
        valid = ["metadata", "header", "pixel", "structure"]
        for strategy in valid:
            assert validate_strategy(strategy, valid) is True

    def test_invalid_strategy(self):
        """Test invalid strategy name."""
        valid = ["metadata", "header", "pixel", "structure"]
        assert validate_strategy("invalid", valid) is False
        assert validate_strategy("", valid) is False
        assert validate_strategy("METADATA", valid) is False  # Case sensitive

    def test_all_keyword(self):
        """Test 'all' special keyword."""
        valid = ["metadata", "header", "pixel", "structure"]
        assert validate_strategy("all", valid) is True

    def test_empty_valid_list(self):
        """Test with empty valid strategies list."""
        assert validate_strategy("metadata", []) is False
        assert validate_strategy("all", []) is True  # 'all' is always valid


class TestParseStrategies:
    """Test parse_strategies function."""

    def test_parse_single_strategy(self):
        """Test parsing single strategy."""
        assert parse_strategies("metadata") == ["metadata"]
        assert parse_strategies("header") == ["header"]
        assert parse_strategies("pixel") == ["pixel"]
        assert parse_strategies("structure") == ["structure"]

    def test_parse_multiple_strategies(self):
        """Test parsing comma-separated strategies."""
        result = parse_strategies("metadata,header")
        assert "metadata" in result
        assert "header" in result
        assert len(result) == 2

    def test_parse_all_strategies(self):
        """Test parsing all valid strategies."""
        result = parse_strategies("metadata,header,pixel,structure")
        assert len(result) == 4

    def test_parse_with_whitespace(self):
        """Test parsing with extra whitespace."""
        result = parse_strategies("metadata, header , pixel")
        assert "metadata" in result
        assert "header" in result
        assert "pixel" in result

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        assert parse_strategies("") == []
        assert parse_strategies("   ") == []

    def test_parse_none(self):
        """Test parsing None input."""
        assert parse_strategies(None) == []

    def test_parse_invalid_warns(self, capsys):
        """Test that invalid strategies produce warnings."""
        result = parse_strategies("metadata,invalid,header")

        # Valid strategies should be returned
        assert "metadata" in result
        assert "header" in result

        # Invalid strategy should be filtered out
        assert "invalid" not in result

        # Warning should be printed
        captured = capsys.readouterr()
        assert "invalid" in captured.out.lower() or "warning" in captured.out.lower()

    def test_parse_case_insensitive(self):
        """Test that strategy names are lowercased."""
        result = parse_strategies("METADATA,Header,PIXEL")
        assert "metadata" in result
        assert "header" in result
        assert "pixel" in result

    def test_parse_duplicates(self):
        """Test that duplicates are preserved."""
        result = parse_strategies("metadata,metadata,header")
        # The function doesn't deduplicate - it just filters invalid
        assert result.count("metadata") == 2


class TestParseStrategiesEdgeCases:
    """Edge case tests for parse_strategies."""

    def test_parse_all_only_invalid(self, capsys):
        """Test with only invalid strategies."""
        result = parse_strategies("invalid1,invalid2,invalid3")
        assert result == []
        captured = capsys.readouterr()
        # Should warn about each invalid strategy
        assert "invalid" in captured.out.lower() or "warning" in captured.out.lower()

    def test_parse_mixed_valid_invalid(self, capsys):
        """Test mixed valid and invalid with correct filtering."""
        result = parse_strategies("metadata,invalid,header,unknown")
        assert "metadata" in result
        assert "header" in result
        assert "invalid" not in result
        assert "unknown" not in result
        assert len(result) == 2

    def test_parse_trailing_comma(self):
        """Test handling of trailing comma."""
        result = parse_strategies("metadata,header,")
        # Empty string after comma should be filtered
        assert "metadata" in result
        assert "header" in result
        assert "" not in result

    def test_parse_leading_comma(self):
        """Test handling of leading comma."""
        result = parse_strategies(",metadata,header")
        assert "metadata" in result
        assert "header" in result
        assert "" not in result

    def test_parse_multiple_commas(self):
        """Test handling of multiple consecutive commas."""
        result = parse_strategies("metadata,,header")
        assert "metadata" in result
        assert "header" in result


class TestFormatFileSizeEdgeCases:
    """Edge case tests for format_file_size."""

    def test_very_large_values(self):
        """Test with terabyte-scale values."""
        # 1 TB = 1024^4 bytes
        tb = 1024 * 1024 * 1024 * 1024
        result = format_file_size(tb)
        # Should show as 1024 GB (or possibly TB if supported)
        assert "1024" in result or "1.0" in result
        assert "GB" in result or "TB" in result

    def test_very_large_tb_values(self):
        """Test with multi-terabyte values."""
        # 5 TB
        five_tb = 5 * 1024 * 1024 * 1024 * 1024
        result = format_file_size(five_tb)
        assert "GB" in result or "TB" in result

    def test_format_small_fractions(self):
        """Test precision with small values."""
        # 1.5 KB exactly
        assert format_file_size(1536) == "1.5 KB"
        # 1.25 KB - check formatting
        result = format_file_size(1280)
        assert "KB" in result
