"""Comprehensive tests for dicom_fuzzer.utils.identifiers module.

This test suite provides complete coverage of identifier generation utilities.
"""

import re
from datetime import datetime

from dicom_fuzzer.utils.identifiers import (
    generate_campaign_id,
    generate_corpus_entry_id,
    generate_crash_id,
    generate_file_id,
    generate_mutation_id,
    generate_seed_id,
    generate_session_id,
    generate_short_id,
    generate_timestamp_id,
)


class TestGenerateShortId:
    """Test suite for generate_short_id function."""

    def test_default_length(self):
        """Test default length is 8 characters."""
        short_id = generate_short_id()
        assert isinstance(short_id, str)
        assert len(short_id) == 8

    def test_custom_length(self):
        """Test custom length parameter."""
        for length in [4, 8, 12, 16, 32]:
            short_id = generate_short_id(length)
            assert isinstance(short_id, str)
            assert len(short_id) == length

    def test_is_hex_string(self):
        """Test that output is valid hex."""
        short_id = generate_short_id()
        assert len(short_id) > 0
        # All characters should be valid hex
        assert all(c in "0123456789abcdef" for c in short_id)

    def test_uniqueness(self):
        """Test that multiple calls produce unique IDs."""
        ids = [generate_short_id() for _ in range(100)]
        assert len(ids) == 100
        assert len(set(ids)) == 100  # All unique

    def test_minimum_length(self):
        """Test with minimum length."""
        short_id = generate_short_id(1)
        assert isinstance(short_id, str)
        assert len(short_id) == 1


class TestGenerateCampaignId:
    """Test suite for generate_campaign_id function."""

    def test_length(self):
        """Test campaign ID is 8 characters."""
        campaign_id = generate_campaign_id()
        assert isinstance(campaign_id, str)
        assert len(campaign_id) == 8

    def test_is_hex(self):
        """Test campaign ID is valid hex."""
        campaign_id = generate_campaign_id()
        assert len(campaign_id) > 0
        assert all(c in "0123456789abcdef" for c in campaign_id)


class TestGenerateSeedId:
    """Test suite for generate_seed_id function."""

    def test_format(self):
        """Test seed ID format matches 'seed_xxxxxxxx'."""
        seed_id = generate_seed_id()
        assert isinstance(seed_id, str)
        assert seed_id.startswith("seed_")
        assert len(seed_id) == 13  # 'seed_' (5) + 8 hex chars

    def test_hex_suffix(self):
        """Test suffix is valid hex."""
        seed_id = generate_seed_id()
        suffix = seed_id[5:]  # Remove 'seed_' prefix
        assert len(suffix) == 8
        assert all(c in "0123456789abcdef" for c in suffix)


class TestGenerateCorpusEntryId:
    """Test suite for generate_corpus_entry_id function."""

    def test_default_generation(self):
        """Test default generation 0 format."""
        entry_id = generate_corpus_entry_id()
        assert isinstance(entry_id, str)
        assert entry_id.startswith("gen0_")
        assert len(entry_id) == 13  # 'gen0_' (5) + 8 hex chars

    def test_custom_generation(self):
        """Test custom generation numbers."""
        for gen in [0, 1, 5, 10, 100]:
            entry_id = generate_corpus_entry_id(generation=gen)
            assert isinstance(entry_id, str)
            assert entry_id.startswith(f"gen{gen}_")

    def test_hex_suffix(self):
        """Test suffix is valid hex."""
        entry_id = generate_corpus_entry_id(generation=3)
        parts = entry_id.split("_")
        assert len(parts) == 2
        assert len(parts[1]) == 8
        assert all(c in "0123456789abcdef" for c in parts[1])


class TestGenerateTimestampId:
    """Test suite for generate_timestamp_id function."""

    def test_no_prefix(self):
        """Test timestamp ID without prefix."""
        ts_id = generate_timestamp_id()
        assert isinstance(ts_id, str)
        # Should match YYYYMMDD_HHMMSS format
        pattern = r"^\d{8}_\d{6}$"
        assert re.match(pattern, ts_id)

    def test_with_prefix(self):
        """Test timestamp ID with prefix."""
        ts_id = generate_timestamp_id("crash")
        assert isinstance(ts_id, str)
        pattern = r"^crash_\d{8}_\d{6}$"
        assert re.match(pattern, ts_id)

    def test_with_microseconds(self):
        """Test timestamp ID with microseconds."""
        ts_id = generate_timestamp_id("fuzz", include_microseconds=True)
        assert isinstance(ts_id, str)
        # Should match prefix_YYYYMMDD_HHMMSS_microseconds
        pattern = r"^fuzz_\d{8}_\d{6}_\d{6}$"
        assert re.match(pattern, ts_id)

    def test_microseconds_no_prefix(self):
        """Test microseconds without prefix."""
        ts_id = generate_timestamp_id(include_microseconds=True)
        assert isinstance(ts_id, str)
        pattern = r"^\d{8}_\d{6}_\d{6}$"
        assert re.match(pattern, ts_id)

    def test_timestamp_is_current(self):
        """Test that timestamp reflects current time."""
        before = datetime.now()
        ts_id = generate_timestamp_id()
        after = datetime.now()

        # Extract date from ID
        date_str = ts_id[:8]
        parsed_date = datetime.strptime(date_str, "%Y%m%d")

        # Should be same day as before/after
        assert parsed_date.date() == before.date()


class TestGenerateCrashId:
    """Test suite for generate_crash_id function."""

    def test_without_hash(self):
        """Test crash ID without hash suffix."""
        crash_id = generate_crash_id()
        assert isinstance(crash_id, str)
        pattern = r"^crash_\d{8}_\d{6}$"
        assert re.match(pattern, crash_id)

    def test_with_hash(self):
        """Test crash ID with hash suffix."""
        crash_id = generate_crash_id("abcdef1234567890")
        assert isinstance(crash_id, str)
        pattern = r"^crash_\d{8}_\d{6}_abcdef12$"
        assert re.match(pattern, crash_id)

    def test_hash_truncation(self):
        """Test that hash is truncated to 8 characters."""
        long_hash = "a" * 64
        crash_id = generate_crash_id(long_hash)
        assert isinstance(crash_id, str)
        # Should end with first 8 chars of hash
        assert crash_id.endswith("_aaaaaaaa")

    def test_short_hash(self):
        """Test with hash shorter than 8 characters."""
        short_hash = "abc"
        crash_id = generate_crash_id(short_hash)
        assert isinstance(crash_id, str)
        assert "_abc" in crash_id


class TestGenerateFileId:
    """Test suite for generate_file_id function."""

    def test_format(self):
        """Test file ID format includes microseconds."""
        file_id = generate_file_id()
        assert isinstance(file_id, str)
        pattern = r"^fuzz_\d{8}_\d{6}_\d{6}$"
        assert re.match(pattern, file_id)

    def test_uniqueness(self):
        """Test rapid calls produce unique IDs."""
        # Generate many IDs quickly
        ids = [generate_file_id() for _ in range(100)]
        assert len(ids) == 100
        # All should be unique due to microseconds
        assert len(set(ids)) == 100


class TestGenerateSessionId:
    """Test suite for generate_session_id function."""

    def test_default_prefix(self):
        """Test default 'fuzzing_session' prefix."""
        session_id = generate_session_id()
        assert isinstance(session_id, str)
        assert session_id.startswith("fuzzing_session_")
        pattern = r"^fuzzing_session_\d{8}_\d{6}$"
        assert re.match(pattern, session_id)

    def test_custom_prefix(self):
        """Test custom session name."""
        session_id = generate_session_id("coverage_test")
        assert isinstance(session_id, str)
        pattern = r"^coverage_test_\d{8}_\d{6}$"
        assert re.match(pattern, session_id)

    def test_empty_string_uses_default(self):
        """Test empty string falls back to default."""
        session_id = generate_session_id("")
        assert isinstance(session_id, str)
        assert session_id.startswith("fuzzing_session_")


class TestGenerateMutationId:
    """Test suite for generate_mutation_id function."""

    def test_format(self):
        """Test mutation ID format includes microseconds."""
        mutation_id = generate_mutation_id()
        assert isinstance(mutation_id, str)
        pattern = r"^mut_\d{8}_\d{6}_\d{6}$"
        assert re.match(pattern, mutation_id)

    def test_uniqueness(self):
        """Test rapid calls produce unique IDs."""
        ids = [generate_mutation_id() for _ in range(100)]
        assert len(ids) == 100
        assert len(set(ids)) == 100


class TestEdgeCases:
    """Test edge cases and integration scenarios."""

    def test_all_generators_produce_strings(self):
        """Test all generator functions return strings."""
        generators = [
            lambda: generate_short_id(),
            lambda: generate_campaign_id(),
            lambda: generate_seed_id(),
            lambda: generate_corpus_entry_id(),
            lambda: generate_timestamp_id(),
            lambda: generate_crash_id(),
            lambda: generate_file_id(),
            lambda: generate_session_id(),
            lambda: generate_mutation_id(),
        ]

        for gen in generators:
            result = gen()
            assert isinstance(result, str)
            assert len(result) > 0

    def test_no_whitespace_in_ids(self):
        """Test that IDs don't contain whitespace."""
        ids = [
            generate_short_id(),
            generate_campaign_id(),
            generate_seed_id(),
            generate_corpus_entry_id(),
            generate_crash_id("test_hash"),
            generate_file_id(),
            generate_session_id(),
            generate_mutation_id(),
        ]

        for id_val in ids:
            assert " " not in id_val
            assert "\t" not in id_val
            assert "\n" not in id_val

    def test_ids_are_filesystem_safe(self):
        """Test that IDs are safe for filesystem use."""
        unsafe_chars = '<>:"/\\|?*'

        ids = [
            generate_short_id(),
            generate_seed_id(),
            generate_corpus_entry_id(),
            generate_crash_id("test"),
            generate_file_id(),
            generate_session_id("my_session"),
        ]

        for id_val in ids:
            for char in unsafe_chars:
                assert char not in id_val
