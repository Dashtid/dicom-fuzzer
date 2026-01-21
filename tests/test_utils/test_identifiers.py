"""Tests for dicom_fuzzer.utils.identifiers module.

Tests unique identifier generation utilities.
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
    """Tests for generate_short_id function."""

    def test_default_length(self):
        """Verify default length is 8 characters."""
        result = generate_short_id()
        assert len(result) == 8
        assert isinstance(result, str)

    def test_custom_length(self):
        """Verify custom length works."""
        result = generate_short_id(length=12)
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_hex_characters_only(self):
        """Verify only hex characters in output."""
        result = generate_short_id()
        assert all(c in "0123456789abcdef" for c in result)
        assert result.islower()

    def test_unique_ids(self):
        """Verify generates unique IDs."""
        ids = {generate_short_id() for _ in range(100)}
        assert len(ids) == 100  # All should be unique

    def test_length_one(self):
        """Verify length=1 works."""
        result = generate_short_id(length=1)
        assert len(result) == 1
        assert result in "0123456789abcdef"

    def test_length_zero(self):
        """Verify length=0 returns empty string."""
        result = generate_short_id(length=0)
        assert result == ""
        assert isinstance(result, str)


class TestGenerateCampaignId:
    """Tests for generate_campaign_id function."""

    def test_returns_8_characters(self):
        """Verify campaign ID is 8 characters."""
        result = generate_campaign_id()
        assert len(result) == 8
        assert isinstance(result, str)

    def test_hex_format(self):
        """Verify hex format."""
        result = generate_campaign_id()
        assert all(c in "0123456789abcdef" for c in result)
        assert result.islower()

    def test_unique_ids(self):
        """Verify generates unique campaign IDs."""
        ids = {generate_campaign_id() for _ in range(50)}
        assert len(ids) == 50


class TestGenerateSeedId:
    """Tests for generate_seed_id function."""

    def test_has_seed_prefix(self):
        """Verify seed_ prefix."""
        result = generate_seed_id()
        assert result.startswith("seed_")
        assert len(result) == 13  # seed_ + 8 hex chars

    def test_correct_format(self):
        """Verify format is seed_XXXXXXXX."""
        result = generate_seed_id()
        assert re.match(r"^seed_[0-9a-f]{8}$", result)

    def test_unique_ids(self):
        """Verify generates unique seed IDs."""
        ids = {generate_seed_id() for _ in range(50)}
        assert len(ids) == 50


class TestGenerateCorpusEntryId:
    """Tests for generate_corpus_entry_id function."""

    def test_default_generation_zero(self):
        """Verify default generation is 0."""
        result = generate_corpus_entry_id()
        assert result.startswith("gen0_")
        assert len(result) == 13  # gen0_ + 8 hex chars

    def test_custom_generation(self):
        """Verify custom generation number."""
        result = generate_corpus_entry_id(generation=5)
        assert result.startswith("gen5_")
        assert len(result) == 13  # gen5_ + 8 hex chars

    def test_correct_format(self):
        """Verify format is genN_XXXXXXXX."""
        result = generate_corpus_entry_id(generation=2)
        assert re.match(r"^gen2_[0-9a-f]{8}$", result)

    def test_unique_ids(self):
        """Verify generates unique entry IDs."""
        ids = {generate_corpus_entry_id() for _ in range(50)}
        assert len(ids) == 50


class TestGenerateTimestampId:
    """Tests for generate_timestamp_id function."""

    def test_no_prefix(self):
        """Verify no prefix returns just timestamp."""
        result = generate_timestamp_id()
        # Format: YYYYMMDD_HHMMSS
        assert re.match(r"^\d{8}_\d{6}$", result)

    def test_with_prefix(self):
        """Verify prefix is prepended."""
        result = generate_timestamp_id(prefix="test")
        assert result.startswith("test_")
        assert re.match(r"^test_\d{8}_\d{6}$", result)
        assert len(result) == 20  # test_ + YYYYMMDD_HHMMSS

    def test_with_microseconds(self):
        """Verify microseconds are included when requested."""
        result = generate_timestamp_id(include_microseconds=True)
        # Format: YYYYMMDD_HHMMSS_FFFFFF
        assert re.match(r"^\d{8}_\d{6}_\d{6}$", result)
        assert len(result) == 22

    def test_with_prefix_and_microseconds(self):
        """Verify prefix and microseconds work together."""
        result = generate_timestamp_id(prefix="fuzz", include_microseconds=True)
        assert re.match(r"^fuzz_\d{8}_\d{6}_\d{6}$", result)
        assert result.startswith("fuzz_")

    def test_timestamp_is_current(self):
        """Verify timestamp reflects current time."""
        now = datetime.now()
        result = generate_timestamp_id()
        date_part = result[:8]
        expected_date = now.strftime("%Y%m%d")
        assert date_part == expected_date
        assert len(result) == 15  # YYYYMMDD_HHMMSS


class TestGenerateCrashId:
    """Tests for generate_crash_id function."""

    def test_has_crash_prefix(self):
        """Verify crash_ prefix."""
        result = generate_crash_id()
        assert result.startswith("crash_")
        assert isinstance(result, str)

    def test_format_without_hash(self):
        """Verify format without hash."""
        result = generate_crash_id()
        assert re.match(r"^crash_\d{8}_\d{6}$", result)
        assert len(result) == 21  # crash_ + YYYYMMDD_HHMMSS

    def test_format_with_hash(self):
        """Verify format with hash appended."""
        result = generate_crash_id(crash_hash="abcdef1234567890")
        assert re.match(r"^crash_\d{8}_\d{6}_[0-9a-f]{8}$", result)
        assert result.endswith("_abcdef12")

    def test_hash_truncated_to_8(self):
        """Verify hash is truncated to 8 characters."""
        long_hash = "a" * 64
        result = generate_crash_id(crash_hash=long_hash)
        assert result.endswith("_aaaaaaaa")
        assert len(result) == 30  # crash_ + timestamp + _ + 8

    def test_short_hash_used_as_is(self):
        """Verify short hash used without padding."""
        short_hash = "abc"
        result = generate_crash_id(crash_hash=short_hash)
        assert result.endswith("_abc")
        assert len(result) == 25  # crash_ + timestamp + _abc


class TestGenerateFileId:
    """Tests for generate_file_id function."""

    def test_has_fuzz_prefix(self):
        """Verify fuzz_ prefix."""
        result = generate_file_id()
        assert result.startswith("fuzz_")
        assert isinstance(result, str)

    def test_includes_microseconds(self):
        """Verify microseconds are included."""
        result = generate_file_id()
        # Format: fuzz_YYYYMMDD_HHMMSS_FFFFFF
        assert re.match(r"^fuzz_\d{8}_\d{6}_\d{6}$", result)
        assert len(result) == 27  # fuzz_ + YYYYMMDD_HHMMSS_FFFFFF

    def test_unique_ids(self):
        """Verify generates unique file IDs."""
        # Even rapid calls should produce unique IDs due to microseconds
        ids = {generate_file_id() for _ in range(100)}
        # Allow some collisions since microsecond precision may not be perfect
        assert len(ids) >= 95


class TestGenerateSessionId:
    """Tests for generate_session_id function."""

    def test_default_prefix(self):
        """Verify default prefix is fuzzing_session."""
        result = generate_session_id()
        assert result.startswith("fuzzing_session_")
        assert isinstance(result, str)

    def test_custom_prefix(self):
        """Verify custom session name is used."""
        result = generate_session_id(session_name="my_test")
        assert result.startswith("my_test_")
        assert len(result) == 23  # my_test_ + YYYYMMDD_HHMMSS

    def test_format(self):
        """Verify format includes timestamp."""
        result = generate_session_id()
        assert re.match(r"^fuzzing_session_\d{8}_\d{6}$", result)
        assert len(result) == 31  # fuzzing_session_ + YYYYMMDD_HHMMSS

    def test_empty_string_name_uses_default(self):
        """Verify empty string uses default prefix."""
        result = generate_session_id(session_name="")
        assert result.startswith("fuzzing_session_")
        assert len(result) == 31


class TestGenerateMutationId:
    """Tests for generate_mutation_id function."""

    def test_has_mut_prefix(self):
        """Verify mut_ prefix."""
        result = generate_mutation_id()
        assert result.startswith("mut_")
        assert isinstance(result, str)

    def test_includes_microseconds(self):
        """Verify microseconds are included."""
        result = generate_mutation_id()
        # Format: mut_YYYYMMDD_HHMMSS_FFFFFF
        assert re.match(r"^mut_\d{8}_\d{6}_\d{6}$", result)
        assert len(result) == 26  # mut_ + YYYYMMDD_HHMMSS_FFFFFF

    def test_unique_ids(self):
        """Verify generates unique mutation IDs."""
        ids = {generate_mutation_id() for _ in range(100)}
        # Allow some collisions since microsecond precision may not be perfect
        assert len(ids) >= 95


# ============================================================================
# Mutation-Killing Tests
# These tests use controlled mocking to verify exact behavior
# ============================================================================


class TestGenerateShortIdMutationKilling:
    """Deterministic tests for generate_short_id."""

    def test_exact_value_with_mocked_uuid(self):
        """Test exact output with controlled UUID."""
        import uuid as uuid_module
        from unittest.mock import patch

        fixed_uuid = uuid_module.UUID("12345678-1234-5678-1234-567812345678")

        with patch(
            "dicom_fuzzer.utils.identifiers.uuid.uuid4", return_value=fixed_uuid
        ):
            result = generate_short_id(8)

        # UUID hex is "12345678123456781234567812345678"
        assert result == "12345678", f"Expected '12345678', got '{result}'"

    def test_slice_length_exact(self):
        """Test that slice length is exactly as specified."""
        import uuid as uuid_module
        from unittest.mock import patch

        fixed_uuid = uuid_module.UUID("abcdef12-3456-7890-abcd-ef1234567890")

        with patch(
            "dicom_fuzzer.utils.identifiers.uuid.uuid4", return_value=fixed_uuid
        ):
            # Test different lengths
            assert generate_short_id(1) == "a"
            assert generate_short_id(4) == "abcd"
            assert generate_short_id(8) == "abcdef12"
            assert generate_short_id(16) == "abcdef1234567890"

    def test_zero_length_returns_empty(self):
        """Test that length=0 returns empty string (slice behavior)."""
        import uuid as uuid_module
        from unittest.mock import patch

        fixed_uuid = uuid_module.UUID("abcdef12-3456-7890-abcd-ef1234567890")

        with patch(
            "dicom_fuzzer.utils.identifiers.uuid.uuid4", return_value=fixed_uuid
        ):
            result = generate_short_id(0)

        assert result == "", f"Expected '', got '{result}'"


class TestGenerateTimestampIdMutationKilling:
    """Deterministic tests for generate_timestamp_id."""

    def test_exact_timestamp_with_mocked_datetime(self):
        """Test exact output with controlled datetime."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            result = generate_timestamp_id()

        assert result == "20240615_103045", (
            f"Expected '20240615_103045', got '{result}'"
        )

    def test_with_microseconds_exact(self):
        """Test exact output with microseconds."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            result = generate_timestamp_id(include_microseconds=True)

        assert result == "20240615_103045_123456", (
            f"Expected '20240615_103045_123456', got '{result}'"
        )

    def test_with_prefix_exact(self):
        """Test exact output with prefix."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            result = generate_timestamp_id(prefix="test")

        assert result == "test_20240615_103045", (
            f"Expected 'test_20240615_103045', got '{result}'"
        )

    def test_prefix_conditional_empty_vs_none(self):
        """Test that empty prefix is treated as falsy (no prefix added)."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            # Empty string should NOT add prefix
            result = generate_timestamp_id(prefix="")
            assert result == "20240615_103045", (
                f"Empty prefix should not add underscore: {result}"
            )

            # Non-empty prefix SHOULD add prefix
            result = generate_timestamp_id(prefix="x")
            assert result == "x_20240615_103045", f"Prefix should be added: {result}"


class TestGenerateCrashIdMutationKilling:
    """Deterministic tests for generate_crash_id."""

    def test_exact_output_with_hash(self):
        """Test exact crash ID with hash."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            result = generate_crash_id(crash_hash="abcdef1234567890")

        assert result == "crash_20240615_103045_abcdef12", f"Got: {result}"

    def test_hash_truncation_exact(self):
        """Test hash is truncated to exactly 8 characters."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            # Long hash - should be truncated
            result = generate_crash_id(crash_hash="x" * 64)
            assert result.endswith("_xxxxxxxx"), f"Hash should be truncated: {result}"

            # Exactly 8 chars - should use as-is
            result = generate_crash_id(crash_hash="12345678")
            assert result.endswith("_12345678"), f"8-char hash should work: {result}"

    def test_empty_hash_not_appended(self):
        """Test empty hash string is not appended.

        The condition 'if crash_hash' should be falsy for empty string.
        """
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            # Empty string should not add hash suffix
            result = generate_crash_id(crash_hash="")
            assert result == "crash_20240615_103045", (
                f"Empty hash should not add suffix: {result}"
            )
            assert not result.endswith("_"), "Should not end with underscore"

    def test_none_hash_not_appended(self):
        """Test None hash is not appended."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            result = generate_crash_id(crash_hash=None)
            assert result == "crash_20240615_103045", (
                f"None hash should not add suffix: {result}"
            )


class TestGenerateSessionIdMutationKilling:
    """Deterministic tests for generate_session_id."""

    def test_empty_name_uses_default(self):
        """Test empty session_name uses default prefix.

        The condition 'session_name if session_name else "fuzzing_session"'
        should use default for empty string.
        """
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            # Empty string should use default
            result = generate_session_id(session_name="")
            assert result.startswith("fuzzing_session_"), (
                f"Empty name should use default: {result}"
            )

            # None should use default
            result = generate_session_id(session_name=None)
            assert result.startswith("fuzzing_session_"), (
                f"None should use default: {result}"
            )

    def test_custom_name_exact(self):
        """Test custom session name produces exact output."""
        from datetime import datetime as dt
        from unittest.mock import patch

        fixed_time = dt(2024, 6, 15, 10, 30, 45, 123456)

        with patch("dicom_fuzzer.utils.identifiers.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time

            result = generate_session_id(session_name="my_test")

        assert result == "my_test_20240615_103045", f"Got: {result}"


class TestGenerateCorpusEntryIdMutationKilling:
    """Deterministic tests for generate_corpus_entry_id."""

    def test_exact_format_with_mocked_uuid(self):
        """Test exact corpus entry ID format."""
        import uuid as uuid_module
        from unittest.mock import patch

        fixed_uuid = uuid_module.UUID("abcdef12-3456-7890-abcd-ef1234567890")

        with patch(
            "dicom_fuzzer.utils.identifiers.uuid.uuid4", return_value=fixed_uuid
        ):
            result = generate_corpus_entry_id(generation=3)

        assert result == "gen3_abcdef12", f"Got: {result}"

    def test_generation_number_in_prefix(self):
        """Test generation number appears correctly."""
        import uuid as uuid_module
        from unittest.mock import patch

        fixed_uuid = uuid_module.UUID("12345678-0000-0000-0000-000000000000")

        with patch(
            "dicom_fuzzer.utils.identifiers.uuid.uuid4", return_value=fixed_uuid
        ):
            assert generate_corpus_entry_id(generation=0).startswith("gen0_")
            assert generate_corpus_entry_id(generation=99).startswith("gen99_")
