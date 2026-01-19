"""Tests for dicom_fuzzer.utils.hashing module.

Tests hash generation utilities for bytes, strings, files, and any values.
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from dicom_fuzzer.utils.hashing import (
    hash_any,
    hash_bytes,
    hash_file,
    hash_file_quick,
    hash_string,
    md5_hash,
    short_hash,
)


class TestHashBytes:
    """Tests for hash_bytes function."""

    def test_returns_hex_string(self):
        """Verify returns hex string."""
        result = hash_bytes(b"test")
        assert isinstance(result, str)
        assert all(c in "0123456789abcdef" for c in result)

    def test_full_hash_length(self):
        """Verify full SHA256 hash is 64 characters."""
        result = hash_bytes(b"test")
        assert isinstance(result, str), f"Expected str, got {type(result)}"
        assert len(result) == 64, f"Expected 64 chars, got {len(result)}"
        assert all(c in "0123456789abcdef" for c in result), "Hash should be hex"

    def test_truncated_hash_length(self):
        """Verify truncated hash has correct length."""
        result = hash_bytes(b"test", length=16)
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_output(self):
        """Verify same input produces same output."""
        data = b"consistent input"
        result1 = hash_bytes(data)
        result2 = hash_bytes(data)
        assert result1 == result2
        assert len(result1) == 64

    def test_different_input_different_hash(self):
        """Verify different inputs produce different hashes."""
        result1 = hash_bytes(b"input1")
        result2 = hash_bytes(b"input2")
        assert result1 != result2
        assert len(result1) == len(result2) == 64

    def test_empty_bytes(self):
        """Verify handles empty bytes."""
        result = hash_bytes(b"")
        assert len(result) == 64
        # SHA256 of empty input is known
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_truncation_prefix(self):
        """Verify truncated hash is prefix of full hash."""
        data = b"test data"
        full_hash = hash_bytes(data)
        truncated = hash_bytes(data, length=16)
        assert full_hash.startswith(truncated)
        assert len(truncated) == 16

    def test_length_zero_returns_full_hash(self):
        """Verify length=0 is treated as None (returns full hash).

        Since 0 is falsy in Python, `if length` evaluates to False,
        so the function returns the full digest.
        """
        result = hash_bytes(b"test", length=0)
        assert len(result) == 64  # Full SHA256 hash


class TestHashString:
    """Tests for hash_string function."""

    def test_returns_hex_string(self):
        """Verify returns hex string."""
        result = hash_string("test")
        assert isinstance(result, str)
        assert all(c in "0123456789abcdef" for c in result)

    def test_matches_encoded_bytes(self):
        """Verify hash matches hash of encoded bytes."""
        text = "hello world"
        string_hash = hash_string(text)
        bytes_hash = hash_bytes(text.encode())
        assert string_hash == bytes_hash

    def test_truncated_length(self):
        """Verify truncation works."""
        result = hash_string("test", length=8)
        assert len(result) == 8
        assert all(c in "0123456789abcdef" for c in result)

    def test_unicode_input(self):
        """Verify handles unicode strings."""
        result = hash_string("日本語テスト")
        assert isinstance(result, str), f"Expected str, got {type(result)}"
        assert len(result) == 64, f"Expected 64 chars, got {len(result)}"
        assert all(c in "0123456789abcdef" for c in result), "Hash should be hex"

    def test_empty_string(self):
        """Verify handles empty string."""
        result = hash_string("")
        assert len(result) == 64
        assert result == hash_bytes(b"")


class TestHashFile:
    """Tests for hash_file function."""

    def test_hashes_file_content(self):
        """Verify hashes file content correctly."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test file content")
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(b"test file content").hexdigest()
            assert result == expected
        finally:
            temp_path.unlink()

    def test_truncated_hash(self):
        """Verify truncation works for file hash."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"content")
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path, length=16)
            assert len(result) == 16
            assert all(c in "0123456789abcdef" for c in result)
        finally:
            temp_path.unlink()

    def test_large_file_chunked_reading(self):
        """Verify large files are handled (chunked reading)."""
        # Create file larger than 4KB chunk size
        large_content = b"x" * 10000
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(large_content)
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(large_content).hexdigest()
            assert result == expected
        finally:
            temp_path.unlink()

    def test_file_not_found_raises(self):
        """Verify FileNotFoundError raised for missing file."""
        with pytest.raises(FileNotFoundError):
            hash_file(Path("/nonexistent/file.txt"))

    def test_empty_file(self):
        """Verify handles empty file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(b"").hexdigest()
            assert result == expected
        finally:
            temp_path.unlink()

    def test_exact_chunk_boundary(self):
        """Verify file exactly at chunk size boundary is hashed correctly.

        Catches mutations to chunk size (4096 -> 4095 or 4097).
        """
        # Exactly one chunk (4096 bytes)
        content = b"a" * 4096
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(content).hexdigest()
            assert result == expected, "Hash mismatch at exact chunk boundary"
        finally:
            temp_path.unlink()

    def test_chunk_boundary_plus_one(self):
        """Verify file at chunk size + 1 is hashed correctly.

        Forces reading into second chunk.
        """
        # One byte more than chunk size
        content = b"b" * 4097
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(content).hexdigest()
            assert result == expected, "Hash mismatch at chunk boundary + 1"
        finally:
            temp_path.unlink()

    def test_content_at_chunk_boundary(self):
        """Verify content at chunk boundaries is included in hash.

        Creates file with marker at 4096 byte boundary to ensure
        both chunks are read and included in hash.
        """
        # First chunk: 4096 'a's, second chunk: MARKER + 'b's
        chunk1 = b"a" * 4096
        marker = b"MARKER"
        chunk2_rest = b"b" * (4096 - len(marker))
        content = chunk1 + marker + chunk2_rest

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(content).hexdigest()
            assert result == expected, "Hash mismatch - marker at chunk boundary not included"
        finally:
            temp_path.unlink()

    def test_multiple_exact_chunks(self):
        """Verify file with exactly N chunks is hashed correctly."""
        # Exactly 3 chunks (12288 bytes)
        content = b"c" * (4096 * 3)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path)
            expected = hashlib.sha256(content).hexdigest()
            assert result == expected, "Hash mismatch for multiple exact chunks"
        finally:
            temp_path.unlink()


class TestHashFileQuick:
    """Tests for hash_file_quick function."""

    def test_default_length(self):
        """Verify default length is 16."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"content")
            temp_path = Path(f.name)

        try:
            result = hash_file_quick(temp_path)
            assert len(result) == 16
            assert isinstance(result, str)
        finally:
            temp_path.unlink()

    def test_custom_length(self):
        """Verify custom length works."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"content")
            temp_path = Path(f.name)

        try:
            result = hash_file_quick(temp_path, length=8)
            assert len(result) == 8
            assert all(c in "0123456789abcdef" for c in result)
        finally:
            temp_path.unlink()

    def test_matches_hash_file_truncated(self):
        """Verify matches truncated hash_file result."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content for comparison")
            temp_path = Path(f.name)

        try:
            quick_result = hash_file_quick(temp_path, length=16)
            full_result = hash_file(temp_path, length=16)
            assert quick_result == full_result
        finally:
            temp_path.unlink()


class TestHashAny:
    """Tests for hash_any function."""

    def test_hash_bytes(self):
        """Verify bytes are hashed directly."""
        data = b"byte data"
        result = hash_any(data)
        expected = hash_bytes(data)
        assert result == expected

    def test_hash_string(self):
        """Verify strings are encoded and hashed."""
        text = "string data"
        result = hash_any(text)
        expected = hash_string(text)
        assert result == expected

    def test_hash_none(self):
        """Verify None is handled specially."""
        result = hash_any(None)
        expected = hash_bytes(b"None")
        assert result == expected

    def test_hash_integer(self):
        """Verify integers use repr()."""
        value = 12345
        result = hash_any(value)
        expected = hash_string(repr(value))
        assert result == expected

    def test_hash_list(self):
        """Verify lists use repr()."""
        value = [1, 2, 3]
        result = hash_any(value)
        expected = hash_string(repr(value))
        assert result == expected

    def test_hash_dict(self):
        """Verify dicts use repr()."""
        value = {"key": "value"}
        result = hash_any(value)
        expected = hash_string(repr(value))
        assert result == expected

    def test_truncated_length(self):
        """Verify truncation works."""
        result = hash_any("test", length=8)
        assert len(result) == 8
        assert all(c in "0123456789abcdef" for c in result)

    def test_type_dispatch_exclusive_branches(self):
        """Verify each type takes its exclusive branch.

        This test catches mutations that swap type branches (e.g., mutating
        `if value is None` to `if value is not None`).
        """
        # None should hash as literal bytes b"None", not as string "None"
        none_hash = hash_any(None)
        bytes_none_hash = hash_any(b"None")
        str_none_hash = hash_any("None")

        # None branch hashes b"None" directly
        # String branch hashes "None".encode() = b"None"
        # So these should be equal
        assert none_hash == str_none_hash, "None should hash same as string 'None'"
        assert none_hash == bytes_none_hash, "None should hash same as bytes b'None'"

    def test_bytes_branch_uses_raw_bytes(self):
        """Verify bytes are hashed directly without encoding.

        Catches mutations that change isinstance(value, bytes) branch.
        """
        # These should produce the same hash since string encodes to same bytes
        data = b"test"
        result = hash_any(data)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected, f"Expected {expected}, got {result}"

    def test_string_branch_encodes_utf8(self):
        """Verify strings are encoded to UTF-8 before hashing.

        Catches mutations that change isinstance(value, str) branch.
        """
        text = "test"
        result = hash_any(text)
        expected = hashlib.sha256(text.encode()).hexdigest()
        assert result == expected, f"Expected {expected}, got {result}"

    def test_fallback_uses_repr(self):
        """Verify non-standard types use repr() for hashing.

        Catches mutations in the else branch.
        """
        value = 42
        result = hash_any(value)
        expected = hashlib.sha256(repr(value).encode()).hexdigest()
        assert result == expected, f"Expected {expected}, got {result}"

    def test_none_vs_bytes_none_vs_str_none_consistency(self):
        """Verify hash consistency across None representations.

        The implementation hashes None as b"None", which is the same
        bytes as "None".encode(). This test documents that behavior.
        """
        # All three should be equal because:
        # - None -> hash_bytes(b"None")
        # - b"None" -> hash_bytes(b"None")
        # - "None" -> hash_string("None") -> hash_bytes("None".encode()) -> hash_bytes(b"None")
        assert hash_any(None) == hash_any(b"None") == hash_any("None")

    def test_bytes_string_equivalence(self):
        """Verify bytes and their string decode produce same hash."""
        data = b"hello world"
        text = data.decode()
        assert hash_any(data) == hash_any(text), "bytes and decoded string should hash same"


class TestShortHash:
    """Tests for short_hash function."""

    def test_returns_16_characters(self):
        """Verify always returns 16 characters."""
        result = short_hash(b"test data")
        assert len(result) == 16
        assert isinstance(result, str)

    def test_hex_characters_only(self):
        """Verify only hex characters in output."""
        result = short_hash(b"test")
        assert all(c in "0123456789abcdef" for c in result)

    def test_matches_hash_bytes_truncated(self):
        """Verify matches hash_bytes with length=16."""
        data = b"comparison test"
        short_result = short_hash(data)
        full_result = hash_bytes(data, length=16)
        assert short_result == full_result

    def test_deterministic(self):
        """Verify same input produces same output."""
        data = b"consistent"
        result1 = short_hash(data)
        result2 = short_hash(data)
        assert result1 == result2
        assert len(result1) == 16


class TestMd5Hash:
    """Tests for md5_hash function."""

    def test_hash_bytes(self):
        """Verify bytes are hashed correctly."""
        data = b"test data"
        result = md5_hash(data)
        expected = hashlib.md5(data, usedforsecurity=False).hexdigest()
        assert result == expected

    def test_hash_string(self):
        """Verify strings are encoded and hashed."""
        text = "test string"
        result = md5_hash(text)
        expected = hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
        assert result == expected

    def test_full_hash_length(self):
        """Verify full MD5 hash is 32 characters."""
        result = md5_hash(b"test")
        assert len(result) == 32
        assert isinstance(result, str)

    def test_truncated_length(self):
        """Verify truncation works."""
        result = md5_hash(b"test", length=8)
        assert len(result) == 8
        assert all(c in "0123456789abcdef" for c in result)

    def test_hex_characters_only(self):
        """Verify only hex characters in output."""
        result = md5_hash(b"test")
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_from_sha256(self):
        """Verify MD5 produces different hash than SHA256."""
        data = b"test data"
        md5_result = md5_hash(data)
        sha256_result = hash_bytes(data)
        # Different lengths and different values
        assert len(md5_result) != len(sha256_result)

    def test_string_bytes_equivalence(self):
        """Verify string and its encoded bytes produce same hash.

        Catches mutations to isinstance(data, str) check.
        """
        text = "test data"
        bytes_result = md5_hash(text.encode())
        string_result = md5_hash(text)
        assert bytes_result == string_result, "String and encoded bytes should hash same"

    def test_type_coercion_explicit(self):
        """Verify type coercion happens correctly.

        Tests that the isinstance check properly routes to encoding.
        """
        # String input should be encoded to UTF-8
        text = "hello"
        result = md5_hash(text)
        expected = hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
        assert result == expected, f"Expected {expected}, got {result}"

        # Bytes input should be used directly
        data = b"hello"
        result = md5_hash(data)
        expected = hashlib.md5(data, usedforsecurity=False).hexdigest()
        assert result == expected, f"Expected {expected}, got {result}"

    def test_unicode_string_encoding(self):
        """Verify unicode strings are properly encoded.

        Catches mutations that might affect UTF-8 encoding.
        """
        text = "日本語テスト"
        result = md5_hash(text)
        expected = hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
        assert result == expected, "Unicode string hash mismatch"
        assert len(result) == 32, f"Expected 32 chars, got {len(result)}"


# =============================================================================
# Mutation-Killing Tests for Surviving Mutations
# These tests specifically target mutations that survived previous testing
# =============================================================================


class TestHashFileMutationKilling:
    """Tests targeting hash_file mutations (mutmut_13, mutmut_14).

    The function has: `return digest[:length] if length else digest`
    Mutations likely change:
    - `if length` to `if not length`
    - `digest[:length]` slicing
    """

    def test_length_none_returns_full_64_chars(self):
        """Verify length=None returns full 64-char hash.

        Catches mutation: `if length` -> `if not length`
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path, length=None)
            assert len(result) == 64, f"None should give 64 chars, got {len(result)}"
        finally:
            temp_path.unlink()

    def test_length_positive_returns_truncated(self):
        """Verify positive length returns truncated hash.

        Catches mutation: `digest[:length]` -> `digest[:None]` or similar
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path, length=8)
            assert len(result) == 8, f"length=8 should give 8 chars, got {len(result)}"

            # Verify it's actually the prefix
            full = hash_file(temp_path, length=None)
            assert result == full[:8], "Truncated should be prefix of full"
        finally:
            temp_path.unlink()

    def test_length_1_returns_single_char(self):
        """Verify length=1 returns single character.

        Catches off-by-one mutations in slicing.
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            result = hash_file(temp_path, length=1)
            assert len(result) == 1, f"length=1 should give 1 char, got {len(result)}"
        finally:
            temp_path.unlink()

    def test_length_64_returns_full_hash(self):
        """Verify length=64 returns full hash (same as None but through truncation)."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            result_64 = hash_file(temp_path, length=64)
            result_none = hash_file(temp_path, length=None)
            assert result_64 == result_none, "length=64 should equal length=None"
            assert len(result_64) == 64
        finally:
            temp_path.unlink()


class TestHashAnyMutationKilling:
    """Tests targeting hash_any mutations (mutmut_3,5,10,12,18,20).

    The function has type dispatch:
    - if value is None: return hash_bytes(b"None", length)
    - elif isinstance(value, bytes): return hash_bytes(value, length)
    - elif isinstance(value, str): return hash_string(value, length)
    - else: return hash_string(repr(value), length)

    Mutations likely swap conditions or change returns.
    """

    def test_none_branch_returns_correct_value(self):
        """Verify None takes its specific branch.

        Catches: `if value is None` -> `if value is not None`
        """
        result = hash_any(None)
        # None should hash as literal bytes b"None"
        expected = hashlib.sha256(b"None").hexdigest()
        assert result == expected, f"None hash mismatch: {result} vs {expected}"

    def test_bytes_branch_vs_repr_branch(self):
        """Verify bytes branch differs from repr branch for same bytes content.

        Catches mutation that routes bytes to repr() branch.
        The repr of b"test" is "b'test'" which would hash differently.
        """
        data = b"test"
        bytes_hash = hash_any(data)

        # If bytes went to repr branch, it would hash repr(b"test") = "b'test'"
        repr_hash = hashlib.sha256(repr(data).encode()).hexdigest()

        # The actual bytes hash
        expected = hashlib.sha256(data).hexdigest()

        assert bytes_hash == expected, "bytes should hash directly"
        assert bytes_hash != repr_hash, "bytes branch should differ from repr branch"

    def test_string_branch_vs_repr_branch(self):
        """Verify string branch differs from repr branch for strings.

        Catches mutation that routes str to repr() branch.
        repr("test") is "'test'" (with quotes) which hashes differently.
        """
        text = "test"
        str_hash = hash_any(text)

        # If string went to repr branch, it would hash repr("test") = "'test'"
        repr_hash = hashlib.sha256(repr(text).encode()).hexdigest()

        # The actual string hash (via encode)
        expected = hashlib.sha256(text.encode()).hexdigest()

        assert str_hash == expected, "string should hash via encode"
        assert str_hash != repr_hash, "string branch should differ from repr branch"

    def test_integer_uses_repr_branch(self):
        """Verify integers use repr() for hashing.

        Catches mutation in else branch.
        """
        value = 42
        result = hash_any(value)
        expected = hashlib.sha256(repr(value).encode()).hexdigest()
        assert result == expected, f"int should use repr: {result} vs {expected}"

    def test_length_passed_through_all_branches(self):
        """Verify length parameter works for all type branches.

        Catches mutations that drop length argument in branches.
        """
        # None branch
        result = hash_any(None, length=8)
        assert len(result) == 8, f"None with length=8: got {len(result)}"

        # Bytes branch
        result = hash_any(b"test", length=8)
        assert len(result) == 8, f"bytes with length=8: got {len(result)}"

        # String branch
        result = hash_any("test", length=8)
        assert len(result) == 8, f"str with length=8: got {len(result)}"

        # Else branch (int)
        result = hash_any(42, length=8)
        assert len(result) == 8, f"int with length=8: got {len(result)}"

    def test_branch_exclusivity_with_truncation(self):
        """Verify branches are exclusive with truncation.

        Tests that each branch returns correct truncated values.
        """
        # Each should give 16 chars and match expected
        none_result = hash_any(None, length=16)
        none_expected = hashlib.sha256(b"None").hexdigest()[:16]
        assert none_result == none_expected

        bytes_result = hash_any(b"data", length=16)
        bytes_expected = hashlib.sha256(b"data").hexdigest()[:16]
        assert bytes_result == bytes_expected

        str_result = hash_any("data", length=16)
        str_expected = hashlib.sha256(b"data").hexdigest()[:16]
        assert str_result == str_expected


class TestMd5HashMutationKilling:
    """Tests targeting md5_hash mutations (mutmut_4,6,7).

    The function has:
    - if isinstance(data, str): data = data.encode()
    - return digest[:length] if length else digest
    """

    def test_length_none_returns_full_32_chars(self):
        """Verify length=None returns full 32-char MD5 hash.

        Catches: `if length` -> `if not length`
        """
        result = md5_hash(b"test", length=None)
        assert len(result) == 32, f"None should give 32 chars, got {len(result)}"

    def test_length_positive_truncates(self):
        """Verify positive length truncates hash.

        Catches mutation in slicing logic.
        """
        result = md5_hash(b"test", length=8)
        assert len(result) == 8, f"length=8 should give 8 chars, got {len(result)}"

        full = md5_hash(b"test", length=None)
        assert result == full[:8], "Truncated should be prefix"

    def test_length_1_single_char(self):
        """Verify length=1 returns single character."""
        result = md5_hash(b"test", length=1)
        assert len(result) == 1, f"length=1 should give 1 char, got {len(result)}"

    def test_string_encoding_occurs(self):
        """Verify string is encoded before hashing.

        Catches: `if isinstance(data, str)` mutation
        """
        text = "test"
        str_result = md5_hash(text)

        # If string wasn't encoded, hashlib.md5(str) would raise TypeError
        # So we verify by comparing with explicit encode
        expected = hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
        assert str_result == expected

    def test_bytes_not_encoded(self):
        """Verify bytes are not double-encoded.

        If bytes went through encode(), we'd get different result.
        """
        data = b"test"
        result = md5_hash(data)
        expected = hashlib.md5(data, usedforsecurity=False).hexdigest()
        assert result == expected

        # If it were encoded, it would hash b"test".encode() which is nonsense
        # but let's verify the hash is what we expect
        assert result == "098f6bcd4621d373cade4e832627b4f6"

    def test_length_32_equals_length_none(self):
        """Verify length=32 gives same result as length=None."""
        result_32 = md5_hash(b"test", length=32)
        result_none = md5_hash(b"test", length=None)
        assert result_32 == result_none
        assert len(result_32) == 32
