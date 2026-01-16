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
            assert result == expected, "Hash mismatch for large file"
            assert len(result) == 64, f"Expected 64 chars, got {len(result)}"
            assert isinstance(result, str), f"Expected str, got {type(result)}"
        finally:
            temp_path.unlink()

    def test_multi_chunk_file_matches_single_read(self):
        """Verify chunked reading produces same hash as single read."""
        # Create file that spans exactly 3 chunks (4KB each) plus partial
        content = b"A" * 4096 + b"B" * 4096 + b"C" * 4096 + b"D" * 1000
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            chunked_result = hash_file(temp_path)
            direct_result = hash_bytes(content)
            assert chunked_result == direct_result, "Chunked vs direct hash mismatch"
            assert len(chunked_result) == 64
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
