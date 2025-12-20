"""Comprehensive tests for dicom_fuzzer.utils.hashing module.

This test suite provides complete coverage of hash utility functions.
"""

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
    """Test suite for hash_bytes function."""

    def test_basic_hash(self):
        """Test basic byte hashing."""
        result = hash_bytes(b"test data")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 full hex length

    def test_deterministic(self):
        """Test that same input produces same hash."""
        data = b"consistent input"
        hash1 = hash_bytes(data)
        hash2 = hash_bytes(data)
        assert hash1 == hash2

    def test_different_inputs_different_hashes(self):
        """Test that different inputs produce different hashes."""
        hash1 = hash_bytes(b"input1")
        hash2 = hash_bytes(b"input2")
        assert hash1 != hash2

    def test_truncation(self):
        """Test hash truncation."""
        result = hash_bytes(b"test", length=16)
        assert len(result) == 16

    def test_various_truncation_lengths(self):
        """Test various truncation lengths."""
        data = b"test data"
        for length in [8, 16, 32, 48, 64]:
            result = hash_bytes(data, length=length)
            assert len(result) == length

    def test_empty_bytes(self):
        """Test hashing empty bytes."""
        result = hash_bytes(b"")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_large_data(self):
        """Test hashing large data."""
        large_data = b"x" * 1_000_000  # 1MB
        result = hash_bytes(large_data)
        assert len(result) == 64

    def test_binary_data(self):
        """Test hashing binary data with all byte values."""
        binary_data = bytes(range(256))
        result = hash_bytes(binary_data)
        assert len(result) == 64


class TestHashString:
    """Test suite for hash_string function."""

    def test_basic_hash(self):
        """Test basic string hashing."""
        result = hash_string("test data")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_matches_bytes_hash(self):
        """Test that string hash matches encoded bytes hash."""
        text = "test string"
        str_hash = hash_string(text)
        bytes_hash = hash_bytes(text.encode())
        assert str_hash == bytes_hash

    def test_truncation(self):
        """Test string hash truncation."""
        result = hash_string("test", length=16)
        assert len(result) == 16

    def test_unicode_strings(self):
        """Test hashing Unicode strings."""
        unicode_str = "Hello World"
        result = hash_string(unicode_str)
        assert len(result) == 64

    def test_empty_string(self):
        """Test hashing empty string."""
        result = hash_string("")
        assert len(result) == 64


class TestHashFile:
    """Test suite for hash_file function."""

    def test_basic_file_hash(self, tmp_path):
        """Test basic file hashing."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test content")

        result = hash_file(test_file)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_deterministic(self, tmp_path):
        """Test that same file produces same hash."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"same content")

        hash1 = hash_file(test_file)
        hash2 = hash_file(test_file)
        assert hash1 == hash2

    def test_matches_content_hash(self, tmp_path):
        """Test file hash matches direct content hash."""
        content = b"test file content"
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(content)

        file_hash = hash_file(test_file)
        content_hash = hash_bytes(content)
        assert file_hash == content_hash

    def test_truncation(self, tmp_path):
        """Test file hash truncation."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"content")

        result = hash_file(test_file, length=16)
        assert len(result) == 16

    def test_large_file(self, tmp_path):
        """Test hashing large file (tests chunked reading)."""
        test_file = tmp_path / "large.bin"
        # Create file larger than chunk size (4096 bytes)
        test_file.write_bytes(b"x" * 100_000)

        result = hash_file(test_file)
        assert len(result) == 64

    def test_nonexistent_file_raises(self, tmp_path):
        """Test that nonexistent file raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            hash_file(nonexistent)

    def test_empty_file(self, tmp_path):
        """Test hashing empty file."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        result = hash_file(test_file)
        # Should match hash of empty bytes
        assert result == hash_bytes(b"")


class TestHashFileQuick:
    """Test suite for hash_file_quick function."""

    def test_basic_hash(self, tmp_path):
        """Test basic quick file hashing."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test content")

        result = hash_file_quick(test_file)
        assert len(result) == 16  # Default truncation

    def test_custom_length(self, tmp_path):
        """Test custom truncation length."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"content")

        result = hash_file_quick(test_file, length=32)
        assert len(result) == 32

    def test_matches_hash_bytes(self, tmp_path):
        """Test quick hash matches truncated hash_bytes."""
        content = b"test content"
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(content)

        quick_hash = hash_file_quick(test_file, length=16)
        bytes_hash = hash_bytes(content, length=16)
        assert quick_hash == bytes_hash


class TestHashAny:
    """Test suite for hash_any function."""

    def test_hash_none(self):
        """Test hashing None value."""
        result = hash_any(None)
        expected = hash_bytes(b"None")
        assert result == expected

    def test_hash_bytes(self):
        """Test hashing bytes directly."""
        data = b"byte data"
        result = hash_any(data)
        expected = hash_bytes(data)
        assert result == expected

    def test_hash_string(self):
        """Test hashing string."""
        text = "string data"
        result = hash_any(text)
        expected = hash_string(text)
        assert result == expected

    def test_hash_integer(self):
        """Test hashing integer (uses repr)."""
        result = hash_any(42)
        expected = hash_string("42")
        assert result == expected

    def test_hash_list(self):
        """Test hashing list (uses repr)."""
        data = [1, 2, 3]
        result = hash_any(data)
        expected = hash_string(repr(data))
        assert result == expected

    def test_hash_dict(self):
        """Test hashing dict (uses repr)."""
        data = {"key": "value"}
        result = hash_any(data)
        expected = hash_string(repr(data))
        assert result == expected

    def test_truncation(self):
        """Test hash_any truncation."""
        result = hash_any("test", length=16)
        assert len(result) == 16

    def test_none_with_truncation(self):
        """Test hashing None with truncation."""
        result = hash_any(None, length=8)
        assert len(result) == 8


class TestShortHash:
    """Test suite for short_hash function."""

    def test_length(self):
        """Test short hash is 16 characters."""
        result = short_hash(b"test data")
        assert len(result) == 16

    def test_deterministic(self):
        """Test short hash is deterministic."""
        data = b"consistent data"
        hash1 = short_hash(data)
        hash2 = short_hash(data)
        assert hash1 == hash2

    def test_is_hex(self):
        """Test short hash is valid hex."""
        result = short_hash(b"test")
        assert all(c in "0123456789abcdef" for c in result)


class TestMd5Hash:
    """Test suite for md5_hash function."""

    def test_bytes_input(self):
        """Test MD5 hash with bytes input."""
        result = md5_hash(b"test data")
        assert isinstance(result, str)
        assert len(result) == 32  # MD5 full hex length

    def test_string_input(self):
        """Test MD5 hash with string input."""
        result = md5_hash("test data")
        assert len(result) == 32

    def test_string_matches_encoded_bytes(self):
        """Test string MD5 matches encoded bytes MD5."""
        text = "test string"
        str_hash = md5_hash(text)
        bytes_hash = md5_hash(text.encode())
        assert str_hash == bytes_hash

    def test_truncation(self):
        """Test MD5 hash truncation."""
        result = md5_hash(b"test", length=16)
        assert len(result) == 16

    def test_deterministic(self):
        """Test MD5 hash is deterministic."""
        data = b"consistent"
        hash1 = md5_hash(data)
        hash2 = md5_hash(data)
        assert hash1 == hash2

    def test_different_from_sha256(self):
        """Test MD5 produces different hash than SHA256."""
        data = b"test data"
        md5 = md5_hash(data)
        sha256 = hash_bytes(data)
        assert md5 != sha256[:32]  # Compare same length


class TestHashCollisions:
    """Test hash uniqueness and collision resistance."""

    def test_no_collisions_in_batch(self):
        """Test no collisions in a batch of random inputs."""
        inputs = [f"input_{i}".encode() for i in range(1000)]
        hashes = [hash_bytes(inp, length=16) for inp in inputs]

        # All hashes should be unique
        assert len(set(hashes)) == len(hashes)

    def test_similar_inputs_different_hashes(self):
        """Test that similar inputs produce different hashes."""
        base = "test_input_"
        hashes = [hash_string(base + str(i)) for i in range(100)]

        assert len(set(hashes)) == 100


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_hash_bytes_with_none_length(self):
        """Test hash_bytes with length=None returns full hash."""
        result = hash_bytes(b"test", length=None)
        assert len(result) == 64  # Full SHA256 hex length

    def test_hash_special_characters(self):
        """Test hashing strings with special characters."""
        special = "Hello\x00World\n\t\r"
        result = hash_string(special)
        assert len(result) == 64

    def test_hash_path_object(self):
        """Test hashing Path object via hash_any."""
        path = Path("/some/path")
        result = hash_any(path)
        expected = hash_string(repr(path))
        assert result == expected
