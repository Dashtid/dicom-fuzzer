"""Hash utilities for fuzzing operations.

Provides standardized functions for generating content hashes used
throughout the fuzzing framework for deduplication, identification,
and integrity verification.
"""

import hashlib
from pathlib import Path
from typing import Any


def hash_bytes(data: bytes, length: int | None = None) -> str:
    """Generate SHA256 hash of byte content.

    Args:
        data: Byte content to hash
        length: Optional length to truncate hash (default: full 64 chars)

    Returns:
        Hex digest string, optionally truncated

    Examples:
        >>> hash_bytes(b"test data")
        'f48dd853...'  # Full 64 char hash

        >>> hash_bytes(b"test data", 16)
        'f48dd853820cec4e'  # Truncated to 16 chars

    """
    digest = hashlib.sha256(data).hexdigest()
    return digest[:length] if length else digest


def hash_string(text: str, length: int | None = None) -> str:
    """Generate SHA256 hash of string content.

    Args:
        text: String content to hash
        length: Optional length to truncate hash (default: full 64 chars)

    Returns:
        Hex digest string, optionally truncated

    Examples:
        >>> hash_string("test data", 16)
        'f48dd853820cec4e'

    """
    return hash_bytes(text.encode(), length)


def hash_file(file_path: Path, length: int | None = None) -> str:
    """Generate SHA256 hash of file content with chunked reading.

    Reads file in 4KB chunks to handle large files efficiently.

    Args:
        file_path: Path to file to hash
        length: Optional length to truncate hash (default: full 64 chars)

    Returns:
        Hex digest string, optionally truncated

    Raises:
        FileNotFoundError: If file does not exist
        PermissionError: If file cannot be read

    Examples:
        >>> hash_file(Path("test.dcm"), 16)
        'a1b2c3d4e5f6g7h8'

    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)

    digest = sha256_hash.hexdigest()
    return digest[:length] if length else digest


def hash_file_quick(file_path: Path, length: int = 16) -> str:
    """Generate quick hash by reading entire file at once.

    Suitable for smaller files where chunked reading overhead isn't needed.

    Args:
        file_path: Path to file to hash
        length: Length to truncate hash (default: 16 chars)

    Returns:
        Truncated hex digest string

    """
    content = file_path.read_bytes()
    return hash_bytes(content, length)


def hash_any(value: Any, length: int | None = None) -> str:
    """Generate hash for any Python value.

    Handles different types appropriately:
    - bytes: Hash directly
    - str: Encode and hash
    - None: Return hash of "None"
    - Other: Use repr() for consistent string representation

    Args:
        value: Any Python value to hash
        length: Optional length to truncate hash

    Returns:
        Hex digest string, optionally truncated

    """
    if value is None:
        return hash_bytes(b"None", length)
    elif isinstance(value, bytes):
        return hash_bytes(value, length)
    elif isinstance(value, str):
        return hash_string(value, length)
    else:
        return hash_string(repr(value), length)


def short_hash(data: bytes) -> str:
    """Generate short 16-character hash for identification.

    Common pattern used for corpus entry IDs, crash hashes, etc.

    Args:
        data: Byte content to hash

    Returns:
        16-character hex string

    """
    return hash_bytes(data, 16)


def md5_hash(data: bytes | str, length: int | None = None) -> str:
    """Generate MD5 hash (for non-security purposes like cache keys).

    MD5 is faster than SHA256 and suitable for:
    - Cache key generation
    - Quick content comparison
    - Non-security-critical deduplication

    Args:
        data: Content to hash (bytes or string)
        length: Optional length to truncate hash

    Returns:
        Hex digest string, optionally truncated

    """
    if isinstance(data, str):
        data = data.encode()
    digest = hashlib.md5(data).hexdigest()
    return digest[:length] if length else digest
