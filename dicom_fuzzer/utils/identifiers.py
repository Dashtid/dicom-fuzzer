"""Identifier generation utilities for fuzzing operations.

Provides standardized functions for generating unique, timestamp-based
identifiers used throughout the fuzzing framework.
"""

import uuid
from datetime import UTC, datetime


def generate_short_id(length: int = 8) -> str:
    """Generate a short unique identifier using UUID4.

    Creates a hex-based unique ID suitable for embedding in file names,
    corpus entry IDs, campaign IDs, etc.

    Args:
        length: Number of hex characters (default 8)

    Returns:
        Short hex string like "a1b2c3d4"

    Examples:
        >>> len(generate_short_id())
        8

        >>> len(generate_short_id(12))
        12

    """
    return uuid.uuid4().hex[:length]


def generate_campaign_id() -> str:
    """Generate a unique campaign identifier.

    Returns:
        Campaign ID - short 8-character hex string

    Examples:
        >>> len(generate_campaign_id())
        8

    """
    return generate_short_id(8)


def generate_seed_id() -> str:
    """Generate a unique seed identifier.

    Returns:
        Seed ID like "seed_a1b2c3d4"

    """
    return f"seed_{generate_short_id(8)}"


def generate_corpus_entry_id(generation: int = 0) -> str:
    """Generate a unique corpus entry identifier.

    Args:
        generation: Mutation generation number (0 for seeds)

    Returns:
        Entry ID like "gen0_a1b2c3d4" or "gen1_b2c3d4e5"

    """
    return f"gen{generation}_{generate_short_id(8)}"


def generate_timestamp_id(prefix: str = "", include_microseconds: bool = False) -> str:
    """Generate timestamp-based unique identifier.

    Creates a consistent timestamp-based ID format used across the fuzzing
    framework for crashes, fuzzed files, and sessions.

    Args:
        prefix: ID prefix (e.g., "crash", "fuzz", "session")
        include_microseconds: Include microseconds for sub-second uniqueness

    Returns:
        Formatted ID string like "crash_20250119_143022" or
        "fuzz_20250119_143022_123456" if include_microseconds=True

    Examples:
        >>> generate_timestamp_id("crash")
        'crash_20250119_143022'

        >>> generate_timestamp_id("fuzz", include_microseconds=True)
        'fuzz_20250119_143022_456789'

        >>> generate_timestamp_id()  # No prefix
        '20250119_143022'

    """
    fmt = "%Y%m%d_%H%M%S_%f" if include_microseconds else "%Y%m%d_%H%M%S"
    timestamp = datetime.now(tz=UTC).strftime(fmt)

    if prefix:
        return f"{prefix}_{timestamp}"
    return timestamp


def generate_crash_id(crash_hash: str | None = None) -> str:
    """Generate a unique crash identifier.

    Args:
        crash_hash: Optional hash string to append (first 8 characters used)

    Returns:
        Crash ID like "crash_20250119_143022_a1b2c3d4"

    Examples:
        >>> generate_crash_id("a1b2c3d4e5f6")
        'crash_20250119_143022_a1b2c3d4'

    """
    crash_id = generate_timestamp_id("crash")

    if crash_hash:
        # Use first 8 characters of hash for brevity
        hash_suffix = crash_hash[:8]
        crash_id = f"{crash_id}_{hash_suffix}"

    return crash_id


def generate_file_id() -> str:
    """Generate a unique fuzzed file identifier.

    Returns:
        File ID like "fuzz_20250119_143022_456789"

    Examples:
        >>> generate_file_id()
        'fuzz_20250119_143022_456789'

    """
    return generate_timestamp_id("fuzz", include_microseconds=True)


def generate_session_id(session_name: str | None = None) -> str:
    """Generate a unique fuzzing session identifier.

    Args:
        session_name: Optional custom session name to prepend

    Returns:
        Session ID like "my_session_20250119_143022" or
        "fuzzing_session_20250119_143022" if no name provided

    Examples:
        >>> generate_session_id("coverage_test")
        'coverage_test_20250119_143022'

        >>> generate_session_id()
        'fuzzing_session_20250119_143022'

    """
    prefix = session_name if session_name else "fuzzing_session"
    return generate_timestamp_id(prefix)


def generate_mutation_id() -> str:
    """Generate a unique mutation identifier.

    Returns:
        Mutation ID like "mut_20250119_143022_456789"

    Examples:
        >>> generate_mutation_id()
        'mut_20250119_143022_456789'

    """
    return generate_timestamp_id("mut", include_microseconds=True)
