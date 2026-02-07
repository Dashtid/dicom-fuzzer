"""Shared UID attack constants for format fuzzers.

Malformed and invalid DICOM UIDs used across multiple fuzzer strategies.
DICOM UIDs must be <= 64 chars, numeric components separated by dots,
no leading zeros, no trailing/leading spaces.
"""

# Invalid/malformed UIDs for format violation attacks
INVALID_UIDS: list[str] = [
    "",  # Empty
    "0",  # Single digit
    "1.2.3",  # Too short
    "1" * 65,  # Too long (max 64)
    "1.2.3.4.5.6.7.8.9." + "0" * 50,  # Long but valid-ish format
    "1.2.3.4.5.6.7.8.9.0.a",  # Non-numeric component
    "1.2.abc.3",  # Non-numeric component (short)
    ".1.2.3.4",  # Leading dot
    "1.2.3.4.",  # Trailing dot
    "1..2.3.4",  # Double dot / empty component
    "1.2.3.4.00005",  # Leading zeros
    "0.0.0.0",  # nosec B104 - DICOM UID, not a bind address  # noqa: S104
    "999.999.999.999.999",  # Large components
    "1.2.840.10008.99999999999999999",  # Very large component
    "1.2.3.4\x00",  # Null byte (trailing)
    "1.2.3\x00.4",  # Null byte (embedded)
    "1.2.3.4 ",  # Trailing space
    " 1.2.3.4",  # Leading space
]

# Standard UID tags that fuzzers target for corruption
UID_TAG_NAMES: list[str] = [
    "StudyInstanceUID",
    "SeriesInstanceUID",
    "SOPInstanceUID",
    "SOPClassUID",
    "FrameOfReferenceUID",
    "ReferencedSOPInstanceUID",
]
