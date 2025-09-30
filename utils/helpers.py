"""
DICOM Fuzzer Utility Helpers

Common utility functions for file operations, DICOM manipulation,
random data generation, and validation.
"""

import random
import string
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, List, Optional, Union

from pydicom.tag import Tag

# File size constants
KB = 1024
MB = KB * 1024
GB = MB * 1024

# DICOM date/time formats
DICOM_DATE_FORMAT = "%Y%m%d"
DICOM_TIME_FORMAT = "%H%M%S"
DICOM_DATETIME_FORMAT = "%Y%m%d%H%M%S"


def validate_file_path(
    file_path: Union[str, Path], must_exist: bool = True, max_size: Optional[int] = None
) -> Path:
    """Validate and normalize file path.

    Args:
        file_path: Path to validate
        must_exist: Whether file must exist
        max_size: Maximum allowed file size in bytes

    Returns:
        Normalized Path object

    Raises:
        FileNotFoundError: If must_exist=True and file doesn't exist
        ValueError: If file exceeds max_size
    """
    path = Path(file_path).resolve()

    if must_exist and not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.exists() and not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    if max_size is not None and path.exists():
        file_size = path.stat().st_size
        if file_size > max_size:
            raise ValueError(f"File size {file_size} exceeds maximum {max_size} bytes")

    return path


def ensure_directory(dir_path: Union[str, Path]) -> Path:
    """Ensure directory exists, create if necessary.

    Args:
        dir_path: Directory path to ensure

    Returns:
        Normalized Path object
    """
    path = Path(dir_path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_file_read(
    file_path: Union[str, Path], max_size: int = 100 * MB, binary: bool = True
) -> Union[bytes, str]:
    """Safely read file with size validation.

    Args:
        file_path: Path to file
        max_size: Maximum allowed file size
        binary: Whether to read in binary mode

    Returns:
        File contents as bytes or string

    Raises:
        ValueError: If file exceeds max_size
    """
    path = validate_file_path(file_path, must_exist=True, max_size=max_size)

    mode = "rb" if binary else "r"
    with open(path, mode) as f:
        return f.read()


def tag_to_hex(tag: Tag) -> str:
    """Convert DICOM tag to hex string format.

    Args:
        tag: DICOM Tag object

    Returns:
        Hex string like "(0008,0016)"

    Example:
        >>> tag = Tag(0x0008, 0x0016)
        >>> tag_to_hex(tag)
        '(0008,0016)'
    """
    return f"({tag.group:04X}, {tag.element:04X})"


def hex_to_tag(hex_string: str) -> Tag:
    """Parse hex string to DICOM tag.

    Args:
        hex_string: Hex string like "(0008,0016)" or "00080016"

    Returns:
        DICOM Tag object

    Raises:
        ValueError: If string format is invalid
    """
    hex_string = hex_string.strip()

    # Remove parentheses and comma if present
    hex_string = hex_string.replace("(", "").replace(")", "").replace(",", "")

    if len(hex_string) != 8:
        raise ValueError(f"Invalid hex string length: {hex_string}")

    try:
        group = int(hex_string[:4], 16)
        element = int(hex_string[4:], 16)
        return Tag(group, element)
    except ValueError as e:
        raise ValueError(f"Invalid hex string format: {hex_string}") from e


def is_private_tag(tag: Tag) -> bool:
    """Check if DICOM tag is a private tag.

    Args:
        tag: DICOM Tag object

    Returns:
        True if tag is private (odd group number)
    """
    return tag.group % 2 == 1


def random_string(
    length: int, charset: str = string.ascii_letters + string.digits
) -> str:
    """Generate random string.

    Args:
        length: Length of string to generate
        charset: Character set to use

    Returns:
        Random string
    """
    return "".join(random.choices(charset, k=length))


def random_bytes(length: int) -> bytes:
    """Generate random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes
    """
    return bytes(random.randint(0, 255) for _ in range(length))


def random_dicom_date(start_year: int = 1950, end_year: Optional[int] = None) -> str:
    """Generate random DICOM date string.

    Args:
        start_year: Start of date range
        end_year: End of date range (default: current year)

    Returns:
        Date string in DICOM format (YYYYMMDD)

    Example:
        >>> date = random_dicom_date(1980, 2000)
        >>> len(date)
        8
    """
    if end_year is None:
        end_year = datetime.now().year

    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)

    days_between = (end_date - start_date).days
    random_days = random.randint(0, days_between)

    random_date = start_date + timedelta(days=random_days)
    return random_date.strftime(DICOM_DATE_FORMAT)


def random_dicom_time() -> str:
    """Generate random DICOM time string.

    Returns:
        Time string in DICOM format (HHMMSS)
    """
    hour = random.randint(0, 23)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)

    return f"{hour:02d}{minute:02d}{second:02d}"


def random_dicom_datetime(
    start_year: int = 1950, end_year: Optional[int] = None
) -> str:
    """Generate random DICOM datetime string.

    Args:
        start_year: Start of date range
        end_year: End of date range (default: current year)

    Returns:
        Datetime string in DICOM format (YYYYMMDDHHMMSS)
    """
    date = random_dicom_date(start_year, end_year)
    time = random_dicom_time()
    return date + time


def random_person_name() -> str:
    """Generate random DICOM person name.

    Returns:
        Person name in DICOM format (LastName^FirstName^Middle^Prefix^Suffix)
    """
    first_names = [
        "John",
        "Jane",
        "Michael",
        "Sarah",
        "David",
        "Emma",
        "James",
        "Mary",
        "Robert",
        "Patricia",
    ]
    last_names = [
        "Smith",
        "Johnson",
        "Williams",
        "Brown",
        "Jones",
        "Garcia",
        "Miller",
        "Davis",
        "Rodriguez",
        "Martinez",
    ]

    first = random.choice(first_names)
    last = random.choice(last_names)

    # Sometimes add middle initial
    if random.random() < 0.3:
        middle = random.choice(string.ascii_uppercase)
        return f"{last}^{first}^{middle}"

    return f"{last}^{first}"


def random_patient_id() -> str:
    """Generate random patient ID.

    Returns:
        Patient ID string
    """
    return f"PAT{random.randint(100000, 999999)}"


def random_accession_number() -> str:
    """Generate random accession number.

    Returns:
        Accession number string
    """
    return f"ACC{random.randint(1000000, 9999999)}"


def clamp(
    value: Union[int, float], min_val: Union[int, float], max_val: Union[int, float]
) -> Union[int, float]:
    """Clamp value between min and max.

    Args:
        value: Value to clamp
        min_val: Minimum value
        max_val: Maximum value

    Returns:
        Clamped value
    """
    return max(min_val, min(value, max_val))


def in_range(
    value: Union[int, float],
    min_val: Union[int, float],
    max_val: Union[int, float],
    inclusive: bool = True,
) -> bool:
    """Check if value is in range.

    Args:
        value: Value to check
        min_val: Minimum value
        max_val: Maximum value
        inclusive: Whether range is inclusive

    Returns:
        True if value is in range
    """
    if inclusive:
        return min_val <= value <= max_val
    return min_val < value < max_val


def format_bytes(size: int) -> str:
    """Format byte size as human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if size < KB:
        return f"{size} B"
    elif size < MB:
        return f"{size / KB:.2f} KB"
    elif size < GB:
        return f"{size / MB:.2f} MB"
    else:
        return f"{size / GB:.2f} GB"


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "1h 23m 45s")
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.0f}s"


@contextmanager
def timing(operation: str = "Operation", logger=None):
    """Context manager for timing operations.

    Args:
        operation: Name of operation being timed
        logger: Optional logger to log results

    Yields:
        Dict that will contain 'duration_ms' when context exits

    Example:
        >>> with timing("file_processing") as t:
        ...     process_file()
        >>> print(f"Took {t['duration_ms']}ms")
    """
    result = {}
    start_time = time.perf_counter()

    try:
        yield result
    finally:
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        result["duration_ms"] = duration_ms
        result["duration_s"] = end_time - start_time

        if logger:
            logger.info(f"{operation} completed", duration_ms=round(duration_ms, 2))


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks.

    Args:
        lst: List to chunk
        chunk_size: Size of each chunk

    Returns:
        List of chunks

    Example:
        >>> chunk_list([1, 2, 3, 4, 5], 2)
        [[1, 2], [3, 4], [5]]
    """
    return [lst[i : i + chunk_size] for i in range(0, len(lst), chunk_size)]


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely divide, returning default on division by zero.

    Args:
        numerator: Numerator
        denominator: Denominator
        default: Default value if denominator is zero

    Returns:
        Result of division or default
    """
    if denominator == 0:
        return default
    return numerator / denominator


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """Truncate string to maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s

    # If max_length is smaller than suffix, just truncate without suffix
    if max_length < len(suffix):
        return s[:max_length]

    truncate_at = max_length - len(suffix)
    return s[:truncate_at] + suffix


if __name__ == "__main__":
    """Test utility functions."""
    print("Testing DICOM Fuzzer Utilities...\n")

    print("File operations:")
    print(f"  100 MB = {format_bytes(100 * MB)}")
    print(f"  1.5 GB = {format_bytes(1.5 * GB)}")

    print("\nRandom data generation:")
    print(f"  Random date: {random_dicom_date(1980, 2000)}")
    print(f"  Random time: {random_dicom_time()}")
    print(f"  Random name: {random_person_name()}")
    print(f"  Random patient ID: {random_patient_id()}")
    print(f"  Random string: {random_string(10)}")

    print("\nDICOM tag operations:")
    tag = Tag(0x0008, 0x0016)
    hex_str = tag_to_hex(tag)
    print(f"  Tag to hex: {hex_str}")
    print(f"  Hex to tag: {hex_to_tag(hex_str)}")
    print(f"  Is private: {is_private_tag(tag)}")

    print("\nTiming operations:")
    with timing("test_operation") as t:
        time.sleep(0.1)
    print(f"  Duration: {format_duration(t['duration_s'])}")

    print("\nUtility testing complete!")
