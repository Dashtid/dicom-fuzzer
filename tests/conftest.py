"""
Pytest configuration and shared fixtures for DICOM-Fuzzer tests.

Optimizations for 4k+ tests:
- Auto-cleanup of orphaned .coverage.* files
- Worksteal distribution for parallel testing
- Session-scoped fixtures for expensive setup
"""

import random
import tempfile
from collections.abc import Generator
from pathlib import Path

import numpy as np
import pydicom
import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import generate_uid

# Ignore production modules that have class names starting with "Test" but are not test classes
# This prevents pytest from collecting them as tests
collect_ignore_glob = ["**/dicom_fuzzer/core/test_minimizer.py"]


@pytest.fixture
def deterministic_random():
    """Fixture to make random behavior deterministic for a test.

    Saves and restores random state for both Python's random module and numpy.
    Seeds both with a fixed value (42) for reproducibility.

    Usage:
        def test_something(deterministic_random):
            # Random calls are now deterministic
            result = random.choice([1, 2, 3])  # Always returns same value
    """
    # Save current state
    py_state = random.getstate()
    np_state = np.random.get_state()

    # Seed with fixed values
    random.seed(42)
    np.random.seed(42)

    yield

    # Restore original state
    random.setstate(py_state)
    np.random.set_state(np_state)


@pytest.fixture
def seeded_random(request):
    """Fixture that seeds random with a test-specific but reproducible value.

    Uses the test node ID to generate a unique but reproducible seed per test.
    This ensures different tests get different random sequences, but each test
    is individually reproducible.

    Usage:
        def test_something(seeded_random):
            # Random calls are deterministic and unique to this test
            result = random.choice([1, 2, 3])
    """
    # Generate seed from test name for reproducibility
    seed = hash(request.node.nodeid) % (2**32)

    # Save current state
    py_state = random.getstate()
    np_state = np.random.get_state()

    # Seed with test-specific value
    random.seed(seed)
    np.random.seed(seed)

    yield seed

    # Restore original state
    random.setstate(py_state)
    np.random.set_state(np_state)


def pytest_sessionstart(session: pytest.Session) -> None:
    """Clean up orphaned coverage files before test session starts.

    This prevents accumulation of .coverage.* files from interrupted xdist runs.
    """
    import glob
    import os

    project_root = Path(__file__).parent.parent
    patterns = [
        str(project_root / ".coverage.*"),  # Worker coverage files
        str(project_root / ".coverage"),  # Main coverage file (will be recreated)
    ]

    for pattern in patterns:
        for file_path in glob.glob(pattern):
            try:
                os.remove(file_path)
            except OSError:
                pass  # Ignore errors (file in use, permissions, etc.)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for test files.

    Yields:
        Path to temporary directory that will be cleaned up after test
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_dicom_file(temp_dir: Path) -> Path:
    """Create a minimal valid DICOM file for testing.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path to created DICOM file
    """
    file_path = temp_dir / "test.dcm"

    # Create minimal DICOM dataset
    file_meta = pydicom.dataset.FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"  # Explicit VR Little Endian
    file_meta.ImplementationClassUID = generate_uid()

    dataset = FileDataset(
        str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    # Add required DICOM elements
    dataset.PatientName = "Test^Patient"
    dataset.PatientID = "TEST123"
    dataset.PatientBirthDate = "19800101"
    dataset.PatientSex = "M"
    dataset.StudyInstanceUID = generate_uid()
    dataset.SeriesInstanceUID = generate_uid()
    dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
    dataset.Modality = "CT"
    dataset.StudyDate = "20240101"
    dataset.StudyTime = "120000"

    # Save to file
    dataset.save_as(str(file_path), write_like_original=False)

    return file_path


@pytest.fixture
def sample_dicom_dataset() -> Dataset:
    """Create a minimal DICOM dataset for testing.

    Returns:
        DICOM Dataset object
    """
    dataset = Dataset()
    dataset.PatientName = "Doe^John"
    dataset.PatientID = "PAT001"
    dataset.PatientBirthDate = "19750315"
    dataset.PatientSex = "M"
    dataset.StudyInstanceUID = generate_uid()
    dataset.SeriesInstanceUID = generate_uid()
    dataset.SOPInstanceUID = generate_uid()
    dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    dataset.Modality = "CT"

    return dataset


@pytest.fixture
def large_file(temp_dir: Path) -> Path:
    """Create a large file for testing size limits.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path to large file (10 MB)
    """
    file_path = temp_dir / "large_file.bin"

    # Create 10 MB file
    size_mb = 10
    with open(file_path, "wb") as f:
        f.write(b"\x00" * (size_mb * 1024 * 1024))

    return file_path


@pytest.fixture
def small_file(temp_dir: Path) -> Path:
    """Create a small file for testing.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path to small file (1 KB)
    """
    file_path = temp_dir / "small_file.txt"

    with open(file_path, "w") as f:
        f.write("Test content\n" * 50)

    return file_path


@pytest.fixture
def reset_structlog():
    """Reset structlog configuration before and after each test.

    This ensures tests don't interfere with each other's logging configuration.
    """
    import logging

    import structlog

    def _cleanup():
        """Clean up logging and structlog configuration."""
        # Flush and close all logging handlers
        for handler in logging.root.handlers[:]:
            handler.flush()
            handler.close()
            logging.root.removeHandler(handler)

        # Reset structlog to defaults
        structlog.reset_defaults()

    # Clean up BEFORE the test to ensure clean state
    _cleanup()

    yield

    # Clean up AFTER the test
    _cleanup()


@pytest.fixture
def capture_logs():
    """Capture log output for testing.

    Returns:
        List that will contain captured log entries

    Note: Uses structlog's official testing utilities which properly
    handle in-place processor modification to preserve cached logger
    references.
    """
    import structlog
    import structlog.testing

    # Ensure structlog is configured before capturing
    # This handles the case where no test has configured structlog yet
    if not structlog.is_configured():
        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=False,
        )

    # Use structlog's official capture_logs with add_log_level processor
    # to ensure 'level' key is present in captured entries
    with structlog.testing.capture_logs(
        processors=[structlog.stdlib.add_log_level]
    ) as captured:
        yield captured


@pytest.fixture
def minimal_dicom_file(temp_dir: Path) -> Path:
    """Create an absolutely minimal valid DICOM file.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path to minimal DICOM file
    """
    file_path = temp_dir / "minimal.dcm"

    file_meta = pydicom.dataset.FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    dataset = FileDataset(
        str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    # Absolute minimum required tags
    dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
    dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID

    dataset.save_as(str(file_path), write_like_original=False)
    return file_path


@pytest.fixture
def dicom_empty_patient_name(temp_dir: Path) -> Path:
    """Create DICOM file with empty patient name.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path to DICOM file with empty patient name
    """
    file_path = temp_dir / "empty_name.dcm"

    file_meta = pydicom.dataset.FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    dataset = FileDataset(
        str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    dataset.PatientName = ""  # Empty patient name
    dataset.PatientID = "TEST002"
    dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
    dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID

    dataset.save_as(str(file_path), write_like_original=False)
    return file_path


@pytest.fixture
def dicom_with_pixels(temp_dir: Path) -> Path:
    """Create DICOM file with pixel data.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path to DICOM file with pixel data
    """
    import numpy as np

    file_path = temp_dir / "with_pixels.dcm"

    file_meta = pydicom.dataset.FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    dataset = FileDataset(
        str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    # Add required tags
    dataset.PatientName = "Test^Patient"
    dataset.PatientID = "TEST003"
    dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
    dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    dataset.Modality = "CT"
    dataset.StudyInstanceUID = generate_uid()
    dataset.SeriesInstanceUID = generate_uid()

    # Add image-specific tags
    dataset.SamplesPerPixel = 1
    dataset.PhotometricInterpretation = "MONOCHROME2"
    dataset.Rows = 64
    dataset.Columns = 64
    dataset.BitsAllocated = 16
    dataset.BitsStored = 16
    dataset.HighBit = 15
    dataset.PixelRepresentation = 0

    # Create pixel data (64x64 image)
    pixel_array = np.random.randint(0, 4096, (64, 64), dtype=np.uint16)
    dataset.PixelData = pixel_array.tobytes()

    dataset.save_as(str(file_path), write_like_original=False)
    return file_path
