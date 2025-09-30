"""
Pytest configuration and shared fixtures for DICOM-Fuzzer tests.
"""

import tempfile
from pathlib import Path
from typing import Generator

import pydicom
import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import generate_uid


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
    """Reset structlog configuration before each test.

    This ensures tests don't interfere with each other's logging configuration.
    """
    import structlog

    yield

    # Reset to original after test
    structlog.reset_defaults()


@pytest.fixture
def capture_logs(reset_structlog):
    """Capture log output for testing.

    Returns:
        List that will contain captured log entries
    """
    import logging

    import structlog

    captured = []

    def capture_processor(logger, method_name, event_dict):
        """Capture event dict before rendering."""
        captured.append(event_dict.copy())
        return event_dict

    # Configure structlog to capture logs
    logging.basicConfig(level=logging.DEBUG)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            capture_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    yield captured

    # Clear captured logs
    captured.clear()
