"""Patient data anonymizer - standalone utility for DICOM dataset anonymization.

Provides fake but believable patient demographics for fuzzing and testing,
without requiring a fuzzer instance.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from pydicom.dataset import Dataset

_FAKE_NAMES: list[str] = ["Smith^John", "Doe^Jane", "Johnson^Mike"]

_DOB_START = datetime(1950, 1, 1)
_DOB_RANGE_DAYS = (datetime(2010, 12, 31) - _DOB_START).days


def _random_dob() -> str:
    """Return a random but valid DICOM date (YYYYMMDD) in the range 1950-2010."""
    return (_DOB_START + timedelta(days=random.randint(0, _DOB_RANGE_DAYS))).strftime(
        "%Y%m%d"
    )


def anonymize_patient_info(dataset: Dataset) -> Dataset:
    """Replace patient identifiers with fake but believable values.

    Sets PatientID, PatientName, and PatientBirthDate.  The dataset is
    mutated in-place and also returned for chaining.

    Args:
        dataset: DICOM dataset to anonymize

    Returns:
        The same dataset with patient fields replaced

    """
    dataset.PatientID = f"PAT{random.randint(1000, 9999):06d}"
    dataset.PatientName = random.choice(_FAKE_NAMES)
    dataset.PatientBirthDate = _random_dob()
    return dataset


__all__ = ["anonymize_patient_info"]
