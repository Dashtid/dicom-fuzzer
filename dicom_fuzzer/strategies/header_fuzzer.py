"""Header Fuzzer - DICOM Tag and Header Mutations.

Targets DICOM tags, Value Representations (VRs), and metadata fields
with edge cases and invalid data to test parser robustness.
"""

import random

from pydicom.dataset import Dataset
from pydicom.tag import Tag


class HeaderFuzzer:
    """Fuzzes DICOM headers with edge cases and invalid values.

    Tests application handling of:
    - Overlong strings (buffer overflow potential)
    - Missing required fields (compliance violations)
    - Invalid data types (type safety)
    - Boundary values (edge cases)
    """

    def __init__(self) -> None:
        """Initialize header fuzzer with attack patterns."""
        # DICOM required tags that can be safely removed for testing
        # Note: We exclude SOPClassUID and SOPInstanceUID as they break parsing
        self.required_tags = [
            "PatientName",  # (0010,0010)
            "PatientID",  # (0010,0020)
            "StudyInstanceUID",  # (0020,000D)
            "SeriesInstanceUID",  # (0020,000E)
        ]

    def mutate_tags(self, dataset: Dataset) -> Dataset:
        """Mutate DICOM tags with edge cases.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        mutations = [
            self._overlong_strings,
            self._missing_required_tags,
            self._invalid_vr_values,
            self._boundary_values,
        ]

        for mutation in random.sample(mutations, k=random.randint(1, 3)):
            dataset = mutation(dataset)
        return dataset

    def _overlong_strings(self, dataset: Dataset) -> Dataset:
        """Insert extremely long strings to test buffer handling.

        DICOM VRs have maximum lengths (LO: 64, SH: 16, PN: 64 per component).
        Tests for buffer overflow in parsers with fixed-size buffers.
        """
        if hasattr(dataset, "InstitutionName"):
            dataset.InstitutionName = "A" * 1024  # Way over 64 char limit

        # Also test other string fields
        if hasattr(dataset, "StudyDescription"):
            dataset.StudyDescription = "B" * 2048  # Extremely long

        if hasattr(dataset, "Manufacturer"):
            dataset.Manufacturer = "C" * 512

        return dataset

    def _missing_required_tags(self, dataset: Dataset) -> Dataset:
        """Remove required DICOM tags to test compliance.

        DICOM defines Type 1 tags that must be present. Tests parser
        behavior when required fields are missing.
        """
        # Randomly remove 1-2 required tags if they exist
        tags_to_remove = random.sample(
            self.required_tags, k=min(random.randint(1, 2), len(self.required_tags))
        )

        for tag in tags_to_remove:
            if hasattr(dataset, tag):
                try:
                    delattr(dataset, tag)
                except Exception:
                    # Some tags can't be deleted, that's fine
                    pass

        return dataset

    def _invalid_vr_values(self, dataset: Dataset) -> Dataset:
        """Insert invalid Value Representation (VR) values.

        Each DICOM tag has a specific VR (DA: YYYYMMDD, TM: HHMMSS,
        IS: numeric string, DS: decimal string). Tests parser handling
        of VR constraint violations.
        """
        # Test invalid date format (should be YYYYMMDD)
        if hasattr(dataset, "StudyDate"):
            invalid_dates = [
                "INVALID",  # Non-numeric
                "99999999",  # Invalid date
                "20251332",  # Month > 12
                "20250145",  # Day > 31
                "2025-01-01",  # Wrong format (has dashes)
                "",  # Empty
                "1",  # Too short
            ]
            dataset.StudyDate = random.choice(invalid_dates)

        # Test invalid time format (should be HHMMSS)
        if hasattr(dataset, "StudyTime"):
            invalid_times = [
                "999999",  # Hours > 23
                "126000",  # Minutes > 59
                "120075",  # Seconds > 59
                "ABCDEF",  # Non-numeric
                "12:30:45",  # Wrong format (has colons)
            ]
            dataset.StudyTime = random.choice(invalid_times)

        # Test invalid integer string (IS VR) - bypass validation
        if hasattr(dataset, "SeriesNumber"):
            invalid_integers = [
                "NOT_A_NUMBER",  # Non-numeric
                "3.14159",  # Decimal (should be integer)
                "999999999999",  # Way too large
                "-999999999",  # Very negative
                "",  # Empty
            ]
            value = random.choice(invalid_integers)
            # Bypass validation by setting the internal _value directly
            elem = dataset[Tag(0x0020, 0x0011)]  # SeriesNumber
            elem._value = value

        # Test invalid decimal string (DS VR) - bypass validation
        if hasattr(dataset, "SliceThickness"):
            invalid_decimals = [
                "INVALID",  # Non-numeric
                "1.2.3",  # Multiple decimals
                "NaN",  # Not a number
                "Infinity",  # Infinity
                "1e999",  # Too large
            ]
            value = random.choice(invalid_decimals)
            # Bypass validation by setting the internal _value directly
            elem = dataset[Tag(0x0018, 0x0050)]  # SliceThickness
            elem._value = value

        return dataset

    def _boundary_values(self, dataset: Dataset) -> Dataset:
        """Insert boundary and edge case values.

        Tests min/max values that may trigger integer overflow,
        division by zero, or array index issues.
        """
        # Test numeric boundary values
        if hasattr(dataset, "Rows"):
            boundary_values = [
                0,  # Zero (division by zero?)
                1,  # Minimum valid
                65535,  # Max 16-bit unsigned
                -1,  # Negative (invalid for image size)
                2147483647,  # Max 32-bit signed int
            ]
            dataset.Rows = random.choice(boundary_values)

        if hasattr(dataset, "Columns"):
            dataset.Columns = random.choice([0, 1, 65535, -1])

        # Test age with boundary values
        if hasattr(dataset, "PatientAge"):
            boundary_ages = [
                "000Y",  # Zero age
                "999Y",  # Very old
                "001D",  # One day old
                "999W",  # 999 weeks
                "000M",  # Zero months
            ]
            dataset.PatientAge = random.choice(boundary_ages)

        # Test string length boundaries
        if hasattr(dataset, "PatientName"):
            # Exactly at VR limit (64 chars for LO)
            dataset.PatientName = "X" * 64
            # Or one character over
            if random.random() > 0.5:
                dataset.PatientName = "X" * 65

        # Test empty strings
        empty_test_tags = ["Manufacturer", "ModelName", "SoftwareVersions"]
        for tag in empty_test_tags:
            if hasattr(dataset, tag) and random.random() > 0.7:
                setattr(dataset, tag, "")

        return dataset
