"""Header Fuzzer - DICOM Tag and Header Mutations.

Targets DICOM tags, Value Representations (VRs), and metadata fields
with edge cases and invalid data to test parser robustness.

Covers all 27 DICOM VRs with appropriate invalid values including:
- Overlong strings, boundary values, format violations
- Invalid encoding, null bytes, empty values
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset

from .base import FormatFuzzerBase
from .uid_attacks import INVALID_UIDS, UID_TAG_NAMES

# VR-specific invalid values for comprehensive testing
# Based on DICOM PS3.5 VR definitions
VR_MUTATIONS = {
    # AE - Application Entity (max 16 chars, no leading/trailing spaces)
    "AE": [
        "A" * 17,  # Over limit
        "A" * 64,  # Way over limit
        " LEADING",  # Leading space (invalid)
        "TRAILING ",  # Trailing space (invalid)
        "\x00AE",  # Null byte
        "",  # Empty
    ],
    # AS - Age String (format: NNNU where U is D/W/M/Y)
    "AS": [
        "999X",  # Invalid unit
        "12345Y",  # Too many digits
        "12Y",  # Too few digits (should be 3)
        "ABCY",  # Non-numeric
        "-01Y",  # Negative
        "",  # Empty
    ],
    # AT - Attribute Tag (4 bytes, group-element pair)
    "AT": [
        b"\xff\xff\xff",  # Odd length (3 bytes)
        b"\xff\xff\xff\xff\xff",  # 5 bytes
        b"",  # Empty
    ],
    # CS - Code String (max 16 chars, uppercase A-Z, 0-9, space, underscore)
    "CS": [
        "lowercase",  # Lowercase (invalid)
        "A" * 17,  # Over limit
        "SPECIAL!@#",  # Special chars
        "WITH\nNEWLINE",  # Newline
        "\x00CODE",  # Null byte
    ],
    # DT - Date Time (YYYYMMDDHHMMSS.FFFFFF&ZZXX)
    "DT": [
        "20251301120000",  # Month 13
        "20250132120000",  # Day 32
        "20250101250000",  # Hour 25
        "20250101126000",  # Minute 60
        "20250101120060",  # Second 60
        "20250101120000.9999999",  # Too many fractional digits
        "20250101120000+2500",  # Invalid timezone
        "NOT_A_DATETIME",  # Non-numeric
        "",  # Empty
    ],
    # FL - Floating Point Single (4 bytes IEEE 754)
    "FL": [
        struct.pack("<f", float("nan")),  # NaN
        struct.pack("<f", float("inf")),  # Positive infinity
        struct.pack("<f", float("-inf")),  # Negative infinity
        b"\x00\x00\x80\x00",  # Denormalized (very small)
        b"\xff\xff\xff\x7f",  # Signaling NaN
        b"\x00",  # Too short
        b"\x00\x00\x00\x00\x00",  # Too long
    ],
    # FD - Floating Point Double (8 bytes IEEE 754)
    "FD": [
        struct.pack("<d", float("nan")),  # NaN
        struct.pack("<d", float("inf")),  # Positive infinity
        struct.pack("<d", float("-inf")),  # Negative infinity
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x01",  # 9 bytes (odd)
        b"\x00\x00\x00",  # Too short
    ],
    # LO - Long String (max 64 chars)
    "LO": [
        "A" * 65,  # Over limit
        "A" * 1024,  # Way over limit
        "\x00" * 10,  # Null bytes
        "Line1\nLine2",  # Newline (invalid)
        "\r\nCRLF",  # CRLF
        "Unicode: \u2603\u2764",  # Unicode snowman and heart
    ],
    # LT - Long Text (max 10240 chars)
    "LT": [
        "A" * 10241,  # Over limit
        "A" * 100000,  # Way over limit
        "\x00" * 100,  # Null bytes
    ],
    # OB - Other Byte (arbitrary bytes)
    "OB": [
        b"\x00" * 0x10001,  # Large (64KB + 1)
        b"",  # Empty
    ],
    # OW - Other Word (16-bit words, must be even length)
    "OW": [
        b"\x00\x00\x00",  # Odd length (3 bytes)
        b"\xff",  # Single byte
        b"\x00" * 0x10001,  # Odd count
    ],
    # PN - Person Name (5 component groups, 64 chars each)
    "PN": [
        "A" * 65 + "^" + "B" * 65,  # Both components over limit
        "Family^Given^Middle^Prefix^Suffix^Extra",  # 6 components (max 5)
        "\x00Name",  # Null byte
        "=Ideographic=Phonetic",  # Component groups without alphabetic
        "A" * 1000,  # Very long single component
    ],
    # SH - Short String (max 16 chars)
    "SH": [
        "A" * 17,  # Over limit
        "A" * 256,  # Way over limit
        "\x00SHORT",  # Null byte
        "WITH\nNEWLINE",  # Newline
    ],
    # SL - Signed Long (32-bit signed integer)
    "SL": [
        struct.pack("<i", -2147483648),  # MIN_INT
        struct.pack("<i", 2147483647),  # MAX_INT
        b"\x00\x00\x00",  # 3 bytes (should be 4)
        b"\x00\x00\x00\x00\x00",  # 5 bytes
    ],
    # SS - Signed Short (16-bit signed integer)
    "SS": [
        struct.pack("<h", -32768),  # MIN_SHORT
        struct.pack("<h", 32767),  # MAX_SHORT
        b"\x00",  # 1 byte (should be 2)
        b"\x00\x00\x00",  # 3 bytes
    ],
    # ST - Short Text (max 1024 chars)
    "ST": [
        "A" * 1025,  # Over limit
        "A" * 10000,  # Way over limit
        "\x00" * 50,  # Null bytes
    ],
    # UC - Unlimited Characters (no max)
    "UC": [
        "A" * 1000000,  # 1MB string
        "\x00" * 10000,  # Null bytes
    ],
    # UI - Unique Identifier (max 64 chars, digits and dots only)
    "UI": [
        "1" * 65,  # Over limit
        "1.2.3.NOT.NUMERIC",  # Non-numeric
        "1.2.3.",  # Trailing dot
        ".1.2.3",  # Leading dot
        "1..2.3",  # Double dot
        "",  # Empty
        " 1.2.3",  # Leading space
        "1.2.3 ",  # Trailing space
        "\x001.2.3",  # Null byte
    ],
    # UL - Unsigned Long (32-bit unsigned integer)
    "UL": [
        struct.pack("<I", 0),  # Zero
        struct.pack("<I", 4294967295),  # MAX_UINT
        b"\x00\x00\x00",  # 3 bytes
        b"\x00\x00\x00\x00\x00",  # 5 bytes
    ],
    # UN - Unknown (any bytes)
    "UN": [
        b"\x00" * 1000000,  # 1MB of nulls
        b"\xff" * 10000,  # All 0xFF
        b"",  # Empty
    ],
    # UR - URI/URL (no max, but specific format)
    "UR": [
        "not-a-valid-uri",  # Invalid format
        "://missing-scheme",  # Missing scheme
        "http://" + "a" * 10000,  # Very long
        "\x00http://example.com",  # Null byte
        "",  # Empty
    ],
    # US - Unsigned Short (16-bit unsigned integer)
    "US": [
        struct.pack("<H", 0),  # Zero
        struct.pack("<H", 65535),  # MAX_USHORT
        b"\x00",  # 1 byte
        b"\x00\x00\x00",  # 3 bytes
    ],
    # UT - Unlimited Text (no max length)
    "UT": [
        "A" * 10000000,  # 10MB string
        "\x00" * 100000,  # Null bytes
    ],
    # OD - Other Double (64-bit floats, must be even multiple of 8)
    "OD": [
        struct.pack("<d", float("nan")),  # NaN
        struct.pack("<d", float("inf")),  # Infinity
        struct.pack("<d", float("-inf")),  # Negative infinity
        b"\x00" * 7,  # 7 bytes (not multiple of 8)
        b"\x00" * 9,  # 9 bytes (not multiple of 8)
        b"",  # Empty
    ],
    # OF - Other Float (32-bit floats, must be even multiple of 4)
    "OF": [
        struct.pack("<f", float("nan")),  # NaN
        struct.pack("<f", float("inf")),  # Infinity
        b"\x00" * 3,  # 3 bytes (not multiple of 4)
        b"\x00" * 5,  # 5 bytes (not multiple of 4)
        b"",  # Empty
    ],
    # OL - Other Long (32-bit unsigned integers, must be multiple of 4)
    "OL": [
        struct.pack("<I", 0),  # Zero
        struct.pack("<I", 4294967295),  # MAX_UINT
        b"\x00" * 3,  # 3 bytes (not multiple of 4)
        b"\x00" * 5,  # 5 bytes (not multiple of 4)
        b"",  # Empty
    ],
    # DA - Date (YYYYMMDD format, 8 chars)
    "DA": [
        "INVALID",  # Non-date
        "99999999",  # Invalid date
        "20251332",  # Month > 12
        "20250145",  # Day > 31
        "2025-01-01",  # Wrong format
        "",  # Empty
        "1",  # Too short
    ],
    # TM - Time (HHMMSS.FFFFFF format)
    "TM": [
        "999999",  # Hours > 23
        "126000",  # Minutes > 59
        "120075",  # Seconds > 59
        "ABCDEF",  # Non-numeric
        "12:30:45",  # Wrong format
        "",  # Empty
    ],
    # IS - Integer String (max 12 chars)
    "IS": [
        "NOT_A_NUMBER",  # Non-numeric
        "3.14159",  # Decimal
        "9" * 13,  # Over 12 char limit
        "",  # Empty
        "-" * 10,  # Just hyphens
    ],
    # DS - Decimal String (max 16 chars)
    "DS": [
        "INVALID",  # Non-numeric
        "1.2.3",  # Multiple decimals
        "NaN",  # Not a number string
        "9" * 17,  # Over 16 char limit
        "",  # Empty
    ],
}


class HeaderFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM headers with edge cases and invalid values.

    Tests application handling of:
    - Overlong strings (buffer overflow potential)
    - Missing required fields (compliance violations)
    - Invalid data types (type safety)
    - Boundary values (edge cases)
    """

    def __init__(self) -> None:
        """Initialize header fuzzer with attack patterns."""
        super().__init__()
        # DICOM required tags that can be safely removed for testing
        # Note: We exclude SOPClassUID and SOPInstanceUID as they break parsing
        self.required_tags = [
            "PatientName",  # (0010,0010)
            "PatientID",  # (0010,0020)
            "StudyInstanceUID",  # (0020,000D)
            "SeriesInstanceUID",  # (0020,000E)
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "header"

    def mutate(self, dataset: Dataset) -> Dataset:
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
            self._comprehensive_vr_mutations,
            self._numeric_vr_mutations,
            self._uid_mutations,
        ]

        for mutation in random.sample(mutations, k=random.randint(2, 4)):
            dataset = mutation(dataset)
        return dataset

    mutate_tags = mutate

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
            elem = dataset["SeriesNumber"]
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
            elem = dataset["SliceThickness"]
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
            dataset.PatientName = random.choice(
                ["X" * 64, "X" * 65]  # At VR limit or one over
            )

        # Test empty strings
        empty_test_tags = ["Manufacturer", "ModelName", "SoftwareVersions"]
        for tag in empty_test_tags:
            if hasattr(dataset, tag) and random.random() > 0.7:
                setattr(dataset, tag, "")

        return dataset

    def _comprehensive_vr_mutations(self, dataset: Dataset) -> Dataset:
        """Apply mutations to elements based on their VR type.

        Targets all VRs found in the dataset with appropriate invalid values
        including buffer overflows, format violations, and encoding issues.
        """
        # Collect elements by VR
        vr_elements: dict[str, list] = {}
        for elem in dataset:
            if hasattr(elem, "VR") and elem.VR in VR_MUTATIONS:
                if elem.VR not in vr_elements:
                    vr_elements[elem.VR] = []
                vr_elements[elem.VR].append(elem)

        # Mutate 1-3 random VR types found in the dataset
        vrs_to_mutate = list(vr_elements.keys())
        if not vrs_to_mutate:
            return dataset

        num_to_mutate = min(random.randint(1, 3), len(vrs_to_mutate))
        for vr in random.sample(vrs_to_mutate, num_to_mutate):
            elements = vr_elements[vr]
            elem = random.choice(elements)
            mutations = VR_MUTATIONS[vr]
            mutation = random.choice(mutations)

            try:
                elem._value = mutation
            except Exception:
                # Some mutations may fail - that's expected
                pass

        return dataset

    def _numeric_vr_mutations(self, dataset: Dataset) -> Dataset:
        """Target numeric VRs with boundary values and type confusion.

        Focuses on integer overflow/underflow and float special values
        that commonly trigger crashes in parsers.
        """
        # Numeric VRs and their boundary attack values
        numeric_attacks = {
            # Unsigned short - common for image dimensions
            "US": [0, 1, 65534, 65535],
            # Signed short
            "SS": [-32768, -1, 0, 32767],
            # Unsigned long - used for lengths
            "UL": [0, 1, 2147483647, 4294967295],
            # Signed long
            "SL": [-2147483648, -1, 0, 2147483647],
        }

        for elem in dataset:
            if not hasattr(elem, "VR"):
                continue

            vr = elem.VR
            if vr in numeric_attacks and random.random() > 0.7:
                try:
                    attack_value = random.choice(numeric_attacks[vr])
                    elem.value = attack_value
                except Exception:
                    pass  # Some VR types may reject the attack value

        return dataset

    def _uid_mutations(self, dataset: Dataset) -> Dataset:
        """Target UID fields with format violations.

        UIDs are critical for DICOM - invalid UIDs can cause lookup failures,
        reference errors, and parsing crashes.
        """
        # Mutate 1-2 UID fields
        available_tags = [t for t in UID_TAG_NAMES if hasattr(dataset, t)]
        if available_tags:
            tags_to_mutate = random.sample(
                available_tags, k=min(random.randint(1, 2), len(available_tags))
            )
            for tag in tags_to_mutate:
                try:
                    elem = dataset.data_element(tag)
                    if elem:
                        elem._value = random.choice(INVALID_UIDS)
                except Exception:
                    pass  # UID element may reject invalid format

        return dataset
