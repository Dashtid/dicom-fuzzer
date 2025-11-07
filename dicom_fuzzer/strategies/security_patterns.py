"""Security Patterns for CVE-specific DICOM vulnerabilities

This module implements specific vulnerability patterns based on real-world CVEs,
particularly CVE-2025-5943 (MicroDicom out-of-bounds write vulnerability).

SECURITY CONTEXT:
CVE-2025-5943 affects MicroDicom 3.0.0 to 3.9.6 and involves out-of-bounds writes
during DICOM header parsing. This can lead to heap corruption and potential RCE.
"""

import random

from pydicom.dataset import Dataset
from pydicom.tag import Tag


class SecurityPatternFuzzer:
    """Implements specific security vulnerability patterns for DICOM fuzzing.

    This fuzzer targets known vulnerability patterns in DICOM parsers,
    particularly focusing on memory corruption vulnerabilities.
    """

    def __init__(self) -> None:
        """Initialize security pattern fuzzer with attack patterns."""
        # CVE-2025-5943 specific patterns
        self.oversized_vr_lengths = [
            0xFFFF,  # Max 16-bit value
            0xFFFE,  # One less than max
            0x8000,  # Boundary value
            0x7FFF,  # Max positive 16-bit signed
            0x10000,  # Just over 16-bit
            0x100000,  # Large value
        ]

        # Common heap spray patterns
        self.heap_spray_patterns = [
            b"\x0c\x0c\x0c\x0c" * 256,  # Classic heap spray NOP sled
            b"\x90" * 1024,  # x86 NOP instructions
            b"\x41" * 512,  # ASCII 'A' pattern
            b"\xeb\xfe" * 256,  # Jump to self (infinite loop)
            b"\xcc" * 512,  # INT3 breakpoints
        ]

        # Malformed VR codes that might trigger parsing errors
        self.malformed_vr_codes = [
            b"\x00\x00",  # Null VR
            b"\xff\xff",  # Invalid VR
            b"XX",  # Non-standard VR
            b"ZZ",  # Non-standard VR
            b"\x41\x41",  # AA in hex
        ]

    def apply_cve_2025_5943_pattern(self, dataset: Dataset) -> Dataset:
        """Apply CVE-2025-5943 specific vulnerability patterns.

        This pattern targets out-of-bounds write vulnerabilities in DICOM
        header parsing by creating oversized VR length fields.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with CVE-2025-5943 patterns

        """
        # Target specific tags that are commonly parsed early
        vulnerable_tags = [
            (0x0008, 0x0005),  # SpecificCharacterSet
            (0x0008, 0x0008),  # ImageType
            (0x0008, 0x0016),  # SOPClassUID
            (0x0008, 0x0018),  # SOPInstanceUID
            (0x0008, 0x0020),  # StudyDate
            (0x0008, 0x0030),  # StudyTime
            (0x0008, 0x0050),  # AccessionNumber
            (0x0008, 0x0060),  # Modality
            (0x0008, 0x0070),  # Manufacturer
            (0x0008, 0x0090),  # ReferringPhysicianName
        ]

        # Select random tags to mutate
        tags_to_mutate = random.sample(
            vulnerable_tags, min(random.randint(1, 3), len(vulnerable_tags))
        )

        for tag_tuple in tags_to_mutate:
            tag = Tag(tag_tuple)
            if tag in dataset:
                # Create oversized value for this tag
                oversized_length = random.choice(self.oversized_vr_lengths)

                # Generate payload that might trigger overflow
                if oversized_length <= 0x10000:
                    # For reasonable sizes, create actual data
                    payload = b"A" * min(oversized_length, 0x8000)
                else:
                    # For huge sizes, create a smaller payload
                    # (the length field itself is the attack vector)
                    payload = b"B" * 1024

                try:
                    # Attempt to set oversized value
                    # This bypasses normal validation
                    elem = dataset[tag]
                    elem._value = payload

                    # Also try to corrupt the VR field directly if possible
                    if hasattr(elem, "VR"):
                        # Set invalid VR that might confuse length calculation
                        elem.VR = "UN"  # Unknown VR allows arbitrary length
                except Exception:
                    # Some tags might be protected, skip them
                    pass

        return dataset

    def apply_heap_spray_pattern(self, dataset: Dataset) -> Dataset:
        """Apply heap spray patterns to facilitate exploitation.

        Heap spraying is a technique used to facilitate exploitation of
        memory corruption vulnerabilities by filling memory with predictable data.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with heap spray patterns

        """
        # Target large data fields that can hold spray patterns
        spray_targets = [
            "PixelData",  # Large binary data
            "OverlayData",  # Overlay pixel data
            "CurveData",  # Curve data (deprecated but still parsed)
            "WaveformData",  # Waveform data
            "EncapsulatedDocument",  # Encapsulated PDF/CDA
            "IconImageSequence",  # Icon image data
        ]

        for field_name in spray_targets:
            if hasattr(dataset, field_name):
                # Select a heap spray pattern
                spray_pattern = random.choice(self.heap_spray_patterns)

                # Optionally combine with shellcode-like patterns
                if random.random() > 0.7:
                    # Add some shellcode-like signatures (harmless)
                    spray_pattern = (
                        b"\xeb\x0e"  # JMP 14 bytes
                        + b"\x90" * 12  # NOP sled
                        + spray_pattern
                    )

                try:
                    setattr(dataset, field_name, spray_pattern)
                except Exception:
                    # Some fields might have strict validation
                    pass

        # Also try to spray in string fields with large capacity
        string_spray_targets = [
            "ImageComments",
            "StudyComments",
            "InterpretationText",
            "TextString",
        ]

        for field_name in string_spray_targets:
            if hasattr(dataset, field_name):
                # Create string-based spray pattern
                spray_str = "A" * 1024 + "B" * 1024 + "C" * 1024
                try:
                    setattr(dataset, field_name, spray_str)
                except Exception:
                    pass

        return dataset

    def apply_malformed_vr_pattern(self, dataset: Dataset) -> Dataset:
        """Apply malformed Value Representation (VR) patterns.

        Malformed VR codes can trigger parsing errors and potentially
        lead to memory corruption if not properly validated.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with malformed VR patterns

        """
        # Target commonly parsed tags
        target_tags = list(dataset.keys())[:10]  # First 10 tags

        for tag in random.sample(target_tags, min(3, len(target_tags))):
            elem = dataset[tag]

            try:
                # Try to set malformed VR
                malformed_vr = random.choice(
                    [
                        "XX",  # Invalid VR code
                        "ZZ",  # Invalid VR code
                        "??",  # Non-standard
                        "\x00\x00",  # Null bytes
                        "UN",  # Unknown (might bypass validation)
                    ]
                )

                # Force VR change (this might not always work due to pydicom protection)
                elem.VR = malformed_vr

                # Also try to set value that doesn't match VR type
                if malformed_vr == "UN":
                    # Unknown VR can contain arbitrary data
                    elem._value = b"\x00" * 256 + b"\xff" * 256

            except Exception:
                # Expected - pydicom has protections
                pass

        return dataset

    def apply_integer_overflow_pattern(self, dataset: Dataset) -> Dataset:
        """Apply integer overflow patterns in length and size fields.

        Integer overflows in size calculations can lead to buffer overflows
        and heap corruption vulnerabilities.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with integer overflow patterns

        """
        # Target size-related fields
        overflow_targets = {
            "Rows": [0, 1, 0x7FFF, 0x8000, 0xFFFF, 0x10000],
            "Columns": [0, 1, 0x7FFF, 0x8000, 0xFFFF, 0x10000],
            "BitsAllocated": [0, 1, 8, 16, 32, 64, 128, 256],
            "BitsStored": [0, 1, 8, 16, 32, 64, 128, 256],
            "HighBit": [0, 7, 15, 31, 63, 127, 255],
            "PixelRepresentation": [-1, 0, 1, 2, 127, 128, 255, 256],
            "SamplesPerPixel": [0, 1, 3, 4, 255, 256, 65535],
            "NumberOfFrames": [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF],
        }

        for field_name, overflow_values in overflow_targets.items():
            if hasattr(dataset, field_name):
                # Select an overflow-inducing value
                overflow_value = random.choice(overflow_values)

                try:
                    setattr(dataset, field_name, overflow_value)

                    # Special case: if setting image dimensions, also adjust PixelData
                    if field_name in ["Rows", "Columns"] and hasattr(
                        dataset, "PixelData"
                    ):
                        # Create mismatched PixelData size to trigger calculations
                        if overflow_value > 0 and overflow_value < 0x1000:
                            # Create undersized data
                            dataset.PixelData = b"\x00" * 100
                        elif overflow_value >= 0x8000:
                            # Create oversized data
                            dataset.PixelData = b"\xff" * 0x10000

                except Exception:
                    pass

        return dataset

    def apply_sequence_depth_attack(self, dataset: Dataset) -> Dataset:
        """Apply deeply nested sequence patterns to trigger stack overflow.

        Deeply nested sequences can cause stack overflow in recursive parsers
        or excessive memory allocation.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with deeply nested sequences

        """
        from pydicom.sequence import Sequence

        # Create deeply nested sequence
        depth = random.randint(10, 100)

        # Build nested structure - start from innermost and work outward
        deepest_ds = Dataset()
        deepest_ds.Manufacturer = f"Level_{depth - 1}"

        # Create the nested structure from the inside out
        current_level = Sequence([deepest_ds])

        for i in range(depth - 2, -1, -1):
            parent_ds = Dataset()
            parent_ds.Manufacturer = f"Level_{i}"
            # Create proper DataElement for sequence
            from pydicom.dataelem import DataElement

            parent_ds[Tag(0x0008, 0x1140)] = DataElement(
                Tag(0x0008, 0x1140), "SQ", current_level
            )
            current_level = Sequence([parent_ds])

        # Add the deeply nested sequence to dataset
        try:
            # Remove existing sequence if present
            if Tag(0x0008, 0x1140) in dataset:
                del dataset[Tag(0x0008, 0x1140)]

            # Create proper DataElement for sequence
            from pydicom.dataelem import DataElement

            dataset[Tag(0x0008, 0x1140)] = DataElement(
                Tag(0x0008, 0x1140), "SQ", current_level
            )
        except Exception:
            pass

        return dataset

    def apply_encoding_confusion_pattern(self, dataset: Dataset) -> Dataset:
        """Apply encoding confusion patterns to trigger parsing errors.

        Mixed or invalid character encodings can cause buffer overflows
        in string processing routines.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with encoding confusion patterns

        """
        # Define problematic encoding patterns
        encoding_attacks = [
            b"\xff\xfe\x00\x00",  # UTF-32 LE BOM
            b"\x00\x00\xfe\xff",  # UTF-32 BE BOM
            b"\xff\xfe",  # UTF-16 LE BOM
            b"\xfe\xff",  # UTF-16 BE BOM
            b"\xef\xbb\xbf",  # UTF-8 BOM
            b"\x00" * 10,  # Null bytes
            bytes(range(256)),  # All byte values
            b"\x80" * 100,  # Invalid UTF-8 continuation bytes
        ]

        # Set confusing SpecificCharacterSet
        if hasattr(dataset, "SpecificCharacterSet"):
            confused_charsets = [
                "ISO-IR 100\\ISO-IR 144",  # Mixed Latin1 and Russian
                "\\".join(
                    [f"ISO-IR {i}" for i in range(100, 200, 10)]
                ),  # Many charsets
                "INVALID_CHARSET",  # Non-existent
                "",  # Empty
                "\\",  # Just delimiter
                "ISO-IR 192",  # UTF-8 (might not be supported everywhere)
            ]
            dataset.SpecificCharacterSet = random.choice(confused_charsets)

        # Apply encoding attacks to string fields
        string_fields = [
            "PatientName",
            "PatientID",
            "StudyDescription",
            "SeriesDescription",
            "Manufacturer",
            "InstitutionName",
        ]

        for field_name in string_fields:
            if hasattr(dataset, field_name):
                attack_bytes = random.choice(encoding_attacks)

                try:
                    # Try to set raw bytes (might fail due to encoding validation)
                    elem = dataset.data_element(field_name)
                    if elem is not None:
                        elem._value = attack_bytes
                except Exception:
                    # Fall back to setting confusing but valid strings
                    try:
                        # Unicode normalization attacks
                        confusing_strings = [
                            "\u0041\u0301",  # A with combining accent
                            "\ufeff" * 10,  # Zero-width no-break spaces
                            "\u202e" + "Hello",  # Right-to-left override
                            "\x00Test",  # Embedded null
                            "A" + "\x00" + "B",  # Null in middle
                        ]
                        setattr(dataset, field_name, random.choice(confusing_strings))
                    except Exception:
                        pass

        return dataset

    def apply_all_patterns(self, dataset: Dataset) -> Dataset:
        """Apply all security patterns to create comprehensive test case.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with multiple security patterns applied

        """
        # List of all pattern application methods
        patterns = [
            self.apply_cve_2025_5943_pattern,
            self.apply_heap_spray_pattern,
            self.apply_malformed_vr_pattern,
            self.apply_integer_overflow_pattern,
            self.apply_sequence_depth_attack,
            self.apply_encoding_confusion_pattern,
        ]

        # Apply 1-3 random patterns
        num_patterns = random.randint(1, 3)
        selected_patterns = random.sample(patterns, num_patterns)

        for pattern_func in selected_patterns:
            try:
                dataset = pattern_func(dataset)
            except Exception:
                # Continue with other patterns if one fails
                pass

        return dataset
