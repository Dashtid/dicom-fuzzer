"""Private Tag Fuzzer - Vendor-Specific Tag Mutations.

Targets DICOM private tags used by vendors for proprietary data.
Private tags use odd group numbers (0009, 0011, 0019, etc.) and
require a "Private Creator" element to identify the vendor.

Private tag vulnerabilities:
- Missing Private Creator causes unknown tag handling
- Wrong VR for private data
- Collisions between vendors using same tag
- Buffer overflows in vendor-specific parsers
- Injection of malicious data in private elements
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase
from .dicom_dictionaries import BINARY_FILE_HEADERS, INJECTION_PAYLOADS

logger = get_logger(__name__)

# Known private creator identifiers (vendors)
KNOWN_CREATORS = [
    "GEMS_GENIE_1",  # GE
    "GEMS_IMAG_01",  # GE
    "GEMS_IDEN_01",  # GE
    "SIEMENS MED",  # Siemens
    "SIEMENS CT VA0 COAD",  # Siemens CT
    "SIEMENS MR VA0 GEN",  # Siemens MR
    "SIEMENS CSA HEADER",  # Siemens CSA
    "Philips MR Imaging DD 001",  # Philips
    "Philips Imaging DD 001",  # Philips
    "AGFA",  # Agfa
    "TOSHIBA_MEC_CT3",  # Toshiba/Canon
    "ELSCINT1",  # Elscint
    "HOLOGIC",  # Hologic
    "SPI-P-GV-CT Release 1",  # Various
]

# Fake/malicious creators for testing
MALICIOUS_CREATORS = [
    "",  # Empty
    "A" * 100,  # Overlong
    "CREATOR\x00HIDDEN",  # Embedded null
    "CREATOR\nNEWLINE",  # Embedded newline
    "../../../etc/passwd",  # Path traversal attempt
    "<script>alert(1)</script>",  # XSS attempt
    "'; DROP TABLE patients; --",  # SQL injection attempt
    "\x00\x01\x02\x03",  # Binary data
]

# Common private tag groups
PRIVATE_GROUPS = [0x0009, 0x0011, 0x0019, 0x0021, 0x0029, 0x0043, 0x0045, 0x7FE1]


class PrivateTagFuzzer(FormatFuzzerBase):
    """Fuzzes private/vendor-specific DICOM tags.

    Targets the proprietary extensions that vendors add to DICOM
    which may have weaker validation than standard tags.
    """

    def __init__(self) -> None:
        """Initialize the private tag fuzzer."""
        self.mutation_strategies = [
            self._missing_creator,
            self._wrong_creator,
            self._creator_collision,
            self._invalid_private_vr,
            self._oversized_private_data,
            self._private_tag_injection,
            self._creator_overwrite,
            self._reserved_group_attack,
            self._private_sequence_attack,
            self._binary_blob_injection,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "private_tag"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply private tag mutations.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with private tag corruptions

        """
        num_strategies = random.randint(1, 3)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug(f"Private tag mutation failed: {e}")

        return dataset

    mutate_private_tags = mutate

    def _missing_creator(self, dataset: Dataset) -> Dataset:
        """Add private data tags without Private Creator.

        Private Creator (gggg,00xx) must define the creator before
        private data (gggg,xxyy) can be used. Missing creator tests
        error handling.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)
            # Add private data without creator
            # Element (0009,1010) requires creator at (0009,0010)
            dataset.add_new(Tag(group, 0x1010), "LO", "DataWithoutCreator")
            dataset.add_new(Tag(group, 0x1011), "UN", b"\x00" * 100)
            dataset.add_new(Tag(group, 0x1012), "DS", "123.456")

        except Exception as e:
            logger.debug(f"Missing creator attack failed: {e}")

        return dataset

    def _wrong_creator(self, dataset: Dataset) -> Dataset:
        """Add private data with wrong/invalid creator identifier.

        Tests handling of unrecognized or malformed creator IDs.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)
            creator = random.choice(MALICIOUS_CREATORS)

            # Set creator (gggg,0010)
            dataset.add_new(Tag(group, 0x0010), "LO", creator)
            # Add data under that creator
            dataset.add_new(Tag(group, 0x1010), "LO", "PrivateData1")
            dataset.add_new(Tag(group, 0x1011), "LO", "PrivateData2")

        except Exception as e:
            logger.debug(f"Wrong creator attack failed: {e}")

        return dataset

    def _creator_collision(self, dataset: Dataset) -> Dataset:
        """Create multiple creators that may collide.

        Same group with multiple creators, or creators that
        overlap in element ranges.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)

            attack = random.choice(
                [
                    "multiple_creators_same_block",
                    "creator_overwrites_data",
                    "duplicate_creator_different_data",
                ]
            )

            if attack == "multiple_creators_same_block":
                # Two creators both claiming block 10
                dataset.add_new(Tag(group, 0x0010), "LO", "CREATOR_A")
                dataset.add_new(Tag(group, 0x1010), "LO", "DataFromA")
                # Overwrite creator
                dataset.add_new(Tag(group, 0x0010), "LO", "CREATOR_B")
                dataset.add_new(Tag(group, 0x1011), "LO", "DataFromB")

            elif attack == "creator_overwrites_data":
                # Put creator in data element position
                dataset.add_new(Tag(group, 0x0010), "LO", "CREATOR")
                dataset.add_new(Tag(group, 0x1010), "LO", "ANOTHER_CREATOR")  # Wrong!

            elif attack == "duplicate_creator_different_data":
                # Same creator ID in different blocks
                dataset.add_new(Tag(group, 0x0010), "LO", "SAME_CREATOR")
                dataset.add_new(Tag(group, 0x0011), "LO", "SAME_CREATOR")
                dataset.add_new(Tag(group, 0x1010), "LO", "Block10Data")
                dataset.add_new(Tag(group, 0x1110), "LO", "Block11Data")

        except Exception as e:
            logger.debug(f"Creator collision attack failed: {e}")

        return dataset

    def _invalid_private_vr(self, dataset: Dataset) -> Dataset:
        """Use invalid or unexpected VR for private data.

        Private data VR is often UN (Unknown) but vendors may
        expect specific VRs. Mismatches test type handling.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)
            creator = random.choice(KNOWN_CREATORS)

            dataset.add_new(Tag(group, 0x0010), "LO", creator)

            attack = random.choice(
                [
                    "numeric_as_string",
                    "string_as_binary",
                    "sequence_where_primitive",
                    "wrong_vr_class",
                ]
            )

            if attack == "numeric_as_string":
                # Numeric data stored as string
                dataset.add_new(Tag(group, 0x1010), "LO", "12345.6789")
                dataset.add_new(Tag(group, 0x1011), "DS", "NotANumber")

            elif attack == "string_as_binary":
                # String data as binary
                dataset.add_new(Tag(group, 0x1010), "OB", b"This is text")
                dataset.add_new(Tag(group, 0x1011), "OW", b"More text data")

            elif attack == "sequence_where_primitive":
                # Use SQ where primitive expected
                from pydicom.sequence import Sequence

                item = Dataset()
                item.add_new(Tag(0x0008, 0x0100), "SH", "CODE")
                dataset.add_new(Tag(group, 0x1010), "SQ", Sequence([item]))

            elif attack == "wrong_vr_class":
                # Mix VR classes inappropriately
                dataset.add_new(Tag(group, 0x1010), "US", 65535)  # Expect string
                dataset.add_new(Tag(group, 0x1011), "FL", 3.14159)  # Expect integer
                dataset.add_new(Tag(group, 0x1012), "AT", Tag(0x0010, 0x0010))

        except Exception as e:
            logger.debug(f"Invalid private VR attack failed: {e}")

        return dataset

    def _oversized_private_data(self, dataset: Dataset) -> Dataset:
        """Add oversized data in private elements.

        Private elements may not have length validation.
        Very large data can cause memory issues.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)
            dataset.add_new(Tag(group, 0x0010), "LO", "OVERSIZED_TEST")

            attack = random.choice(
                [
                    "large_string",
                    "large_binary",
                    "many_elements",
                ]
            )

            if attack == "large_string":
                # Very long string
                size = random.choice([10000, 100000, 1000000])
                dataset.add_new(Tag(group, 0x1010), "LT", "X" * size)

            elif attack == "large_binary":
                # Large binary blob
                size = random.choice([10000, 100000, 1000000])
                dataset.add_new(Tag(group, 0x1010), "OB", b"\x00" * size)

            elif attack == "many_elements":
                # Many private elements
                for i in range(256):  # Fill entire block
                    element = 0x1000 + i
                    if element <= 0x10FF:
                        dataset.add_new(Tag(group, element), "LO", f"Element_{i:04X}")

        except Exception as e:
            logger.debug(f"Oversized private data attack failed: {e}")

        return dataset

    def _private_tag_injection(self, dataset: Dataset) -> Dataset:
        """Inject potentially malicious data in private tags.

        Private tags are often displayed or processed differently.
        Injection payloads test sanitization.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)
            dataset.add_new(Tag(group, 0x0010), "LO", "INJECTION_TEST")

            for i, payload in enumerate(INJECTION_PAYLOADS[:10]):
                element = 0x1010 + i
                try:
                    dataset.add_new(Tag(group, element), "LO", payload)
                except Exception:
                    # Some payloads may fail, that's okay
                    pass

        except Exception as e:
            logger.debug(f"Private tag injection attack failed: {e}")

        return dataset

    def _creator_overwrite(self, dataset: Dataset) -> Dataset:
        """Attempt to overwrite standard tags with private tags.

        Test if private groups can interfere with standard data.
        """
        try:
            # Try using a standard group as private (should fail)
            standard_groups = [0x0008, 0x0010, 0x0018, 0x0020, 0x0028]
            group = random.choice(standard_groups)

            try:
                dataset.add_new(Tag(group, 0x0010), "LO", "HijackedCreator")
                dataset.add_new(Tag(group, 0x1010), "LO", "HijackedData")
            except Exception:
                pass  # Expected to fail

            # Also try odd groups in standard range
            for g in [0x0007, 0x000F, 0x0017]:
                try:
                    dataset.add_new(Tag(g, 0x0010), "LO", "OddGroupCreator")
                    dataset.add_new(Tag(g, 0x1010), "LO", "OddGroupData")
                except Exception:
                    pass  # Some groups may be rejected by pydicom

        except Exception as e:
            logger.debug(f"Creator overwrite attack failed: {e}")

        return dataset

    def _reserved_group_attack(self, dataset: Dataset) -> Dataset:
        """Use reserved or special group numbers.

        Certain groups are reserved (0x0001, 0x0003, 0x0005, 0x0007).
        Using them tests parser error handling.
        """
        try:
            reserved_groups = [0x0001, 0x0003, 0x0005, 0x0007, 0xFFFF]

            for group in reserved_groups:
                try:
                    dataset.add_new(Tag(group, 0x0010), "LO", f"Reserved_{group:04X}")
                    dataset.add_new(Tag(group, 0x1010), "LO", f"Data_{group:04X}")
                except Exception:
                    pass  # Reserved groups may be rejected by pydicom

            # Also try group 0x0000 (Command group, not for data)
            try:
                dataset.add_new(Tag(0x0000, 0x0010), "LO", "CommandGroupData")
            except Exception:
                pass  # Command group tags may be rejected

        except Exception as e:
            logger.debug(f"Reserved group attack failed: {e}")

        return dataset

    def _private_sequence_attack(self, dataset: Dataset) -> Dataset:
        """Create problematic sequences in private tags.

        Sequences in private tags may have different parsing
        than standard sequences.
        """
        try:
            from pydicom.sequence import Sequence

            group = random.choice(PRIVATE_GROUPS)
            dataset.add_new(Tag(group, 0x0010), "LO", "SEQUENCE_TEST")

            attack = random.choice(
                [
                    "deeply_nested",
                    "mixed_creators_in_items",
                    "circular_private_ref",
                ]
            )

            if attack == "deeply_nested":
                # Deeply nested private sequence
                def create_nested(depth: int) -> Dataset:
                    item = Dataset()
                    item.add_new(Tag(group, 0x1001), "LO", f"Level_{depth}")
                    if depth > 0:
                        item.add_new(
                            Tag(group, 0x1002),
                            "SQ",
                            Sequence([create_nested(depth - 1)]),
                        )
                    return item

                dataset.add_new(Tag(group, 0x1010), "SQ", Sequence([create_nested(50)]))

            elif attack == "mixed_creators_in_items":
                # Items with different creators
                items = []
                for i, creator in enumerate(KNOWN_CREATORS[:5]):
                    item = Dataset()
                    other_group = PRIVATE_GROUPS[(i + 1) % len(PRIVATE_GROUPS)]
                    item.add_new(Tag(other_group, 0x0010), "LO", creator)
                    item.add_new(Tag(other_group, 0x1010), "LO", f"Data_{i}")
                    items.append(item)

                dataset.add_new(Tag(group, 0x1010), "SQ", Sequence(items))

            elif attack == "circular_private_ref":
                # Private sequence referencing itself (sort of)
                item1 = Dataset()
                item1.add_new(Tag(group, 0x1001), "LO", "Item1")

                item2 = Dataset()
                item2.add_new(Tag(group, 0x1001), "LO", "Item2")

                # Item1 contains reference to where item2's data would be
                item1.add_new(Tag(group, 0x1002), "AT", Tag(group, 0x1010))

                dataset.add_new(Tag(group, 0x1010), "SQ", Sequence([item1, item2]))

        except Exception as e:
            logger.debug(f"Private sequence attack failed: {e}")

        return dataset

    def _binary_blob_injection(self, dataset: Dataset) -> Dataset:
        """Inject binary blobs that may be misinterpreted.

        Binary data in private tags could be parsed as
        executable or structured data.
        """
        try:
            group = random.choice(PRIVATE_GROUPS)
            dataset.add_new(Tag(group, 0x0010), "LO", "BINARY_BLOB_TEST")

            for i, blob in enumerate(BINARY_FILE_HEADERS):
                element = 0x1010 + i
                try:
                    dataset.add_new(Tag(group, element), "OB", blob)
                except Exception:
                    pass  # Some blob payloads may be rejected

        except Exception as e:
            logger.debug(f"Binary blob injection failed: {e}")

        return dataset
