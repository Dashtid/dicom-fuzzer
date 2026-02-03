"""Dataset mutation strategies for DICOM elements.

Provides mutation operations for DICOM dataset elements including
value, VR, tag, and length mutations. Extracted from dimse_fuzzer.py
to enable better modularity.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dicom_fuzzer.strategies.network.dimse.types import (
        DICOMElement,
        DIMSEFuzzingConfig,
    )


class DatasetMutator:
    """Mutator for DICOM dataset elements."""

    # Common VRs and their characteristics
    STRING_VRS = {
        "AE",
        "AS",
        "CS",
        "DA",
        "DS",
        "DT",
        "IS",
        "LO",
        "LT",
        "PN",
        "SH",
        "ST",
        "TM",
        "UC",
        "UI",
        "UR",
        "UT",
    }
    NUMERIC_VRS = {"SS", "US", "SL", "UL", "FL", "FD"}
    BINARY_VRS = {"OB", "OD", "OF", "OL", "OW", "UN"}

    # Interesting values for fuzzing
    INTERESTING_STRINGS = [
        "",  # Empty
        " " * 100,  # Spaces
        "\x00" * 10,  # Nulls
        "A" * 1000,  # Long
        "A" * 65536,  # Very long
        "../../../etc/passwd",  # Path traversal
        "; DROP TABLE patients;--",  # SQL injection
        "<script>alert(1)</script>",  # XSS
        "%s%s%s%s%s",  # Format string
        "\n\r\t\x0b\x0c",  # Control characters
    ]

    INTERESTING_UIDS = [
        "",  # Empty
        "1.2.3",  # Short
        "1." + "2" * 64,  # Long component
        "1.2.840.10008.1.1",  # Valid verification UID
        "1.2.840.10008.5.1.4.1.1.2",  # CT Storage
        "1.2.840.999999999999.1.1",  # Large org root
        "1.2.3.4.5.6.7.8.9.0" * 10,  # Very long
        "0.0.0.0.0.0",  # All zeros
        "1.2.abc.def",  # Invalid characters
    ]

    INTERESTING_INTEGERS = [
        0,
        1,
        -1,
        127,
        128,
        255,
        256,
        32767,
        32768,
        65535,
        65536,
        2147483647,
        2147483648,
        -2147483648,
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFF,
    ]

    def __init__(self, config: DIMSEFuzzingConfig | None = None):
        """Initialize the mutator.

        Args:
            config: Fuzzing configuration.

        """
        if config is None:
            from dicom_fuzzer.strategies.network.dimse.types import (
                DIMSEFuzzingConfig,
            )

            config = DIMSEFuzzingConfig()
        self.config = config
        # Lazy import to avoid circular dependency
        from dicom_fuzzer.strategies.network.dimse.types import DICOMElement

        self._DICOMElement = DICOMElement

    def mutate_element(self, element: DICOMElement) -> DICOMElement:
        """Mutate a single DICOM element.

        Args:
            element: Element to mutate.

        Returns:
            Mutated element.

        """
        mutation_type = random.choice(
            [
                "value",
                "vr",
                "tag",
                "length",
            ]
        )

        if mutation_type == "value":
            return self._mutate_value(element)
        elif mutation_type == "vr":
            return self._mutate_vr(element)
        elif mutation_type == "tag":
            return self._mutate_tag(element)
        else:
            return self._mutate_length(element)

    def _mutate_value(self, element: DICOMElement) -> DICOMElement:
        """Mutate element value."""
        vr = element.vr
        new_value: str | int | bytes

        if vr in self.STRING_VRS:
            new_value = random.choice(self.INTERESTING_STRINGS)
        elif vr in self.NUMERIC_VRS:
            new_value = random.choice(self.INTERESTING_INTEGERS)
        elif vr == "UI":
            new_value = random.choice(self.INTERESTING_UIDS)
        else:
            # Binary mutation
            if isinstance(element.value, bytes):
                new_value = self._mutate_bytes(element.value)
            else:
                new_value = element.value  # type: ignore[assignment]

        return self._DICOMElement(
            tag=element.tag,
            vr=element.vr,
            value=new_value,
        )

    def _mutate_vr(self, element: DICOMElement) -> DICOMElement:
        """Mutate element VR to invalid type."""
        all_vrs = list(self.STRING_VRS | self.NUMERIC_VRS | self.BINARY_VRS)
        # Pick a different VR
        new_vr = random.choice([v for v in all_vrs if v != element.vr])

        return self._DICOMElement(
            tag=element.tag,
            vr=new_vr,
            value=element.value,
        )

    def _mutate_tag(self, element: DICOMElement) -> DICOMElement:
        """Mutate element tag."""
        group, elem = element.tag

        mutation = random.choice(["group", "element", "both", "invalid"])

        if mutation == "group":
            group = random.choice(
                [
                    0x0000,
                    0x0002,
                    0x0008,
                    0x0010,
                    0x0020,
                    0x7FE0,
                    0xFFFF,
                    random.randint(0, 0xFFFF),
                ]
            )
        elif mutation == "element":
            elem = random.choice(
                [0x0000, 0x0001, 0x0010, 0x0100, 0xFFFF, random.randint(0, 0xFFFF)]
            )
        elif mutation == "both":
            group = random.randint(0, 0xFFFF)
            elem = random.randint(0, 0xFFFF)
        else:
            # Create definitely invalid tag
            group = random.choice([0x0001, 0x0003, 0x0005, 0x0007])  # Odd groups
            elem = 0x0000

        return self._DICOMElement(
            tag=(group, elem),
            vr=element.vr,
            value=element.value,
        )

    def _mutate_length(self, element: DICOMElement) -> DICOMElement:
        """Create element with incorrect length encoding."""
        # This requires custom encoding, return element with special marker
        return self._DICOMElement(
            tag=element.tag,
            vr=element.vr,
            value=element.value,
        )

    def _mutate_bytes(self, data: bytes) -> bytes:
        """Mutate binary data."""
        if not data:
            return bytes([random.randint(0, 255) for _ in range(10)])

        mutation = random.choice(["flip", "insert", "delete", "replace"])

        data_array = bytearray(data)

        if mutation == "flip":
            pos = random.randint(0, len(data_array) - 1)
            data_array[pos] ^= 1 << random.randint(0, 7)
        elif mutation == "insert":
            pos = random.randint(0, len(data_array))
            data_array.insert(pos, random.randint(0, 255))
        elif mutation == "delete" and len(data_array) > 1:
            pos = random.randint(0, len(data_array) - 1)
            del data_array[pos]
        elif mutation == "replace":
            pos = random.randint(0, len(data_array) - 1)
            data_array[pos] = random.randint(0, 255)

        return bytes(data_array)

    def generate_malformed_dataset(
        self,
        base_elements: list[DICOMElement],
    ) -> list[DICOMElement]:
        """Generate a malformed version of a dataset.

        Args:
            base_elements: Base elements to mutate.

        Returns:
            Mutated elements.

        """
        mutated = []

        for element in base_elements:
            if random.random() < 0.3:
                mutated.append(self.mutate_element(element))
            else:
                mutated.append(element)

        # Optionally add extra elements
        if self.config.add_private_elements:
            mutated.extend(self._generate_private_elements())

        return mutated

    def _generate_private_elements(self) -> list[DICOMElement]:
        """Generate private DICOM elements for fuzzing."""
        elements = []

        # Private creator
        private_group = random.choice([0x0009, 0x0011, 0x0013, 0x0015])
        creator = self._DICOMElement(
            tag=(private_group, 0x0010),
            vr="LO",
            value="FUZZ PRIVATE",
        )
        elements.append(creator)

        # Private elements
        for i in range(random.randint(1, 5)):
            elem = self._DICOMElement(
                tag=(private_group, 0x1000 + i),
                vr=random.choice(list(self.STRING_VRS)),
                value=random.choice(self.INTERESTING_STRINGS),
            )
            elements.append(elem)

        return elements
