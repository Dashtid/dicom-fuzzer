"""Structure Fuzzer - DICOM File Structure Mutations.

Targets the DICOM file structure itself (preamble, prefix, tag ordering,
length fields) rather than just data values. Tests parser robustness against
malformed file structures that may trigger crashes or buffer overflows.

Extended to include:
- Length field attacks (integer overflow/underflow)
- Transfer syntax violations
- VM (Value Multiplicity) mismatches

Based on CVE patterns:
- Integer underflow in length calculations
- Buffer overread from length > actual data
- Encoding confusion from transfer syntax mismatches
"""

import random
import struct

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class StructureFuzzer:
    """Fuzzes the underlying DICOM file structure.

    Targets the binary structure of DICOM files:
    - File preamble (128 bytes)
    - DICOM prefix "DICM" (4 bytes)
    - Data elements with tags, VRs, and lengths
    """

    def __init__(self) -> None:
        """Initialize the structure fuzzer with attack patterns."""
        self.corruption_strategies = [
            self._corrupt_tag_ordering,
            self._corrupt_length_fields,
            self._insert_unexpected_tags,
            self._duplicate_tags,
            self._length_field_attacks,
            self._vm_mismatch_attacks,
        ]

    def mutate_structure(self, dataset: Dataset) -> Dataset:
        """Apply structure-level mutations to the dataset.

        Randomly selects 1-2 corruption strategies, each targeting
        a different aspect of DICOM structure.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with structure corruptions

        """
        # Randomly select 1-2 corruption strategies to apply
        num_strategies = random.randint(1, 2)
        selected_strategies = random.sample(self.corruption_strategies, num_strategies)

        for strategy in selected_strategies:
            dataset = strategy(dataset)

        return dataset

    def _corrupt_tag_ordering(self, dataset: Dataset) -> Dataset:
        """Corrupt the ordering of DICOM tags.

        DICOM tags must be in ascending numerical order per the spec.
        Breaking this order tests parser assumptions about tag ordering.

        Args:
            dataset: Dataset to corrupt

        Returns:
            Dataset with potentially scrambled tag order

        """
        # Get all data elements as a list
        elements = list(dataset.items())

        if len(elements) > 2:
            # Swap two random elements to break ordering
            idx1, idx2 = random.sample(range(len(elements)), 2)
            elements[idx1], elements[idx2] = elements[idx2], elements[idx1]

            # Rebuild dataset with corrupted order
            new_dataset = Dataset()
            if hasattr(dataset, "file_meta"):
                new_dataset.file_meta = dataset.file_meta
            for tag, element in elements:
                new_dataset[tag] = element

            return new_dataset

        return dataset

    def _corrupt_length_fields(self, dataset: Dataset) -> Dataset:
        """Corrupt length fields in DICOM data elements.

        Each DICOM element has a length field indicating data size.
        Incorrect lengths can cause buffer overflows, integer overflow,
        or parser loops.

        Args:
            dataset: Dataset to corrupt

        Returns:
            Dataset with corrupted length indicators

        """
        # Target string-type elements for length corruption
        string_tags = [
            tag
            for tag, element in dataset.items()
            if hasattr(element, "VR")
            and element.VR in ["LO", "SH", "PN", "LT", "ST", "UT"]
        ]

        if string_tags:
            # Pick a random tag to corrupt
            target_tag = random.choice(string_tags)
            element = dataset[target_tag]

            # Apply length corruption strategy
            corruption_type = random.choice(["overflow", "underflow", "mismatch"])

            if corruption_type == "overflow":
                # Make value much longer than declared (buffer overflow test)
                element.value = str(element.value) + ("X" * 10000)
            elif corruption_type == "underflow":
                # Make value very short (underflow test)
                element.value = ""
            elif corruption_type == "mismatch":
                # Add null bytes in the middle (length mismatch)
                current_value = str(element.value)
                if len(current_value) > 2:
                    insert_pos = len(current_value) // 2
                    element.value = (
                        current_value[:insert_pos]
                        + "\x00" * 5
                        + current_value[insert_pos:]
                    )

        return dataset

    def _insert_unexpected_tags(self, dataset: Dataset) -> Dataset:
        """Insert unexpected or reserved DICOM tags.

        Inserts tags from reserved ranges or private tag space to test
        parser handling of unexpected elements.

        Args:
            dataset: Dataset to modify

        Returns:
            Dataset with unexpected tags inserted

        """
        # Define some problematic tag values
        unusual_tags = [
            0xFFFFFFFF,  # Maximum tag value (invalid)
            0x00000000,  # Minimum tag value
            0xDEADBEEF,  # Arbitrary private tag
            0x7FE00010,  # Pixel Data tag (duplicate if already exists)
        ]

        # Insert 1-2 unusual tags
        num_tags = random.randint(1, 2)
        for _ in range(num_tags):
            tag = random.choice(unusual_tags)
            try:
                # Try to add the unusual tag with garbage data
                dataset.add_new(tag, "UN", b"\x00" * 100)
            except Exception as e:
                # If it fails, that's fine - some tags can't be added
                logger.debug(f"Failed to add unusual tag {tag}: {e}")

        return dataset

    def _duplicate_tags(self, dataset: Dataset) -> Dataset:
        """Create duplicate DICOM tags.

        DICOM specifies each tag should appear once. Parsers may use
        first occurrence, last occurrence, or crash on duplicates.

        Args:
            dataset: Dataset to modify

        Returns:
            Dataset with duplicated tags

        """
        # Get existing tags
        existing_tags = list(dataset.keys())

        if existing_tags:
            # Pick a random tag to duplicate
            tag_to_duplicate = random.choice(existing_tags)

            try:
                # Get the original element
                original_element = dataset[tag_to_duplicate]

                # Try to add it again with different value
                # Note: pydicom may prevent this, but we try anyway
                if hasattr(original_element, "value"):
                    # Modify the value slightly
                    new_value = str(original_element.value) + "_DUPLICATE"
                    dataset.add_new(tag_to_duplicate, original_element.VR, new_value)
            except Exception as e:
                # If duplication fails, continue
                logger.debug(f"Failed to duplicate tag {tag_to_duplicate}: {e}")

        return dataset

    def _length_field_attacks(self, dataset: Dataset) -> Dataset:
        """Apply length field attacks to test integer overflow/underflow.

        Targets:
        - Undefined length (0xFFFFFFFF) for non-SQ/non-Item elements
        - Length > actual data (buffer overread)
        - Length = 0 for elements that require data
        - Very large lengths (2GB+) for signed/unsigned issues

        These patterns commonly trigger CVEs in DICOM parsers.
        """
        attack = random.choice([
            "extreme_length_value",
            "zero_length_required",
            "negative_interpreted_as_large",
        ])

        # Find elements to attack
        elements = list(dataset.items())
        if not elements:
            return dataset

        tag, element = random.choice(elements)

        try:
            if attack == "extreme_length_value":
                # Attempt to set element with data that suggests wrong length
                # pydicom calculates length, but we can create mismatch scenarios
                if hasattr(element, "value") and isinstance(element.value, str):
                    # Add data that would overflow various length calculations
                    # 65535 bytes triggers 16-bit overflow
                    # 2GB+ triggers signed 32-bit overflow
                    sizes = [65535, 65536, 2147483647, 2147483648]
                    size = random.choice(sizes)
                    # Can't actually create 2GB strings, but we set metadata
                    if size <= 100000:  # Only actually create up to 100KB
                        element.value = "X" * size

            elif attack == "zero_length_required":
                # Set zero-length value for elements that shouldn't be empty
                required_vrs = ["UI", "DA", "TM", "PN"]
                if hasattr(element, "VR") and element.VR in required_vrs:
                    element._value = ""

            elif attack == "negative_interpreted_as_large":
                # For numeric elements, set values that when interpreted
                # as lengths in other contexts cause issues
                if hasattr(element, "VR") and element.VR in ["UL", "US"]:
                    # -1 as unsigned = MAX value
                    if element.VR == "UL":
                        element.value = 4294967295  # 0xFFFFFFFF
                    else:
                        element.value = 65535  # 0xFFFF

        except Exception:
            pass

        return dataset

    def _vm_mismatch_attacks(self, dataset: Dataset) -> Dataset:
        """Create Value Multiplicity (VM) mismatches.

        VM defines how many values an element should have.
        Mismatches can cause:
        - Index out of bounds
        - Null pointer when expected value missing
        - Buffer overflow when too many values
        """
        # Tags with specific VM requirements
        vm_targets = [
            # Tag, expected VM, attack
            (Tag(0x0020, 0x0032), 3, "too_few"),  # ImagePositionPatient (VM=3)
            (Tag(0x0020, 0x0037), 6, "too_few"),  # ImageOrientationPatient (VM=6)
            (Tag(0x0028, 0x0030), 2, "too_few"),  # PixelSpacing (VM=2)
            (Tag(0x0018, 0x0050), 1, "too_many"),  # SliceThickness (VM=1)
            (Tag(0x0008, 0x0018), 1, "too_many"),  # SOPInstanceUID (VM=1)
        ]

        attack = random.choice([
            "too_few_values",
            "too_many_values",
            "empty_multivalue",
        ])

        try:
            if attack == "too_few_values":
                # Give fewer values than VM requires
                targets = [(t, vm) for t, vm, a in vm_targets if a == "too_few"]
                if targets:
                    tag, expected_vm = random.choice(targets)
                    if tag in dataset:
                        # Set only one value when more expected
                        elem = dataset[tag]
                        if hasattr(elem, "VR") and elem.VR == "DS":
                            elem._value = "1.0"  # Only 1 value
                        elif hasattr(elem, "VR") and elem.VR == "FL":
                            elem._value = struct.pack("<f", 1.0)

            elif attack == "too_many_values":
                # Give more values than VM allows
                targets = [(t, vm) for t, vm, a in vm_targets if a == "too_many"]
                if targets:
                    tag, expected_vm = random.choice(targets)
                    if tag in dataset:
                        elem = dataset[tag]
                        if hasattr(elem, "VR"):
                            if elem.VR == "DS":
                                # Multiple values separated by backslash
                                elem._value = "\\".join(["1.0"] * 10)
                            elif elem.VR == "UI":
                                elem._value = "\\".join(["1.2.3.4"] * 5)

            elif attack == "empty_multivalue":
                # Empty string where multiple values expected
                for tag, vm, _ in vm_targets:
                    if tag in dataset and vm > 1:
                        dataset[tag]._value = ""
                        break

        except Exception:
            pass

        return dataset

    def _corrupt_preamble(self, file_data: bytearray) -> bytearray:
        """Corrupt the 128-byte preamble."""
        if len(file_data) >= 128:
            for _ in range(10):
                pos = random.randint(0, 127)
                file_data[pos] = random.randint(0, 255)
        return file_data

    def _corrupt_dicm_prefix(self, file_data: bytearray) -> bytearray:
        """Corrupt the DICM prefix at bytes 128-131."""
        if len(file_data) >= 132:
            file_data[128:132] = b"XXXX"
        return file_data

    def _corrupt_transfer_syntax(self, file_data: bytearray) -> bytearray:
        """Corrupt transfer syntax UID area."""
        if len(file_data) >= 200:
            for _ in range(5):
                pos = random.randint(132, min(200, len(file_data) - 1))
                file_data[pos] = random.randint(0, 255)
        return file_data

    def _truncate_file(self, file_data: bytearray) -> bytearray:
        """Truncate file at random position."""
        if len(file_data) > 1000:
            truncate_pos = random.randint(500, len(file_data) - 1)
            return file_data[:truncate_pos]
        return file_data

    def corrupt_file_header(
        self, file_path: str, output_path: str | None = None
    ) -> str | None:
        """Directly corrupt the DICOM file header at binary level.

        Operates on raw bytes to corrupt preamble, DICM prefix, or transfer
        syntax - bypasses high-level validation.

        Args:
            file_path: Path to input DICOM file
            output_path: Path for corrupted output (or auto-generate)

        Returns:
            Path to corrupted file, or None on failure

        """
        corruption_handlers = {
            "corrupt_preamble": self._corrupt_preamble,
            "corrupt_dicm_prefix": self._corrupt_dicm_prefix,
            "corrupt_transfer_syntax": self._corrupt_transfer_syntax,
            "truncate_file": self._truncate_file,
        }

        try:
            with open(file_path, "rb") as f:
                file_data = bytearray(f.read())

            corruption_type = random.choice(list(corruption_handlers.keys()))
            file_data = corruption_handlers[corruption_type](file_data)

            if output_path is None:
                output_path = file_path.replace(".dcm", "_header_corrupted.dcm")

            with open(output_path, "wb") as f:
                f.write(file_data)

            return output_path

        except Exception as e:
            print(f"Header corruption failed: {e}")
            return None


def create_transfer_syntax_attacks() -> list[tuple[str, bytes]]:
    """Create binary attacks targeting transfer syntax handling.

    Returns list of (attack_name, bytes) for injection/replacement in DICOM files.
    These test encoding edge cases that commonly cause parser confusion.
    """
    attacks = []

    # Transfer Syntax UID tag in file meta
    ts_tag = b"\x02\x00\x10\x00"  # (0002,0010)

    # Attack 1: Unknown transfer syntax UID
    unknown_ts = (
        ts_tag
        + b"UI"  # VR
        + b"\x1A\x00"  # Length = 26
        + b"9.9.999.99999.9.9.9.9.9.9"  # Invalid TS UID
        + b"\x00"  # Padding
    )
    attacks.append(("unknown_transfer_syntax", unknown_ts))

    # Attack 2: Empty transfer syntax
    empty_ts = (
        ts_tag
        + b"UI"
        + b"\x00\x00"  # Length = 0
    )
    attacks.append(("empty_transfer_syntax", empty_ts))

    # Attack 3: Very long transfer syntax UID
    long_ts = (
        ts_tag
        + b"UI"
        + b"\x00\x01"  # Length = 256
        + b"1.2.840." + b"9" * 248  # Long UID
    )
    attacks.append(("long_transfer_syntax", long_ts))

    # Attack 4: Transfer syntax with null bytes
    null_ts = (
        ts_tag
        + b"UI"
        + b"\x20\x00"  # Length = 32
        + b"1.2.840.10008\x00\x00\x00.1.2.1"  # Embedded nulls
        + b"\x00" * 6  # Padding
    )
    attacks.append(("null_in_transfer_syntax", null_ts))

    # Attack 5: Explicit VR tag in implicit VR file (mixed encoding)
    # This simulates switching from implicit to explicit mid-file
    mixed_encoding = (
        b"\x08\x00\x18\x00"  # SOPInstanceUID tag (little endian)
        + b"UI"  # Explicit VR (shouldn't be here in implicit file)
        + b"\x00\x00"  # Reserved
        + b"\x20\x00\x00\x00"  # 32-bit length (explicit VR long form)
        + b"1.2.3.4.5.6.7.8.9.0.1.2.3.4.5"  # UID
        + b"\x00"  # Padding
    )
    attacks.append(("mixed_explicit_implicit", mixed_encoding))

    # Attack 6: Big endian tag in little endian file
    wrong_endian = (
        b"\x00\x08\x00\x18"  # SOPInstanceUID in big endian (swapped bytes)
        + b"\x00\x00\x00\x20"  # Length in big endian
        + b"1.2.3.4.5.6.7.8.9.0.1.2.3.4.5"
        + b"\x00\x00"
    )
    attacks.append(("wrong_endianness", wrong_endian))

    # Attack 7: Deflated syntax indicator but uncompressed data
    # Claims to be deflated but data is raw
    fake_deflate_ts = (
        ts_tag
        + b"UI"
        + b"\x18\x00"  # Length = 24
        + b"1.2.840.10008.1.2.1.99"  # Deflated Explicit VR LE
        + b"\x00\x00"  # Padding
    )
    attacks.append(("fake_deflated", fake_deflate_ts))

    return attacks


def create_length_overflow_attacks() -> list[tuple[str, bytes]]:
    """Create binary attacks targeting length field parsing.

    Returns list of (attack_name, bytes) for file corruption.
    These target integer overflow/underflow in length calculations.
    """
    attacks = []

    # Generic tag for length tests
    test_tag = b"\x08\x00\x50\x00"  # AccessionNumber (0008,0050)

    # Attack 1: 32-bit max length (undefined length marker)
    undefined_len = (
        test_tag
        + b"LO"  # VR
        + b"\x00\x00"  # Reserved
        + b"\xFF\xFF\xFF\xFF"  # 0xFFFFFFFF = undefined length
        + b"TEST"  # Some data (parser should keep reading)
    )
    attacks.append(("undefined_length_non_sq", undefined_len))

    # Attack 2: Length claims more data than file contains
    oversize_len = (
        test_tag
        + b"LO"
        + b"\x00\x00"
        + b"\x00\x10\x00\x00"  # Length = 4096 bytes
        + b"ONLY16BYTESHERE!"  # Only 16 bytes of actual data
    )
    attacks.append(("length_exceeds_data", oversize_len))

    # Attack 3: 16-bit max length for short VRs
    max_short_len = (
        test_tag
        + b"SH"  # Short string VR (uses 16-bit length)
        + b"\xFF\xFF"  # 0xFFFF = 65535 bytes
        + b"SHORT"  # Only 5 bytes
    )
    attacks.append(("max_16bit_length", max_short_len))

    # Attack 4: Length = 1 (odd, invalid for word-aligned VRs)
    odd_length = (
        b"\xE0\x7F\x10\x00"  # PixelData tag
        + b"OW"  # Other Word (must be even length)
        + b"\x00\x00"
        + b"\x01\x00\x00\x00"  # Length = 1 (odd!)
        + b"\xFF"  # Single byte
    )
    attacks.append(("odd_length_ow", odd_length))

    # Attack 5: Signed interpretation attack
    # Length that's negative if interpreted as signed 32-bit
    signed_negative = (
        test_tag
        + b"LO"
        + b"\x00\x00"
        + b"\x00\x00\x00\x80"  # 0x80000000 = -2147483648 as signed
        + b"DATA"
    )
    attacks.append(("signed_negative_length", signed_negative))

    # Attack 6: Length causes integer overflow when multiplied
    # E.g., Rows * Columns * BitsAllocated / 8 overflows
    # This is set via header values, not directly in element
    overflow_dimensions = (
        # Rows = 65535
        b"\x28\x00\x10\x00"  # Rows tag
        + b"US"
        + b"\x02\x00"  # Length = 2
        + b"\xFF\xFF"  # 65535
        # Columns = 65535
        + b"\x28\x00\x11\x00"  # Columns tag
        + b"US"
        + b"\x02\x00"
        + b"\xFF\xFF"  # 65535
        # 65535 * 65535 = 4294836225, overflows 32-bit signed
    )
    attacks.append(("dimension_overflow", overflow_dimensions))

    return attacks
