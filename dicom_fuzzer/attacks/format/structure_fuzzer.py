"""Structure Fuzzer - DICOM File Structure Mutations.

Category: generic

Attacks:
- Tag ordering violations (out-of-order group/element)
- Length field corruption (truncated, oversized, undefined)
- Unexpected tag insertion
- Duplicate tag entries
- Value Multiplicity (VM) violations
- Binary-level tag ordering, duplicate tag, and length field corruption
- Binary-level VR field corruption (whitespace, null, dash, UN substitution)
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# DICOM file layout constants
_DICM_MAGIC = b"DICM"
_DICM_OFFSET = 128
_DATA_OFFSET = 132  # preamble (128) + "DICM" (4)

# VRs that use 2-byte reserved field + 4-byte length (instead of 2-byte length)
_LONG_VRS = frozenset(
    {b"OB", b"OD", b"OF", b"OL", b"OW", b"SQ", b"UC", b"UN", b"UR", b"UT"}
)


def _parse_dicom_elements(
    file_data: bytes, start_offset: int
) -> list[tuple[int, int, int, int]]:
    """Parse Explicit VR Little Endian DICOM elements starting at start_offset.

    Returns list of (elem_start, elem_end, len_field_offset, len_field_size).

    Skips:
    - Group 0002 elements (file meta -- must stay intact for readers)
    - SQ elements (nested structure; swapping breaks internal references)
    - Elements with undefined length (0xFFFFFFFF / 0xFFFF)
    - Group 0xFFFE item/delimiter tags

    Stops and returns a partial list on any parse error.

    Args:
        file_data: Complete DICOM file bytes
        start_offset: Byte offset to begin parsing (after preamble + DICM)

    Returns:
        List of (elem_start, elem_end, len_field_offset, len_field_size) tuples

    """
    results: list[tuple[int, int, int, int]] = []
    pos = start_offset
    data_len = len(file_data)

    try:
        while pos + 4 <= data_len:
            elem_start = pos

            # Read group and element (2 bytes each, little-endian)
            group = struct.unpack_from("<H", file_data, pos)[0]
            pos += 2
            pos += 2  # element number -- not needed for candidate selection

            # Skip group 0002 (file meta) -- must remain intact
            if group == 0x0002:
                # Still need to advance past this element
                if pos + 2 > data_len:
                    break
                vr = file_data[pos : pos + 2]
                pos += 2
                if vr in _LONG_VRS:
                    pos += 2  # skip 2-byte reserved
                    if pos + 4 > data_len:
                        break
                    length = struct.unpack_from("<I", file_data, pos)[0]
                    pos += 4
                else:
                    if pos + 2 > data_len:
                        break
                    length = struct.unpack_from("<H", file_data, pos)[0]
                    pos += 2
                if length == 0xFFFFFFFF or length == 0xFFFF:
                    break  # undefined length in file meta -- stop
                pos += length
                continue

            # Stop at item/delimiter tags (group 0xFFFE)
            if group == 0xFFFE:
                break

            # Need at least VR (2 bytes)
            if pos + 2 > data_len:
                break

            vr = file_data[pos : pos + 2]
            pos += 2

            if vr in _LONG_VRS:
                # 2-byte reserved + 4-byte length
                pos += 2  # skip reserved
                if pos + 4 > data_len:
                    break
                len_field_offset = pos
                len_field_size = 4
                length = struct.unpack_from("<I", file_data, pos)[0]
                pos += 4
            else:
                # 2-byte length
                if pos + 2 > data_len:
                    break
                len_field_offset = pos
                len_field_size = 2
                length = struct.unpack_from("<H", file_data, pos)[0]
                pos += 2

            # Skip undefined-length elements and SQ
            if length == 0xFFFFFFFF or (len_field_size == 2 and length == 0xFFFF):
                break  # can't safely skip; stop here
            if vr == b"SQ":
                pos += length
                continue

            elem_end = pos + length
            if elem_end > data_len:
                break

            results.append((elem_start, elem_end, len_field_offset, len_field_size))
            pos = elem_end

    except struct.error:
        pass  # return whatever we parsed so far

    return results


class StructureFuzzer(FormatFuzzerBase):
    """Fuzzes the underlying DICOM file structure.

    Targets data element structure: tags, VRs, lengths, and value
    multiplicity within pydicom Dataset objects.
    """

    def __init__(self) -> None:
        """Initialize the structure fuzzer with attack patterns."""
        super().__init__()
        self.corruption_strategies = [
            self._corrupt_tag_ordering,  # [STRUCTURAL] shuffled elements violate strict-parser sort assumption
            self._corrupt_length_fields,  # [STRUCTURAL] overflow/underflow/null patterns in string length fields
            self._insert_unexpected_tags,  # [STRUCTURAL] reserved/invalid group tags trigger unguarded handlers
            self._duplicate_tags,  # [STRUCTURAL] duplicate tag presence crashes parsers assuming uniqueness
            self._length_field_attacks,  # [STRUCTURAL] extreme/zero/negative/odd/boundary length values
            self._vm_mismatch_attacks,  # [STRUCTURAL] VM mismatch — wrong array allocation size
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "structure"

    def mutate(self, dataset: Dataset) -> Dataset:
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
        self.last_variant = ",".join(s.__name__ for s in selected_strategies)

        for strategy in selected_strategies:
            dataset = strategy(dataset)

        return dataset

    def _corrupt_tag_ordering(self, dataset: Dataset) -> Dataset:
        """Rebuild dataset from shuffled element list.

        Note: pydicom re-sorts elements by tag number on insertion, so
        the output tag order is unchanged. The mutation still rebuilds
        the Dataset object, which may lose non-tag metadata. For true
        tag-order corruption, operate on raw bytes (see backlog).

        Args:
            dataset: Dataset to corrupt

        Returns:
            Rebuilt dataset (tag order preserved by pydicom)

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
        """Mutate string element values with overflow/underflow/null patterns.

        Note: pydicom recalculates length fields from actual values on
        write, so the output file has correct lengths for the new values.
        The mutations still stress parsers via extreme-length strings,
        empty required fields, and embedded null bytes. For true
        length-field corruption, operate on raw bytes (see backlog).

        Args:
            dataset: Dataset to corrupt

        Returns:
            Dataset with mutated string values

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
                logger.debug("Failed to add unusual tag %s: %s", tag, e)

        return dataset

    # VR types that pydicom validates as numeric
    _NUMERIC_VRS = frozenset({"DS", "IS", "FL", "FD", "US", "SS", "UL", "SL"})

    def _duplicate_tags(self, dataset: Dataset) -> Dataset:
        """Overwrite a random tag's value with a modified copy.

        Note: pydicom cannot hold two elements with the same tag, so
        add_new overwrites the existing value. For string VRs the mutation
        appends "_DUPLICATE". For numeric VRs (DS, IS, FL, FD, etc.) it
        appends "99" to stay valid enough for pydicom to accept.

        Args:
            dataset: Dataset to modify

        Returns:
            Dataset with one tag value modified

        """
        existing_tags = list(dataset.keys())

        if existing_tags:
            tag_to_duplicate = random.choice(existing_tags)

            try:
                original_element = dataset[tag_to_duplicate]

                if hasattr(original_element, "value"):
                    vr = original_element.VR
                    if vr in self._NUMERIC_VRS:
                        # Numeric VRs: append digits to stay parseable
                        new_value = str(original_element.value) + "99"
                    elif vr == "SQ":
                        # Skip sequences -- can't assign a string
                        return dataset
                    else:
                        new_value = str(original_element.value) + "_DUPLICATE"
                    dataset.add_new(tag_to_duplicate, vr, new_value)
            except Exception as e:
                logger.debug("Failed to duplicate tag %s: %s", tag_to_duplicate, e)

        return dataset

    def _length_field_attacks(self, dataset: Dataset) -> Dataset:
        """Apply length field attacks to test integer overflow/underflow.

        Targets:
        - Undefined length (0xFFFFFFFF) for non-SQ/non-Item elements
        - Length > actual data (buffer overread)
        - Length = 0 for elements that require data
        - Very large lengths (2GB+) for signed/unsigned issues
        - Odd length for word-aligned VRs (OW, OF, OD, etc.)

        These patterns commonly trigger CVEs in DICOM parsers.
        """
        attack = random.choice(
            [
                "extreme_length_value",
                "zero_length_required",
                "negative_interpreted_as_large",
                "odd_length_word_aligned",
                "boundary_length_values",
            ]
        )

        # Find elements to attack
        elements = list(dataset.items())
        if not elements:
            return dataset

        _, element = random.choice(elements)

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
                        element.value = "X" * size  # pyright: ignore[reportAttributeAccessIssue]

            elif attack == "zero_length_required":
                # Set zero-length value for elements that shouldn't be empty
                required_vrs = ["UI", "DA", "TM", "PN"]
                if hasattr(element, "VR") and element.VR in required_vrs:
                    element._value = ""  # pyright: ignore[reportAttributeAccessIssue]
            elif attack == "negative_interpreted_as_large":
                # For numeric elements, set values that when interpreted
                # as lengths in other contexts cause issues
                if hasattr(element, "VR") and element.VR in ["UL", "US"]:
                    # -1 as unsigned = MAX value
                    if element.VR == "UL":
                        element.value = 4294967295  # pyright: ignore[reportAttributeAccessIssue]  # 0xFFFFFFFF
                    else:
                        element.value = 65535  # pyright: ignore[reportAttributeAccessIssue]  # 0xFFFF

            elif attack == "odd_length_word_aligned":
                # Set odd-length data for VRs that require even length
                # OW (Other Word) requires 2-byte alignment
                # OF (Other Float) requires 4-byte alignment
                # OD (Other Double) requires 8-byte alignment
                word_aligned_vrs = [
                    "OW",
                    "OF",
                    "OD",
                    "OL",
                    "FL",
                    "FD",
                    "SL",
                    "SS",
                    "UL",
                    "US",
                ]
                for _t, elem in dataset.items():
                    if hasattr(elem, "VR") and elem.VR in word_aligned_vrs:
                        # Set odd-length bytes that violate alignment
                        if elem.VR in ["OW", "US", "SS"]:
                            elem._value = b"\x00\x00\x00"  # pyright: ignore[reportAttributeAccessIssue]  # 3 bytes, should be 2
                        elif elem.VR in ["OF", "FL", "UL", "SL", "OL"]:
                            elem._value = b"\x00\x00\x00\x00\x00"  # pyright: ignore[reportAttributeAccessIssue]  # 5 bytes, should be 4
                        elif elem.VR in ["OD", "FD"]:
                            elem._value = b"\x00" * 7  # pyright: ignore[reportAttributeAccessIssue]  # 7 bytes, should be 8
                        break

            elif attack == "boundary_length_values":
                # Test specific boundary values that cause issues
                boundary_sizes = [
                    0xFFFF,  # 16-bit max
                    0x10000,  # 16-bit overflow
                    0x7FFFFFFF,  # 32-bit signed max
                    0x80000000,  # 32-bit signed overflow
                ]
                if hasattr(element, "value") and isinstance(
                    element.value, (str, bytes)
                ):
                    size = random.choice(boundary_sizes)
                    if size <= 100000:  # Only create reasonable sized data
                        if isinstance(element.value, str):
                            element.value = "X" * size  # pyright: ignore[reportAttributeAccessIssue]
                        else:
                            element._value = b"\x00" * size  # pyright: ignore[reportAttributeAccessIssue]

        except Exception as e:
            logger.debug("Length field attack failed: %s", e)

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

        attack = random.choice(
            [
                "too_few_values",
                "too_many_values",
                "empty_multivalue",
            ]
        )

        try:
            if attack == "too_few_values":
                # Give fewer values than VM requires
                targets = [(t, vm) for t, vm, a in vm_targets if a == "too_few"]
                if targets:
                    tag, _ = random.choice(targets)
                    if tag in dataset:
                        # Set only one value when more expected
                        elem = dataset[tag]
                        if hasattr(elem, "VR") and elem.VR == "DS":
                            elem._value = "1.0"  # pyright: ignore[reportAttributeAccessIssue]  # Only 1 value
                        elif hasattr(elem, "VR") and elem.VR == "FL":
                            elem._value = struct.pack("<f", 1.0)  # pyright: ignore[reportAttributeAccessIssue]
            elif attack == "too_many_values":
                # Give more values than VM allows
                targets = [(t, vm) for t, vm, a in vm_targets if a == "too_many"]
                if targets:
                    tag, _ = random.choice(targets)
                    if tag in dataset:
                        elem = dataset[tag]
                        if hasattr(elem, "VR"):
                            if elem.VR == "DS":
                                # Multiple values separated by backslash
                                elem._value = "\\".join(["1.0"] * 10)  # pyright: ignore[reportAttributeAccessIssue]
                            elif elem.VR == "UI":
                                elem._value = "\\".join(["1.2.3.4"] * 5)  # pyright: ignore[reportAttributeAccessIssue]
            elif attack == "empty_multivalue":
                # Empty string where multiple values expected
                for tag, vm, _ in vm_targets:
                    if tag in dataset and vm > 1:
                        dataset[tag]._value = ""  # pyright: ignore[reportAttributeAccessIssue]
                        break

        except Exception as e:
            logger.debug("VM mismatch attack failed: %s", e)

        return dataset

    # ------------------------------------------------------------------
    # Binary-level attacks -- operate on raw bytes after pydicom write
    # ------------------------------------------------------------------

    # Corrupt length values for 4-byte length fields
    _CORRUPT_LENGTHS_4B: list[bytes] = [
        struct.pack("<I", 0xFFFFFFFF),  # undefined-length sentinel
        struct.pack("<I", 0x00000000),  # zero length for non-empty element
        struct.pack("<I", 0x7FFFFFFF),  # 2 GB-1 (signed 32-bit max)
        struct.pack("<I", 0x80000000),  # signed 32-bit overflow
        struct.pack("<I", 0x0000FFFF),  # 16-bit max in 32-bit field
        struct.pack("<I", 0x00010000),  # 16-bit overflow
    ]

    # Corrupt length values for 2-byte length fields
    _CORRUPT_LENGTHS_2B: list[bytes] = [
        struct.pack("<H", 0xFFFF),  # max 16-bit (undefined sentinel for short VRs)
        struct.pack("<H", 0x0000),  # zero length
        struct.pack("<H", 0x8000),  # signed 16-bit overflow
    ]

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Apply binary-level structure corruptions after pydicom serialization.

        Selects 1-2 of the three binary attacks and applies them in sequence.
        Falls back to returning file_data unchanged on any error.

        Args:
            file_data: Complete DICOM file bytes (preamble + DICM + elements)

        Returns:
            Possibly-modified byte string

        """
        self._applied_binary_mutations = []
        if len(file_data) < _DATA_OFFSET + 4:
            return file_data
        if file_data[_DICM_OFFSET:_DATA_OFFSET] != _DICM_MAGIC:
            return file_data

        binary_attacks = [
            self._binary_corrupt_tag_ordering,
            self._binary_duplicate_tag,
            self._binary_corrupt_length_field,
            self._binary_whitespace_vr,
            self._binary_null_vr,
            self._binary_dash_vr,
            self._binary_vr_un_substitution,
            self._binary_dimension_vr_ul,
            self._binary_nonstandard_vr_meta,
            self._binary_duplicate_meta_tag,
        ]
        num = random.randint(1, 2)
        selected = random.sample(binary_attacks, num)
        result = file_data
        for attack in selected:
            try:
                result = attack(result)
                self._applied_binary_mutations.append(attack.__name__)
            except Exception as e:
                logger.debug("Binary attack %s failed: %s", attack.__name__, e)
        return result

    @staticmethod
    def _is_valid_dicom(file_data: bytes) -> bool:
        """Return True if file_data has a valid DICOM preamble + DICM magic."""
        return (
            len(file_data) >= _DATA_OFFSET + 4
            and file_data[_DICM_OFFSET:_DATA_OFFSET] == _DICM_MAGIC
        )

    def _binary_corrupt_tag_ordering(self, file_data: bytes) -> bytes:
        """Swap two data elements in the byte stream to violate tag ordering.

        Parses Explicit VR LE elements, picks two non-adjacent elements, and
        swaps their raw bytes. The result is a byte stream where elements
        appear out of ascending tag-number order, which violates the DICOM
        standard.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with two elements swapped, or file_data unchanged

        """
        if not self._is_valid_dicom(file_data):
            return file_data
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        if len(elements) < 3:
            return file_data

        idx1, idx2 = random.sample(range(len(elements)), 2)
        if idx1 > idx2:
            idx1, idx2 = idx2, idx1

        s1, e1, _, _ = elements[idx1]
        s2, e2, _, _ = elements[idx2]

        # Swap: rebuild byte string working back-to-front to avoid offset drift
        chunk1 = file_data[s1:e1]
        chunk2 = file_data[s2:e2]

        if len(chunk1) == len(chunk2):
            # Same size -- simple in-place swap
            result = bytearray(file_data)
            result[s1:e1] = chunk2
            result[s2:e2] = chunk1
            return bytes(result)
        else:
            # Different sizes -- rebuild in three slices
            return file_data[:s1] + chunk2 + file_data[e1:s2] + chunk1 + file_data[e2:]

    def _binary_duplicate_tag(self, file_data: bytes) -> bytes:
        """Duplicate a random element's raw bytes at another position.

        Picks a random element, copies its raw bytes, and inserts the copy
        after a different random element. The result is a byte stream where
        the same tag appears twice, violating the DICOM uniqueness rule.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with one element duplicated (file grows), or file_data

        """
        if not self._is_valid_dicom(file_data):
            return file_data
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        if len(elements) < 2:
            return file_data

        src_idx = random.randrange(len(elements))
        # Pick a different index for the insertion point
        candidates = [i for i in range(len(elements)) if i != src_idx]
        insert_after_idx = random.choice(candidates)

        src_start, src_end, _, _ = elements[src_idx]
        _, insert_pos, _, _ = elements[insert_after_idx]

        element_bytes = file_data[src_start:src_end]
        return file_data[:insert_pos] + element_bytes + file_data[insert_pos:]

    def _binary_corrupt_length_field(self, file_data: bytes) -> bytes:
        """Overwrite a random element's length field with a corrupt value.

        Targets non-group-0002 elements with definite length. The corrupt
        length does not match the actual value size, creating a length/data
        mismatch that parsers must handle.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with one length field patched, or file_data unchanged

        """
        if not self._is_valid_dicom(file_data):
            return file_data
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        if not elements:
            return file_data

        _, _, len_offset, len_size = random.choice(elements)

        result = bytearray(file_data)
        if len_size == 4:
            corrupt = random.choice(self._CORRUPT_LENGTHS_4B)
        else:
            corrupt = random.choice(self._CORRUPT_LENGTHS_2B)

        result[len_offset : len_offset + len_size] = corrupt
        return bytes(result)

    # ------------------------------------------------------------------
    # Binary VR field corruption attacks
    #
    # Target the VR (Value Representation) field in Explicit VR Little
    # Endian data elements. For short-VR elements, the 2-byte VR sits
    # at `elem_start + 4`, followed by a 2-byte length field. Rewriting
    # those 2 bytes in place is a minimal, length-preserving mutation
    # that breaks parser VR detection logic.
    #
    # Each attack maps to a fixed fo-dicom issue:
    #
    #   _binary_whitespace_vr      -> #1847 (space+LF trips VR detection)
    #   _binary_null_vr            -> null bytes fail VR lookup
    #   _binary_dash_vr            -> #1660 (parser Suspended, truncation)
    #   _binary_vr_un_substitution -> #1941 (UN forces 4-byte length read
    #                                        on a file that still has a
    #                                        2-byte length field, causing
    #                                        parser/data desync)
    # ------------------------------------------------------------------

    @staticmethod
    def _select_short_vr_element(
        file_data: bytes,
    ) -> tuple[int, bytes] | None:
        """Pick a random short-VR (2-byte length) element and return its VR offset.

        Returns ``(vr_offset, original_vr_bytes)`` on success, or ``None`` if the
        file has no DICOM magic or no short-VR elements. Long-VR elements
        (OB/OW/SQ/UN/etc.) are excluded because their length encoding differs
        and in-place 2-byte VR overwrites would produce different desync
        patterns that deserve their own dedicated attacks.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            Tuple of (vr_offset, original_vr_bytes) or None

        """
        if not StructureFuzzer._is_valid_dicom(file_data):
            return None
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        short_vr_elements = [e for e in elements if e[3] == 2]
        if not short_vr_elements:
            return None
        elem_start, _, _, _ = random.choice(short_vr_elements)
        vr_offset = elem_start + 4
        original_vr = file_data[vr_offset : vr_offset + 2]
        return vr_offset, original_vr

    @staticmethod
    def _overwrite_vr_bytes(file_data: bytes, vr_offset: int, new_vr: bytes) -> bytes:
        """Rewrite the 2 VR bytes at ``vr_offset`` with ``new_vr``.

        Assumes caller has already validated ``vr_offset + 2 <= len(file_data)``
        via _select_short_vr_element. Length-preserving.
        """
        assert len(new_vr) == 2, "VR field is exactly 2 bytes"
        result = bytearray(file_data)
        result[vr_offset : vr_offset + 2] = new_vr
        return bytes(result)

    def _binary_whitespace_vr(self, file_data: bytes) -> bytes:
        """Replace a short-VR field with 0x20 0x0A (space + LF).

        fo-dicom #1847. Parser VR detection uses ``isalpha()``/uppercase
        checks on the 2-byte VR field; whitespace fails this check and
        trips the fallback path, which historically dereferenced unchecked
        state and crashed.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with one VR field overwritten, or file_data unchanged

        """
        selection = self._select_short_vr_element(file_data)
        if selection is None:
            return file_data
        vr_offset, _ = selection
        return self._overwrite_vr_bytes(file_data, vr_offset, b"\x20\x0a")

    def _binary_null_vr(self, file_data: bytes) -> bytes:
        """Replace a short-VR field with 0x00 0x00 (null bytes).

        Null VR bytes fail ASCII uppercase VR detection and trip fallback
        code paths that may dereference a null VR lookup or cast the VR
        to an int/enum.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with one VR field overwritten, or file_data unchanged

        """
        selection = self._select_short_vr_element(file_data)
        if selection is None:
            return file_data
        vr_offset, _ = selection
        return self._overwrite_vr_bytes(file_data, vr_offset, b"\x00\x00")

    def _binary_dash_vr(self, file_data: bytes) -> bytes:
        """Replace a short-VR field with 0x2D 0x2D (two dashes "--").

        fo-dicom #1660. The parser recognises "--" as a sentinel and
        returns ``DicomReaderResult.Suspended``, truncating the dataset.
        Downstream code that assumed the dataset was complete then
        accesses missing tags and crashes.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with one VR field overwritten, or file_data unchanged

        """
        selection = self._select_short_vr_element(file_data)
        if selection is None:
            return file_data
        vr_offset, _ = selection
        return self._overwrite_vr_bytes(file_data, vr_offset, b"--")

    def _binary_vr_un_substitution(self, file_data: bytes) -> bytes:
        """Replace a short-VR field with "UN" (Unknown VR, long-VR encoding).

        fo-dicom #1941. UN is a long-VR that uses ``reserved(2) + length(4)``
        after the 2-byte VR, but the file's original short-VR element was
        encoded with a 2-byte length directly after the VR. After this
        substitution the parser sees "UN", skips 2 bytes (thinks they're
        reserved), and reads the next 4 bytes as a 32-bit length — which is
        now completely unrelated to the actual element size. Result: either
        a buffer over-read, a negative allocation, or a total parser desync
        that corrupts every subsequent element.

        This attack only fires on elements whose ORIGINAL VR was not "UN",
        so the mutation is guaranteed to change the byte stream.

        Args:
            file_data: Complete DICOM file bytes

        Returns:
            File bytes with one VR field overwritten, or file_data unchanged

        """
        if not self._is_valid_dicom(file_data):
            return file_data
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        # Filter: must be short-VR AND not already "UN".
        candidates = [
            e for e in elements if e[3] == 2 and file_data[e[0] + 4 : e[0] + 6] != b"UN"
        ]
        if not candidates:
            return file_data
        elem_start, _, _, _ = random.choice(candidates)
        vr_offset = elem_start + 4
        return self._overwrite_vr_bytes(file_data, vr_offset, b"UN")

    def _binary_dimension_vr_ul(self, file_data: bytes) -> bytes:
        """Replace VR "US" with "UL" on a Rows or Columns tag.

        Orthanc CVE-2026-5442. US is a 2-byte unsigned short; UL is a
        4-byte unsigned long. Both are short-VR (2-byte length field in
        Explicit VR LE), so the length encoding is unchanged. But the
        parser now interprets the 2-byte value as the first half of a
        4-byte integer, reading 2 bytes from the next element as the
        high word. The resulting huge dimension overflows the frame-size
        calculation (rows * cols * bytes_per_pixel).
        """
        if not self._is_valid_dicom(file_data):
            return file_data
        # Scan for Rows (0028,0010) or Columns (0028,0011) with VR "US"
        rows_tag = b"\x28\x00\x10\x00"  # (0028,0010) LE
        cols_tag = b"\x28\x00\x11\x00"  # (0028,0011) LE
        targets = []
        for tag_bytes in (rows_tag, cols_tag):
            idx = file_data.find(tag_bytes, _DATA_OFFSET)
            if idx >= 0 and idx + 6 <= len(file_data):
                vr = file_data[idx + 4 : idx + 6]
                if vr == b"US":
                    targets.append(idx + 4)
        if not targets:
            return file_data
        vr_offset = random.choice(targets)
        return self._overwrite_vr_bytes(file_data, vr_offset, b"UL")

    def _binary_nonstandard_vr_meta(self, file_data: bytes) -> bytes:
        """Replace a group 0002 element's VR with a fabricated string "ZZ".

        GDCM CVE-2026-3650 (UNPATCHED). Non-standard VR types in file
        meta information cause parsers to fall back to VR-implied length
        rules. "ZZ" is not in any VR table, so the parser may treat it
        as a long-VR (reading 6 extra bytes as reserved+length) or
        allocate based on a garbage length value. A ~150-byte file with
        this pattern caused GDCM to allocate ~4.2 GB of heap.

        Note: the standard _parse_dicom_elements helper skips group
        0002 elements, so this attack scans for them independently.
        """
        if not self._is_valid_dicom(file_data):
            return file_data
        # Walk group 0002 elements manually to find one with a valid VR
        pos = _DATA_OFFSET
        data_len = len(file_data)
        candidates = []
        while pos + 8 <= data_len:
            group = int.from_bytes(file_data[pos : pos + 2], "little")
            if group != 0x0002:
                break  # past file meta
            vr = file_data[pos + 4 : pos + 6]
            # Skip if already non-ASCII (already corrupted)
            if vr.isalpha() and vr.isupper():
                candidates.append(pos + 4)
            # Advance past this element
            if vr in _LONG_VRS:
                if pos + 12 > data_len:
                    break
                length = int.from_bytes(file_data[pos + 8 : pos + 12], "little")
                pos += 12 + length
            else:
                if pos + 8 > data_len:
                    break
                length = int.from_bytes(file_data[pos + 6 : pos + 8], "little")
                pos += 8 + length
        if not candidates:
            return file_data
        vr_offset = random.choice(candidates)
        return self._overwrite_vr_bytes(file_data, vr_offset, b"ZZ")

    @staticmethod
    def _parse_meta_elements(
        file_data: bytes,
    ) -> list[tuple[int, int]]:
        """Parse group 0002 elements and return (start, end) byte offsets.

        Walks Explicit VR elements in the File Meta Information header
        (group 0002) and returns their byte ranges. Stops at the first
        non-0002 group or on parse error.
        """
        results: list[tuple[int, int]] = []
        pos = _DATA_OFFSET
        data_len = len(file_data)
        while pos + 8 <= data_len:
            group = int.from_bytes(file_data[pos : pos + 2], "little")
            if group != 0x0002:
                break
            elem_start = pos
            vr = file_data[pos + 4 : pos + 6]
            if vr in _LONG_VRS:
                if pos + 12 > data_len:
                    break
                length = int.from_bytes(file_data[pos + 8 : pos + 12], "little")
                pos = pos + 12 + length
            else:
                if pos + 8 > data_len:
                    break
                length = int.from_bytes(file_data[pos + 6 : pos + 8], "little")
                pos = pos + 8 + length
            if pos > data_len:
                break
            results.append((elem_start, pos))
        return results

    def _binary_duplicate_meta_tag(self, file_data: bytes) -> bytes:
        """Duplicate a group 0002 element within the file meta header.

        libdicom CVE-2024-24793/24794 (TALOS-2024-1931, CVSS 8.1).
        Parsers using hash-map insertion with destroy-on-collision
        double-free the original element when they encounter a
        duplicate tag in the File Meta Information header. The standard
        ``_binary_duplicate_tag`` skips group 0002, so this attack
        targets meta elements specifically.
        """
        if not self._is_valid_dicom(file_data):
            return file_data
        meta_elems = self._parse_meta_elements(file_data)
        if not meta_elems:
            return file_data
        src_start, src_end = random.choice(meta_elems)
        elem_bytes = file_data[src_start:src_end]
        # Insert the duplicate right after the original element
        return file_data[:src_end] + elem_bytes + file_data[src_end:]
