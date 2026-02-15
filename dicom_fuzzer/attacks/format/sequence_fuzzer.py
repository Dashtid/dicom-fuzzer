"""Sequence Fuzzer - DICOM Sequence and Item Structure Mutations.

Targets DICOM Sequences (SQ VR) and nested Item structures to test parser
robustness against malformed hierarchical data.

Sequences are used in ~40% of DICOM structure for:
- Referenced images/series
- Procedure codes
- Measurement data
- Frame-level metadata

Common vulnerabilities:
- Deep nesting causing stack overflow
- Item length mismatches causing buffer overflows
- Missing delimiters causing infinite loops
- Empty required sequences causing null pointer dereference
"""

from __future__ import annotations

import random
from typing import Any

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)


class SequenceFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Sequence (SQ) and Item structures.

    Targets hierarchical data structures that are common crash vectors
    due to complex parsing requirements and memory management.
    """

    def __init__(self) -> None:
        """Initialize the sequence fuzzer with attack patterns."""
        super().__init__()
        self.mutation_strategies = [
            self._deep_nesting_attack,
            self._item_length_mismatch,
            self._empty_required_sequence,
            self._orphan_item_attack,
            self._circular_reference_attack,
            self._delimiter_corruption,
            self._mixed_encoding_sequence,
            self._massive_item_count,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "sequence"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply sequence-level mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with sequence corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug(f"Sequence mutation failed: {e}")

        return dataset

    mutate_sequences = mutate

    def _find_sequences(self, dataset: Dataset) -> list[tuple[Tag, Any]]:
        """Find all sequence elements in the dataset."""
        sequences = []
        for tag, elem in dataset.items():
            if hasattr(elem, "VR") and elem.VR == "SQ":
                sequences.append((tag, elem))
        return sequences

    def _deep_nesting_attack(self, dataset: Dataset) -> Dataset:
        """Create deeply nested sequences to trigger stack overflow.

        Many parsers use recursive descent for sequences. Deep nesting
        can exceed stack limits or cause excessive memory allocation.

        Note: depth=1000 intentionally approaches Python's default recursion
        limit (~1000). This may raise RecursionError ~25% of the time, which
        the outer try/except catches silently. Do not "fix" by raising
        sys.setrecursionlimit -- the silent failure is acceptable here.
        """
        # Create a deeply nested sequence structure
        depth = random.choice([50, 100, 500, 1000])

        def create_nested_item(current_depth: int) -> Dataset:
            item = Dataset()
            item.add_new(Tag(0x0008, 0x0100), "SH", f"CODE_{current_depth}")

            if current_depth > 0:
                nested_seq = Sequence([create_nested_item(current_depth - 1)])
                item.add_new(Tag(0x0008, 0x1115), "SQ", nested_seq)

            return item

        try:
            deep_seq = Sequence([create_nested_item(depth)])
            # Add to a common sequence tag
            dataset.add_new(Tag(0x0040, 0xA730), "SQ", deep_seq)  # ContentSequence
            logger.debug(f"Created sequence with depth {depth}")
        except Exception as e:
            logger.debug(f"Deep nesting attack failed: {e}")

        return dataset

    def _item_length_mismatch(self, dataset: Dataset) -> Dataset:
        """Add items with extreme-length string data to sequence elements.

        Note: pydicom recalculates length fields on write, so true
        length/content mismatches require binary-level manipulation.
        The extreme-length values (64KB, 100KB strings) still stress
        parsers that assume bounded item sizes.
        """
        sequences = self._find_sequences(dataset)

        if not sequences:
            # Create a new sequence to corrupt
            seq = Sequence([Dataset()])
            seq[0].add_new(Tag(0x0008, 0x0100), "SH", "TEST_CODE")
            dataset.add_new(Tag(0x0008, 0x1115), "SQ", seq)
            sequences = [(Tag(0x0008, 0x1115), dataset[Tag(0x0008, 0x1115)])]

        if sequences:
            tag, seq_elem = random.choice(sequences)
            if hasattr(seq_elem, "value") and len(seq_elem.value) > 0:
                item = seq_elem.value[0]

                attack = random.choice(
                    [
                        "overflow_length",
                        "zero_length",
                        "negative_length",
                        "undefined_length_non_sq",
                    ]
                )

                if attack == "overflow_length":
                    # Add data that suggests length overflow
                    item.add_new(Tag(0x0008, 0x0102), "SH", "X" * 65536)
                elif attack == "zero_length":
                    # Add empty element where data expected
                    item.add_new(Tag(0x0008, 0x0104), "LO", "")
                elif attack == "negative_length":
                    # Add element with data suggesting signed overflow
                    item.add_new(Tag(0x0008, 0x0100), "SH", "A" * 32768)
                elif attack == "undefined_length_non_sq":
                    # Add a long text element (parsers may mishandle)
                    item.add_new(Tag(0x0008, 0x2111), "ST", "B" * 100000)

        return dataset

    def _empty_required_sequence(self, dataset: Dataset) -> Dataset:
        """Create empty sequences where items are expected.

        Empty sequences can cause null pointer dereference when
        code expects at least one item.
        """
        # Required sequences that often expect at least one item
        required_sequences = [
            Tag(0x0008, 0x1115),  # ReferencedSeriesSequence
            Tag(0x0008, 0x1140),  # ReferencedImageSequence
            Tag(0x0032, 0x1064),  # RequestedProcedureCodeSequence
            Tag(0x0040, 0x0275),  # RequestAttributesSequence
            Tag(0x5200, 0x9230),  # PerFrameFunctionalGroupsSequence
        ]

        attack = random.choice(
            [
                "empty_sequence",
                "null_first_item",
                "empty_nested",
            ]
        )

        try:
            if attack == "empty_sequence":
                # Add empty sequence
                target = random.choice(required_sequences)
                dataset.add_new(target, "SQ", Sequence([]))

            elif attack == "null_first_item":
                # Add sequence with empty item
                target = random.choice(required_sequences)
                empty_item = Dataset()
                dataset.add_new(target, "SQ", Sequence([empty_item]))

            elif attack == "empty_nested":
                # Add sequence with item containing empty nested sequence
                target = random.choice(required_sequences)
                item = Dataset()
                item.add_new(Tag(0x0008, 0x1199), "SQ", Sequence([]))
                dataset.add_new(target, "SQ", Sequence([item]))

        except Exception as e:
            logger.debug(f"Empty sequence attack failed: {e}")

        return dataset

    def _orphan_item_attack(self, dataset: Dataset) -> Dataset:
        """Embed Item-tag-like bytes in private element data.

        Inserts raw Item tag bytes (FFFE,E000) into a private element's
        value. Parsers that scan for Item delimiters without respecting
        element boundaries may misinterpret these as real Items.
        """
        try:
            # Add item-related data as regular elements (invalid)
            # Item tag is (FFFE,E000), ItemDelimiter is (FFFE,E00D)
            # These are normally handled specially, not as data elements
            dataset.add_new(Tag(0x0009, 0x0010), "LO", "OrphanItemCreator")
            dataset.add_new(Tag(0x0009, 0x1000), "UN", b"\xfe\xff\x00\xe0" * 10)
        except Exception as e:
            logger.debug(f"Orphan item attack failed: {e}")

        return dataset

    def _circular_reference_attack(self, dataset: Dataset) -> Dataset:
        """Attempt to create circular references in sequences.

        While pydicom prevents true circular references, we can create
        UIDs that suggest circular relationships which may confuse
        applications that resolve references.
        """
        try:
            # Create two items that reference each other's UIDs
            uid1 = "1.2.3.4.5.6.7.8.9.1"
            uid2 = "1.2.3.4.5.6.7.8.9.2"

            item1 = Dataset()
            item1.add_new(Tag(0x0008, 0x0018), "UI", uid1)  # SOPInstanceUID
            item1.add_new(Tag(0x0008, 0x1155), "UI", uid2)  # ReferencedSOPInstanceUID

            item2 = Dataset()
            item2.add_new(Tag(0x0008, 0x0018), "UI", uid2)
            item2.add_new(Tag(0x0008, 0x1155), "UI", uid1)  # References item1

            # Add as referenced image sequence
            dataset.add_new(Tag(0x0008, 0x1140), "SQ", Sequence([item1, item2]))

        except Exception as e:
            logger.debug(f"Circular reference attack failed: {e}")

        return dataset

    def _delimiter_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt sequence/item delimiters.

        Sequences with undefined length rely on delimiters.
        Missing or corrupted delimiters can cause infinite loops.
        """
        sequences = self._find_sequences(dataset)

        if not sequences:
            return dataset

        tag, seq_elem = random.choice(sequences)

        try:
            # Add items with delimiter-like data embedded
            if hasattr(seq_elem, "value") and len(seq_elem.value) > 0:
                item = seq_elem.value[0]
                # Embed delimiter bytes in text field
                # SequenceDelimiter is (FFFE,E0DD)
                item.add_new(
                    Tag(0x0008, 0x1030), "LO", "Study\xfe\xff\xdd\xe0Description"
                )
        except Exception as e:
            logger.debug(f"Delimiter corruption failed: {e}")

        return dataset

    def _mixed_encoding_sequence(self, dataset: Dataset) -> Dataset:
        """Create sequences with mixed character encodings.

        Items may have different SpecificCharacterSet values.
        Inconsistent encoding can cause display issues or crashes.
        """
        try:
            item1 = Dataset()
            item1.add_new(Tag(0x0008, 0x0005), "CS", "ISO_IR 100")  # Latin1
            item1.add_new(Tag(0x0008, 0x0104), "LO", "Caf\xe9")  # Latin1 encoding

            item2 = Dataset()
            item2.add_new(Tag(0x0008, 0x0005), "CS", "ISO_IR 192")  # UTF-8
            item2.add_new(Tag(0x0008, 0x0104), "LO", "日本語")  # UTF-8

            item3 = Dataset()
            # No character set specified but has non-ASCII
            item3.add_new(
                Tag(0x0008, 0x0104), "LO", b"\xff\xfe\x00\x01".decode("latin1")
            )

            dataset.add_new(Tag(0x0032, 0x1064), "SQ", Sequence([item1, item2, item3]))

        except Exception as e:
            logger.debug(f"Mixed encoding attack failed: {e}")

        return dataset

    def _massive_item_count(self, dataset: Dataset) -> Dataset:
        """Create sequences with excessive item counts.

        Large item counts can cause:
        - Memory exhaustion
        - Integer overflow in item counting
        - UI rendering issues
        """
        attack = random.choice(
            [
                "many_items",
                "many_nested_items",
                "items_with_large_data",
            ]
        )

        try:
            if attack == "many_items":
                # Create sequence with many simple items
                count = random.choice([1000, 5000, 10000])
                items = []
                for i in range(count):
                    item = Dataset()
                    item.add_new(Tag(0x0008, 0x0100), "SH", f"CODE_{i}")
                    items.append(item)
                dataset.add_new(Tag(0x0040, 0xA730), "SQ", Sequence(items))

            elif attack == "many_nested_items":
                # Create moderately nested structure with many siblings
                outer_items = []
                for i in range(100):
                    outer = Dataset()
                    inner_items = []
                    for j in range(100):
                        inner = Dataset()
                        inner.add_new(Tag(0x0008, 0x0100), "SH", f"CODE_{i}_{j}")
                        inner_items.append(inner)
                    outer.add_new(Tag(0x0008, 0x1199), "SQ", Sequence(inner_items))
                    outer_items.append(outer)
                dataset.add_new(Tag(0x0008, 0x1115), "SQ", Sequence(outer_items))

            elif attack == "items_with_large_data":
                # Fewer items but each has significant data
                items = []
                for _i in range(100):
                    item = Dataset()
                    item.add_new(Tag(0x0008, 0x0104), "LO", "X" * 1000)
                    item.add_new(Tag(0x0008, 0x2111), "ST", "Y" * 10000)
                    items.append(item)
                dataset.add_new(Tag(0x0040, 0xA730), "SQ", Sequence(items))

        except Exception as e:
            logger.debug(f"Massive item count attack failed: {e}")

        return dataset
