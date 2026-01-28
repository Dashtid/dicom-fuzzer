"""Sequence Fuzzer - DICOM Sequence (SQ) Mutations.

Targets nested DICOM sequences with edge cases to test parser robustness:
- Deep nesting (stack exhaustion)
- Empty sequences and items
- Large item counts
- Circular/self-referencing structures
"""

import random
from typing import Any

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag

# DICOM sequence-related tags
ITEM_TAG = Tag(0xFFFE, 0xE000)  # Item
ITEM_DELIM_TAG = Tag(0xFFFE, 0xE00D)  # Item Delimitation Item
SEQ_DELIM_TAG = Tag(0xFFFE, 0xE0DD)  # Sequence Delimitation Item

# Common sequence tags to target
SEQUENCE_TAGS = [
    (0x0008, 0x1115),  # ReferencedSeriesSequence
    (0x0008, 0x1140),  # ReferencedImageSequence
    (0x0008, 0x1111),  # ReferencedStudySequence
    (0x0040, 0x0260),  # PerformedProtocolCodeSequence
    (0x0040, 0x0275),  # RequestAttributesSequence
    (0x0008, 0x0082),  # InstitutionCodeSequence
    (0x0008, 0x1032),  # ProcedureCodeSequence
    (0x0020, 0x4000),  # ImageComments (not SQ but commonly nested context)
    (0x5200, 0x9229),  # SharedFunctionalGroupsSequence
    (0x5200, 0x9230),  # PerFrameFunctionalGroupsSequence
]


class SequenceFuzzer:
    """Fuzzes DICOM sequences to test nested structure handling.

    Tests parser robustness against:
    - Deep nesting (stack overflow)
    - Circular references (infinite loops)
    - Missing delimiters (buffer overread)
    - Undefined lengths (memory allocation issues)
    """

    def __init__(self, max_depth: int = 100) -> None:
        """Initialize sequence fuzzer.

        Args:
            max_depth: Maximum nesting depth for deep nesting attacks.

        """
        self.max_depth = max_depth

    def mutate_sequences(self, dataset: Dataset) -> Dataset:
        """Apply sequence mutations to the dataset.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        mutations = [
            self._deep_nesting,
            self._empty_sequence,
            self._empty_item,
            self._inject_malformed_sequence,
            self._corrupt_existing_sequence,
        ]

        # Apply 1-2 mutations
        for mutation in random.sample(mutations, k=random.randint(1, 2)):
            try:
                dataset = mutation(dataset)
            except Exception:
                # Some mutations may fail on certain datasets
                pass

        return dataset

    def _deep_nesting(self, dataset: Dataset) -> Dataset:
        """Create deeply nested sequences to test stack limits.

        Deep nesting can cause:
        - Stack overflow in recursive parsers
        - Memory exhaustion from allocation
        - Integer overflow in depth counters
        """
        depth = random.choice([50, 100, 200, 500])

        # Build nested sequence from inside out
        inner_ds = Dataset()
        inner_ds.add_new(Tag(0x0008, 0x0050), "SH", "INNERMOST")

        current_seq = Sequence([inner_ds])
        for i in range(depth):
            wrapper_ds = Dataset()
            wrapper_ds.add_new(Tag(0x0008, 0x1115), "SQ", current_seq)
            current_seq = Sequence([wrapper_ds])

        # Add the deeply nested sequence
        dataset.add_new(Tag(0x0008, 0x1115), "SQ", current_seq)

        return dataset

    def _empty_sequence(self, dataset: Dataset) -> Dataset:
        """Create empty sequences (no items).

        Empty sequences test:
        - Null pointer dereference when accessing first item
        - Off-by-one errors in iteration
        """
        # Add multiple empty sequences
        empty_seq = Sequence([])

        for tag_tuple in random.sample(SEQUENCE_TAGS[:5], k=2):
            tag = Tag(*tag_tuple)
            try:
                dataset.add_new(tag, "SQ", empty_seq)
            except Exception:
                pass

        return dataset

    def _empty_item(self, dataset: Dataset) -> Dataset:
        """Create sequences with empty items (items containing no elements).

        Empty items test:
        - Handling of zero-length item data
        - Iteration over empty datasets
        """
        # Create sequence with empty item
        empty_ds = Dataset()  # No elements
        seq_with_empty = Sequence([empty_ds])

        # Also create one with multiple empty items
        multi_empty = Sequence([Dataset(), Dataset(), Dataset()])

        tag1 = Tag(*random.choice(SEQUENCE_TAGS[:5]))
        tag2 = Tag(*random.choice(SEQUENCE_TAGS[:5]))

        try:
            dataset.add_new(tag1, "SQ", seq_with_empty)
            dataset.add_new(tag2, "SQ", multi_empty)
        except Exception:
            pass

        return dataset

    def _inject_malformed_sequence(self, dataset: Dataset) -> Dataset:
        """Inject sequences with various malformations.

        Tests multiple malformation types:
        - Very large item counts
        - Items with unusual content
        - Mixed valid/invalid items
        """
        malformations = [
            self._create_large_item_count_sequence,
            self._create_item_with_garbage,
            self._create_mixed_valid_invalid_sequence,
        ]

        malformation = random.choice(malformations)
        return malformation(dataset)

    def _create_large_item_count_sequence(self, dataset: Dataset) -> Dataset:
        """Create sequence with many items (memory pressure test)."""
        item_count = random.choice([100, 500, 1000])

        items = []
        for i in range(item_count):
            item_ds = Dataset()
            item_ds.add_new(Tag(0x0008, 0x0050), "SH", f"ITEM{i:05d}")
            items.append(item_ds)

        large_seq = Sequence(items)
        tag = Tag(*random.choice(SEQUENCE_TAGS[:3]))

        try:
            dataset.add_new(tag, "SQ", large_seq)
        except Exception:
            pass

        return dataset

    def _create_item_with_garbage(self, dataset: Dataset) -> Dataset:
        """Create item containing garbage/unexpected data."""
        garbage_ds = Dataset()

        # Add elements with unusual values
        garbage_ds.add_new(Tag(0xFFFF, 0xFFFF), "UN", b"\x00" * 100)  # Max tag
        garbage_ds.add_new(Tag(0x0000, 0x0000), "UL", 0)  # Min tag
        garbage_ds.add_new(Tag(0x7FE0, 0x0010), "OB", b"\xFF" * 50)  # PixelData in SQ

        garbage_seq = Sequence([garbage_ds])
        tag = Tag(*random.choice(SEQUENCE_TAGS[:3]))

        try:
            dataset.add_new(tag, "SQ", garbage_seq)
        except Exception:
            pass

        return dataset

    def _create_mixed_valid_invalid_sequence(self, dataset: Dataset) -> Dataset:
        """Create sequence with mix of valid and problematic items."""
        items = []

        # Valid item
        valid_ds = Dataset()
        valid_ds.add_new(Tag(0x0008, 0x0050), "SH", "VALID")
        items.append(valid_ds)

        # Empty item
        items.append(Dataset())

        # Item with very long value
        long_ds = Dataset()
        long_ds.add_new(Tag(0x0008, 0x0050), "SH", "X" * 10000)
        items.append(long_ds)

        # Another valid item
        valid_ds2 = Dataset()
        valid_ds2.add_new(Tag(0x0008, 0x0050), "SH", "VALID2")
        items.append(valid_ds2)

        # Item with null bytes
        null_ds = Dataset()
        null_ds.add_new(Tag(0x0008, 0x0050), "SH", "\x00\x00\x00")
        items.append(null_ds)

        mixed_seq = Sequence(items)
        tag = Tag(*random.choice(SEQUENCE_TAGS[:3]))

        try:
            dataset.add_new(tag, "SQ", mixed_seq)
        except Exception:
            pass

        return dataset

    def _corrupt_existing_sequence(self, dataset: Dataset) -> Dataset:
        """Find and corrupt existing sequences in the dataset.

        Modifies existing sequences rather than adding new ones,
        which can trigger different code paths in parsers.
        """
        # Find existing sequences
        seq_elements = []
        for elem in dataset:
            if hasattr(elem, "VR") and elem.VR == "SQ":
                seq_elements.append(elem)

        if not seq_elements:
            return dataset

        # Pick one to corrupt
        elem = random.choice(seq_elements)

        corruption = random.choice([
            "add_deep_item",
            "add_empty_items",
            "clear_sequence",
            "duplicate_items",
        ])

        try:
            seq = elem.value
            if seq is None:
                return dataset

            if corruption == "add_deep_item":
                # Add a deeply nested item
                deep_ds = self._create_nested_dataset(depth=20)
                seq.append(deep_ds)

            elif corruption == "add_empty_items":
                # Add many empty items
                for _ in range(50):
                    seq.append(Dataset())

            elif corruption == "clear_sequence":
                # Clear all items
                seq.clear()

            elif corruption == "duplicate_items":
                # Duplicate existing items many times
                if len(seq) > 0:
                    original = seq[0]
                    for _ in range(100):
                        seq.append(original)

        except Exception:
            pass

        return dataset

    def _create_nested_dataset(self, depth: int) -> Dataset:
        """Create a dataset with nested sequences to specified depth."""
        if depth <= 0:
            ds = Dataset()
            ds.add_new(Tag(0x0008, 0x0050), "SH", "LEAF")
            return ds

        inner = self._create_nested_dataset(depth - 1)
        ds = Dataset()
        ds.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([inner]))
        return ds
