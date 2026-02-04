"""Encapsulated Pixel Data mutation strategy.

Strategy 9: Corrupt encapsulated (compressed) pixel data structures:
- Invalid Basic Offset Table (BOT) entries
- Extended Offset Table (EOT) inconsistencies
- Fragment size/count manipulation
- Missing or duplicate sequence delimiters
- BOT + EOT coexistence (violates standard)

Targets: Compressed transfer syntax parsing, frame extraction from
encapsulated data, offset table validation, fragment reassembly.

CVE context:
- CVE-2025-11266: GDCM unsigned integer underflow in encapsulated fragments
- TALOS-2024-1935: Out-of-bounds write in JPEG2000Codec
- pydicom #1140: Embedded sequence delimiter confusion
- pydicom #1274: 32-bit overflow in pixel data size

"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import UID

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

# DICOM sequence delimiter bytes (FFFE,E0DD with zero length)
_SEQ_DELIM_BYTES = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
# DICOM item tag bytes (FFFE,E000)
_ITEM_TAG_BYTES = b"\xfe\xff\x00\xe0"
# Undefined length sentinel
_UNDEFINED_LENGTH = b"\xff\xff\xff\xff"


class EncapsulatedPixelStrategy(MutationStrategyBase):
    """Mutation strategy for encapsulated pixel data attacks."""

    _ATTACK_TYPES = [
        "invalid_bot_offsets",
        "bot_length_not_multiple_of_4",
        "empty_bot_with_eot",
        "bot_and_eot_coexist",
        "fragment_count_mismatch",
        "fragment_embedded_delimiter",
        "fragment_undefined_length",
        "truncated_fragment",
        "missing_seq_delimiter",
    ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "encapsulated_pixel_data"

    def _make_record(
        self,
        tag: str,
        original: str,
        mutated: str,
        attack_type: str,
        **extra: object,
    ) -> MultiFrameMutationRecord:
        """Create a mutation record."""
        details: dict[str, object] = {"attack_type": attack_type}
        details.update(extra)
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag=tag,
            original_value=original,
            mutated_value=mutated,
            severity=self.severity,
            details=details,
        )

    def _build_encapsulated_pixel_data(
        self, frame_count: int, frame_size: int
    ) -> bytes:
        """Build well-formed encapsulated pixel data with BOT and fragments.

        Returns raw bytes: BOT item + N fragment items + sequence delimiter.

        """
        fragments = []
        for _ in range(frame_count):
            fragments.append(bytes(random.getrandbits(8) for _ in range(frame_size)))

        # BOT: item tag + length + offset entries
        offsets = []
        current_offset = 0
        for frag in fragments:
            offsets.append(current_offset)
            # Each fragment is: 4 bytes tag + 4 bytes length + data
            current_offset += 4 + 4 + len(frag)

        bot_data = struct.pack(f"<{len(offsets)}I", *offsets)
        bot_item = _ITEM_TAG_BYTES + struct.pack("<I", len(bot_data)) + bot_data

        # Fragment items
        frag_items = b""
        for frag in fragments:
            frag_items += _ITEM_TAG_BYTES + struct.pack("<I", len(frag)) + frag

        return bot_item + frag_items + _SEQ_DELIM_BYTES

    def _ensure_encapsulated(self, dataset: Dataset) -> tuple[int, int]:
        """Ensure dataset has encapsulated pixel data structure.

        Returns (frame_count, fragment_size) used.

        """
        frame_count = self._get_frame_count(dataset)
        frame_size = self._calculate_frame_size(dataset)
        if frame_size == 0:
            frame_size = 256  # Default fragment size

        # Set a compressed transfer syntax
        if not hasattr(dataset, "file_meta"):
            dataset.file_meta = FileMetaDataset()
        dataset.file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.4.90")  # JPEG2000

        # Build encapsulated pixel data
        dataset.PixelData = self._build_encapsulated_pixel_data(frame_count, frame_size)

        return frame_count, frame_size

    # --- Attack handlers ---

    def _attack_invalid_bot_offsets(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Set BOT offsets pointing beyond pixel data end."""
        frame_count, frame_size = self._ensure_encapsulated(dataset)

        # Build BOT with offsets way past the end of actual data
        total_data = len(dataset.PixelData)
        bad_offsets = [total_data * 10 + i * frame_size for i in range(frame_count)]
        bot_data = struct.pack(
            f"<{frame_count}I", *[o & 0xFFFFFFFF for o in bad_offsets]
        )
        bot_item = _ITEM_TAG_BYTES + struct.pack("<I", len(bot_data)) + bot_data

        # Keep existing fragment data after the original BOT
        # Find end of original BOT (first item)
        orig_bot_len = struct.unpack_from("<I", dataset.PixelData, 4)[0]
        remaining = dataset.PixelData[8 + orig_bot_len :]

        dataset.PixelData = bot_item + remaining

        return self._make_record(
            "PixelData/BasicOffsetTable",
            f"{frame_count} valid offsets",
            f"{frame_count} offsets past data end",
            "invalid_bot_offsets",
        )

    def _attack_bot_length_not_multiple_of_4(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Create BOT item whose length is not a multiple of 4 bytes."""
        self._ensure_encapsulated(dataset)

        # BOT with 7 bytes (not divisible by 4)
        bad_bot_data = b"\x01\x02\x03\x04\x05\x06\x07"
        bot_item = _ITEM_TAG_BYTES + struct.pack("<I", len(bad_bot_data)) + bad_bot_data

        # Find end of original BOT and keep fragments
        orig_bot_len = struct.unpack_from("<I", dataset.PixelData, 4)[0]
        remaining = dataset.PixelData[8 + orig_bot_len :]

        dataset.PixelData = bot_item + remaining

        return self._make_record(
            "PixelData/BasicOffsetTable",
            "<length % 4 == 0>",
            "7 bytes (not multiple of 4)",
            "bot_length_not_multiple_of_4",
        )

    def _attack_empty_bot_with_eot(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create empty BOT and add an empty Extended Offset Table (prohibited)."""
        self._ensure_encapsulated(dataset)

        # Replace BOT with empty BOT (zero-length item)
        empty_bot = _ITEM_TAG_BYTES + struct.pack("<I", 0)
        orig_bot_len = struct.unpack_from("<I", dataset.PixelData, 4)[0]
        remaining = dataset.PixelData[8 + orig_bot_len :]
        dataset.PixelData = empty_bot + remaining

        # Add empty Extended Offset Table (7FE0,0001) -- prohibited by standard
        dataset.add_new(Tag(0x7FE0, 0x0001), "OB", b"")

        return self._make_record(
            "ExtendedOffsetTable",
            "<absent>",
            "<empty> (prohibited)",
            "empty_bot_with_eot",
        )

    def _attack_bot_and_eot_coexist(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create populated BOT AND Extended Offset Table (violates standard)."""
        frame_count, frame_size = self._ensure_encapsulated(dataset)

        # BOT already populated from _ensure_encapsulated
        # Add EOT with 64-bit offsets
        eot_offsets = struct.pack(
            f"<{frame_count}Q",
            *[i * (frame_size + 8) for i in range(frame_count)],
        )
        dataset.add_new(Tag(0x7FE0, 0x0001), "OB", eot_offsets)

        return self._make_record(
            "BasicOffsetTable+ExtendedOffsetTable",
            "<BOT only>",
            "<both BOT and EOT populated>",
            "bot_and_eot_coexist",
        )

    def _attack_fragment_count_mismatch(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Create more fragments than NumberOfFrames declares."""
        frame_count, frame_size = self._ensure_encapsulated(dataset)

        extra_count = frame_count * 2
        dataset.PixelData = self._build_encapsulated_pixel_data(extra_count, frame_size)

        return self._make_record(
            "PixelData/Fragments",
            f"{frame_count} fragments",
            f"{extra_count} fragments (2x declared frames)",
            "fragment_count_mismatch",
        )

    def _attack_fragment_embedded_delimiter(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Embed sequence delimiter bytes inside a fragment's data."""
        self._ensure_encapsulated(dataset)

        # Build a fragment containing the sequence delimiter byte pattern
        poison_data = b"\xaa" * 16 + _SEQ_DELIM_BYTES + b"\xbb" * 16
        poison_frag = (
            _ITEM_TAG_BYTES + struct.pack("<I", len(poison_data)) + poison_data
        )

        # Replace first fragment after BOT
        orig_bot_len = struct.unpack_from("<I", dataset.PixelData, 4)[0]
        after_bot = 8 + orig_bot_len

        # Find end of first fragment (skip its tag + length + data)
        if len(dataset.PixelData) > after_bot + 8:
            first_frag_len = struct.unpack_from("<I", dataset.PixelData, after_bot + 4)[
                0
            ]
            after_first_frag = after_bot + 8 + first_frag_len
            remaining = dataset.PixelData[after_first_frag:]
        else:
            remaining = _SEQ_DELIM_BYTES

        dataset.PixelData = dataset.PixelData[:after_bot] + poison_frag + remaining

        return self._make_record(
            "PixelData/Fragment[0]",
            "<clean>",
            "<contains FFFE,E0DD delimiter bytes>",
            "fragment_embedded_delimiter",
        )

    def _attack_fragment_undefined_length(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Create a fragment item with undefined length (0xFFFFFFFF)."""
        self._ensure_encapsulated(dataset)

        orig_bot_len = struct.unpack_from("<I", dataset.PixelData, 4)[0]
        after_bot = 8 + orig_bot_len

        # Create fragment with undefined length
        undef_frag = _ITEM_TAG_BYTES + _UNDEFINED_LENGTH + b"\x00" * 64

        # Keep BOT, replace first fragment
        if len(dataset.PixelData) > after_bot + 8:
            first_frag_len = struct.unpack_from("<I", dataset.PixelData, after_bot + 4)[
                0
            ]
            after_first_frag = after_bot + 8 + first_frag_len
            remaining = dataset.PixelData[after_first_frag:]
        else:
            remaining = _SEQ_DELIM_BYTES

        dataset.PixelData = dataset.PixelData[:after_bot] + undef_frag + remaining

        return self._make_record(
            "PixelData/Fragment[0]",
            "<defined length>",
            "0xFFFFFFFF (undefined length)",
            "fragment_undefined_length",
        )

    def _attack_truncated_fragment(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create a fragment that declares more bytes than available."""
        self._ensure_encapsulated(dataset)

        orig_bot_len = struct.unpack_from("<I", dataset.PixelData, 4)[0]
        after_bot = 8 + orig_bot_len

        # Fragment claims 10000 bytes but only has 32
        claimed_len = 10000
        actual_data = b"\x00" * 32
        trunc_frag = _ITEM_TAG_BYTES + struct.pack("<I", claimed_len) + actual_data

        dataset.PixelData = (
            dataset.PixelData[:after_bot] + trunc_frag + _SEQ_DELIM_BYTES
        )

        return self._make_record(
            "PixelData/Fragment[0]",
            "<length matches data>",
            f"claims {claimed_len} bytes, has {len(actual_data)}",
            "truncated_fragment",
        )

    def _attack_missing_seq_delimiter(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Remove the sequence delimiter from end of encapsulated data."""
        self._ensure_encapsulated(dataset)

        # Strip trailing sequence delimiter if present
        if dataset.PixelData[-8:] == _SEQ_DELIM_BYTES:
            dataset.PixelData = dataset.PixelData[:-8]

        return self._make_record(
            "PixelData/SequenceDelimiter",
            "<present>",
            "<missing>",
            "missing_seq_delimiter",
        )

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply encapsulated pixel data mutations."""
        handlers = {
            "invalid_bot_offsets": self._attack_invalid_bot_offsets,
            "bot_length_not_multiple_of_4": self._attack_bot_length_not_multiple_of_4,
            "empty_bot_with_eot": self._attack_empty_bot_with_eot,
            "bot_and_eot_coexist": self._attack_bot_and_eot_coexist,
            "fragment_count_mismatch": self._attack_fragment_count_mismatch,
            "fragment_embedded_delimiter": self._attack_fragment_embedded_delimiter,
            "fragment_undefined_length": self._attack_fragment_undefined_length,
            "truncated_fragment": self._attack_truncated_fragment,
            "missing_seq_delimiter": self._attack_missing_seq_delimiter,
        }
        records: list[MultiFrameMutationRecord] = []
        for _ in range(mutation_count):
            attack_type = random.choice(self._ATTACK_TYPES)
            records.append(handlers[attack_type](dataset))
        return dataset, records


__all__ = ["EncapsulatedPixelStrategy"]
