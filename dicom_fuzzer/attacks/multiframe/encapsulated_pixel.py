"""Encapsulated Pixel Data mutation strategy.

Strategy 9: Corrupt encapsulated (compressed) pixel data structures:
- Invalid Basic Offset Table (BOT) entries
- Extended Offset Table (EOT) inconsistencies
- Fragment size/count manipulation
- Missing or duplicate sequence delimiters
- BOT + EOT coexistence (violates standard)

Binary-level attacks (mutate_bytes) operate on the already-serialized
byte stream, attacking multi-frame-specific invariants that dataset-level
mutations cannot express (frame count / BOT entry count / fragment count
desync, EOT 64-bit offset overflow, EOT-vs-fragment mismatch).

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

from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import (
    EncapsRegion,
    _find_encapsulated_region,
)
from dicom_fuzzer.attacks.multiframe.format_base import MultiFrameMutationRecord
from dicom_fuzzer.utils.logger import get_logger

from .format_base import MultiFrameFuzzerBase

logger = get_logger(__name__)

# File-level DICOM constants
_DICM_MAGIC = b"DICM"
_DICM_OFFSET = 128
_DATA_OFFSET = 132  # preamble (128) + "DICM" (4)

# Tag bytes in Explicit-VR little-endian encoding
_NUMBER_OF_FRAMES_TAG = b"\x28\x00\x08\x00"  # (0028,0008)
_EOT_TAG = b"\xe0\x7f\x01\x00"  # (7FE0,0001) Extended Offset Table
_PIXEL_DATA_TAG = b"\xe0\x7f\x10\x00"  # (7FE0,0010)


def _find_region_tolerant(file_data: bytes) -> EncapsRegion | None:
    """Locate encapsulated pixel data, tolerating defined-length wrappers.

    The main generator pipeline forces Explicit VR Little Endian transfer
    syntax before writing, which wraps encapsulated pixel bytes in a
    defined-length element. The strict region finder in the format layer
    rejects that because encapsulation formally requires undefined length.
    This helper falls back to inspecting the PixelData value directly: if
    it starts with an Item tag, the BOT-plus-fragments structure is
    present regardless of the outer length encoding.
    """
    region = _find_encapsulated_region(file_data)
    if region is not None:
        return region

    idx = file_data.rfind(_PIXEL_DATA_TAG)
    if idx < 0:
        return None

    # Skip tag + (optional) VR + reserved + length, matching the strict
    # helper's offset math for Explicit VR.
    pos = idx + 4
    if pos + 2 <= len(file_data) and file_data[pos : pos + 2] in (b"OB", b"OW"):
        pos += 2 + 2  # VR + reserved
    if pos + 4 > len(file_data):
        return None
    length = struct.unpack_from("<I", file_data, pos)[0]
    pos += 4  # value_start

    # Encapsulated content always begins with an Item tag (BOT).
    if pos + 8 > len(file_data) or file_data[pos : pos + 4] != _ITEM_TAG_BYTES:
        return None

    bot_offset = pos
    bot_length = struct.unpack_from("<I", file_data, pos + 4)[0]
    first_fragment_offset = bot_offset + 8 + bot_length

    # For defined-length PixelData, the "sequence delimitation" is the end
    # of the value, not a delimiter tag. Set seq_delim_offset to value end.
    value_end = (
        idx + (12 if file_data[idx + 4 : idx + 6] in (b"OB", b"OW") else 8) + length
    )
    seq_delim_offset = file_data.find(
        b"\xfe\xff\xdd\xe0", first_fragment_offset, value_end
    )
    if seq_delim_offset < 0:
        # Still return a region; attacks that need the delimiter can check.
        seq_delim_offset = -1

    return EncapsRegion(
        bot_offset=bot_offset,
        bot_length=bot_length,
        first_fragment_offset=first_fragment_offset,
        seq_delim_offset=seq_delim_offset,
    )


# DICOM sequence delimiter bytes (FFFE,E0DD with zero length)
_SEQ_DELIM_BYTES = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
# DICOM item tag bytes (FFFE,E000)
_ITEM_TAG_BYTES = b"\xfe\xff\x00\xe0"
# Undefined length sentinel
_UNDEFINED_LENGTH = b"\xff\xff\xff\xff"


class EncapsulatedPixelStrategy(MultiFrameFuzzerBase):
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

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate datasets that carry pixel data."""
        return hasattr(dataset, "PixelData")

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
        import os

        fragments = [os.urandom(frame_size) for _ in range(frame_count)]

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
        frame_count = min(self._get_frame_count(dataset), 10)  # cap for perf
        frame_size = self._calculate_frame_size(dataset)
        if frame_size == 0:
            frame_size = 256  # Default fragment size
        # Cap to 256 bytes: the attack targets structure, not content size.
        frame_size = min(frame_size, 256)

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

    def _mutate_impl(
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

    # ------------------------------------------------------------------
    # Binary-level attacks -- operate on raw bytes after pydicom serializes.
    #
    # These attacks target invariants that dataset-level mutations cannot
    # express because pydicom may normalize the byte layout on write. The
    # attacks here are multi-frame-aware: they read NumberOfFrames from the
    # serialized bytes and use it to build BOT/EOT desync patterns tied to
    # the declared frame count.
    # ------------------------------------------------------------------

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Apply binary-level multi-frame encapsulation corruptions.

        Runs after mutate() + dcmwrite(). Selects 1 attack and applies it;
        returns file_data unchanged if the file is not valid DICOM or has
        no encapsulated pixel data.
        """
        self._applied_binary_mutations = []

        if len(file_data) < _DATA_OFFSET + 4:
            return file_data
        if file_data[_DICM_OFFSET:_DATA_OFFSET] != _DICM_MAGIC:
            return file_data

        region = _find_region_tolerant(file_data)
        if region is None:
            return file_data

        eot_offset = self._find_eot_offset(file_data)

        # BOT attacks always apply; EOT attacks only when an EOT is present.
        candidates = [
            self._binary_bot_count_desync,
            self._binary_bot_misaligned_offsets,
            self._binary_bot_vs_frame_count_mismatch,
        ]
        if eot_offset is not None:
            candidates.extend(
                [
                    self._binary_eot_offset_overflow,
                    self._binary_eot_count_mismatch,
                    self._binary_eot_offset_past_eof,
                ]
            )

        attack = random.choice(candidates)
        try:
            result = attack(file_data, region, eot_offset)
            self._applied_binary_mutations.append(attack.__name__)
            return result
        except Exception as e:
            logger.debug("Multiframe binary attack %s failed: %s", attack.__name__, e)
            return file_data

    # -- helpers --

    @staticmethod
    def _find_eot_offset(file_data: bytes) -> int | None:
        """Return byte offset of the Extended Offset Table tag, or None.

        Searches for tag (7FE0,0001) before the Pixel Data tag (7FE0,0010).
        Returns the offset of the tag's first byte, suitable for direct
        patching. None if the EOT tag is not present in the main dataset.
        """
        idx = file_data.find(_EOT_TAG, _DATA_OFFSET)
        if idx < 0:
            return None
        return idx

    @staticmethod
    def _read_number_of_frames(file_data: bytes) -> int | None:
        """Parse NumberOfFrames (0028,0008) from serialized bytes.

        Returns the integer value or None if the tag isn't found. The tag
        has VR IS (Integer String), so the value bytes are ASCII digits
        with optional whitespace/sign padding.
        """
        idx = file_data.find(_NUMBER_OF_FRAMES_TAG, _DATA_OFFSET)
        if idx < 0 or idx + 8 > len(file_data):
            return None
        vr = file_data[idx + 4 : idx + 6]
        if vr != b"IS":
            return None
        length = struct.unpack_from("<H", file_data, idx + 6)[0]
        value_start = idx + 8
        if value_start + length > len(file_data):
            return None
        raw = file_data[value_start : value_start + length].decode("ascii", "ignore")
        # IS VR is padded with SPACE (0x20) to even length, but tolerate
        # null padding too since some serializers emit it.
        try:
            return int(raw.strip().rstrip("\x00"))
        except ValueError:
            return None

    @staticmethod
    def _count_fragments(file_data: bytes, first_fragment_offset: int) -> int:
        """Count fragment items between first_fragment_offset and the Sequence
        Delimitation Item. Returns 0 on parse error.
        """
        count = 0
        pos = first_fragment_offset
        data_len = len(file_data)
        # _ITEM_TAG_BYTES = b"\xfe\xff\x00\xe0"
        # _SEQ_DELIM pattern starts with b"\xfe\xff\xdd\xe0"
        while pos + 8 <= data_len:
            tag = file_data[pos : pos + 4]
            if tag == b"\xfe\xff\xdd\xe0":
                break  # hit sequence delimiter
            if tag != _ITEM_TAG_BYTES:
                break  # unexpected tag; stop counting
            length = struct.unpack_from("<I", file_data, pos + 4)[0]
            if length == 0xFFFFFFFF:
                break  # undefined length fragment; can't advance safely
            pos += 8 + length
            count += 1
            if count > 10000:  # safety cap
                break
        return count

    # -- binary BOT attacks --

    def _binary_bot_count_desync(
        self,
        file_data: bytes,
        region: EncapsRegion,
        eot_offset: int | None,
    ) -> bytes:
        """Rewrite BOT to declare N+5 offsets while only N fragments exist.

        Parsers that use BOT entries to seek to each frame will read past
        the final fragment into the Sequence Delimitation Item (or EOF).
        """
        fragment_count = self._count_fragments(file_data, region.first_fragment_offset)
        if fragment_count == 0:
            return file_data

        new_entry_count = fragment_count + 5

        # Stride roughly matches the average fragment footprint, so early
        # entries look plausible and late entries overrun the fragment list.
        avg_stride = max(
            16,
            (len(file_data) - region.first_fragment_offset) // max(1, fragment_count),
        )
        offsets = [i * avg_stride for i in range(new_entry_count)]
        new_bot_data = struct.pack(f"<{new_entry_count}I", *offsets)
        new_bot_item = (
            _ITEM_TAG_BYTES + struct.pack("<I", len(new_bot_data)) + new_bot_data
        )

        # Splice: keep everything before the original BOT item header, replace
        # the BOT (tag+length+data), keep everything after (fragments +
        # sequence delimiter).
        before = file_data[: region.bot_offset]
        after = file_data[region.first_fragment_offset :]
        return before + new_bot_item + after

    def _binary_bot_misaligned_offsets(
        self,
        file_data: bytes,
        region: EncapsRegion,
        eot_offset: int | None,
    ) -> bytes:
        """Rewrite BOT entries to point 3 bytes past real fragment boundaries.

        Parsers that seek to the declared offset to read the next Item tag
        will land mid-fragment and misinterpret the next 8 bytes as tag+length.
        """
        fragment_count = self._count_fragments(file_data, region.first_fragment_offset)
        if fragment_count == 0:
            return file_data

        # Compute real offsets, then shift each by +3 bytes.
        pos = region.first_fragment_offset
        real_offsets: list[int] = []
        for _ in range(fragment_count):
            if pos + 8 > len(file_data):
                break
            real_offsets.append(pos - region.first_fragment_offset)
            length = struct.unpack_from("<I", file_data, pos + 4)[0]
            if length == 0xFFFFFFFF:
                break
            pos += 8 + length

        if not real_offsets:
            return file_data

        misaligned = [(o + 3) & 0xFFFFFFFF for o in real_offsets]
        new_bot_data = struct.pack(f"<{len(misaligned)}I", *misaligned)
        new_bot_item = (
            _ITEM_TAG_BYTES + struct.pack("<I", len(new_bot_data)) + new_bot_data
        )

        before = file_data[: region.bot_offset]
        after = file_data[region.first_fragment_offset :]
        return before + new_bot_item + after

    def _binary_bot_vs_frame_count_mismatch(
        self,
        file_data: bytes,
        region: EncapsRegion,
        eot_offset: int | None,
    ) -> bytes:
        """Replace BOT with one whose entry count wildly differs from
        NumberOfFrames.

        Parsers that allocate a NumberOfFrames-sized frame-offset array and
        then iterate over BOT entries (or vice versa) get a size mismatch.
        """
        declared = self._read_number_of_frames(file_data)
        if declared is None:
            declared = self._count_fragments(file_data, region.first_fragment_offset)
        if declared <= 0:
            declared = 1

        # Either way-more or way-fewer entries than declared frames.
        if random.random() < 0.5:
            new_count = declared * 4 + 1  # way-more
        else:
            new_count = max(1, declared // 4)  # way-fewer

        offsets = [i * 256 for i in range(new_count)]
        new_bot_data = struct.pack(f"<{new_count}I", *offsets)
        new_bot_item = (
            _ITEM_TAG_BYTES + struct.pack("<I", len(new_bot_data)) + new_bot_data
        )

        before = file_data[: region.bot_offset]
        after = file_data[region.first_fragment_offset :]
        return before + new_bot_item + after

    # -- binary EOT attacks --

    def _binary_eot_offset_overflow(
        self,
        file_data: bytes,
        region: EncapsRegion,
        eot_offset: int | None,
    ) -> bytes:
        """Overwrite one EOT 64-bit offset entry with UINT64_MAX.

        Parsers that cast the offset to signed int64 see -1; those that do
        arithmetic on it overflow. Either way, downstream buffer math is
        wrong.
        """
        if eot_offset is None:
            return file_data
        entry_info = self._parse_eot_value(file_data, eot_offset)
        if entry_info is None:
            return file_data
        value_start, length = entry_info
        if length < 8:
            return file_data

        num_entries = length // 8
        victim_idx = random.randrange(num_entries)
        pos = value_start + victim_idx * 8

        result = bytearray(file_data)
        struct.pack_into("<Q", result, pos, 0xFFFFFFFFFFFFFFFF)
        return bytes(result)

    def _binary_eot_count_mismatch(
        self,
        file_data: bytes,
        region: EncapsRegion,
        eot_offset: int | None,
    ) -> bytes:
        """Truncate or extend EOT value so its entry count disagrees with
        the actual number of fragments.
        """
        if eot_offset is None:
            return file_data
        entry_info = self._parse_eot_value(file_data, eot_offset)
        if entry_info is None:
            return file_data
        value_start, length = entry_info

        fragment_count = self._count_fragments(file_data, region.first_fragment_offset)
        delta = random.choice([-3, -2, 2, 3])
        new_count = max(1, fragment_count + delta)
        new_value = struct.pack(f"<{new_count}Q", *[i * 512 for i in range(new_count)])

        # EOT element layout (long-VR form): tag(4) + VR(2) + reserved(2) +
        # length(4) + value. Patch the length field in place, then splice
        # the new value into the byte stream in place of the old one.
        header = bytearray(file_data[eot_offset : eot_offset + 12])
        struct.pack_into("<I", header, 8, len(new_value))

        before = file_data[:eot_offset]
        after = file_data[value_start + length :]
        return before + bytes(header) + new_value + after

    def _binary_eot_offset_past_eof(
        self,
        file_data: bytes,
        region: EncapsRegion,
        eot_offset: int | None,
    ) -> bytes:
        """Set all EOT entries to an offset past EOF.

        Parsers that seek to the declared offset read from unmapped memory
        or beyond buffer bounds.
        """
        if eot_offset is None:
            return file_data
        entry_info = self._parse_eot_value(file_data, eot_offset)
        if entry_info is None:
            return file_data
        value_start, length = entry_info
        if length < 8:
            return file_data

        num_entries = length // 8
        past_eof = len(file_data) + 0x100000  # 1 MB past EOF

        result = bytearray(file_data)
        for i in range(num_entries):
            struct.pack_into("<Q", result, value_start + i * 8, past_eof)
        return bytes(result)

    @staticmethod
    def _parse_eot_value(file_data: bytes, eot_offset: int) -> tuple[int, int] | None:
        """Return (value_start, value_length) for the EOT element at eot_offset.

        EOT uses VR "OV" (long-form): tag(4) + VR(2) + reserved(2) + length(4).
        Some encoders ship EOT as "OB" (also long-form, same layout). Returns
        None if the header is malformed or would read past EOF.
        """
        if eot_offset + 12 > len(file_data):
            return None
        vr = file_data[eot_offset + 4 : eot_offset + 6]
        if vr not in (b"OV", b"OB"):
            return None
        length = struct.unpack_from("<I", file_data, eot_offset + 8)[0]
        value_start = eot_offset + 12
        if value_start + length > len(file_data):
            return None
        return value_start, length


__all__ = ["EncapsulatedPixelStrategy"]
