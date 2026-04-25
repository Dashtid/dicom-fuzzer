"""Tests for EncapsulatedPixelStrategy.mutate_bytes() binary attacks.

Builds a minimal valid encapsulated multi-frame DICOM byte stream as a
fixture, then exercises each binary attack in isolation and verifies the
resulting byte-level invariants.
"""

from __future__ import annotations

import struct

import pytest
from pydicom.uid import UID

from dicom_fuzzer.attacks.multiframe.encapsulated_pixel import (
    _EOT_TAG,
    _NUMBER_OF_FRAMES_TAG,
    EncapsulatedPixelStrategy,
)

# DICOM constants mirrored from the strategy module -- kept local so these
# tests document the byte layout under test.
_ITEM_TAG = b"\xfe\xff\x00\xe0"
_SEQ_DELIM = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
_PIXEL_DATA_TAG_EXPLICIT = b"\xe0\x7f\x10\x00OB\x00\x00\xff\xff\xff\xff"
_DICM_PREAMBLE = b"\x00" * 128 + b"DICM"


def _build_bot(fragment_sizes: list[int]) -> bytes:
    """Build a Basic Offset Table Item with one 32-bit offset per fragment."""
    current = 0
    offsets: list[int] = []
    for size in fragment_sizes:
        offsets.append(current)
        current += 8 + size  # Item tag(4) + length(4) + data
    bot_value = struct.pack(f"<{len(offsets)}I", *offsets)
    return _ITEM_TAG + struct.pack("<I", len(bot_value)) + bot_value


def _build_fragments(sizes: list[int]) -> bytes:
    out = b""
    for size in sizes:
        out += _ITEM_TAG + struct.pack("<I", size) + (b"\xaa" * size)
    return out


def _build_file_meta(num_frames: int, include_eot: bool = False) -> bytes:
    """Build a minimal dataset header up to (but not including) PixelData.

    Layout: preamble + DICM + minimal group 0002 + NumberOfFrames element
    + optional EOT element (as VR OV).
    """
    # Group 0002 is tiny; a real meta header has TransferSyntaxUID etc., but
    # the mutate_bytes code paths under test only care about the main dataset.
    # Build a 0002,0000 GroupLength element with a short TransferSyntaxUID.
    ts = UID("1.2.840.10008.1.2.4.90").encode("ascii")
    if len(ts) % 2 == 1:
        ts += b"\x00"
    transfer_syntax_elem = (
        b"\x02\x00\x10\x00"  # (0002,0010)
        + b"UI"
        + struct.pack("<H", len(ts))
        + ts
    )
    group_length_value = struct.pack("<I", len(transfer_syntax_elem))
    group_length_elem = (
        b"\x02\x00\x00\x00"  # (0002,0000)
        + b"UL"
        + struct.pack("<H", 4)
        + group_length_value
    )
    meta = group_length_elem + transfer_syntax_elem

    # Main dataset: NumberOfFrames (0028,0008) as IS VR
    nof_str = str(num_frames).encode("ascii")
    if len(nof_str) % 2 == 1:
        nof_str += b"\x00"
    nof_elem = _NUMBER_OF_FRAMES_TAG + b"IS" + struct.pack("<H", len(nof_str)) + nof_str

    header = _DICM_PREAMBLE + meta + nof_elem

    if include_eot:
        # EOT with one 64-bit offset per frame, VR OV (long form).
        eot_value = struct.pack(
            f"<{num_frames}Q", *[i * 1024 for i in range(num_frames)]
        )
        eot_elem = (
            _EOT_TAG
            + b"OV"
            + b"\x00\x00"  # reserved
            + struct.pack("<I", len(eot_value))
            + eot_value
        )
        header += eot_elem

    return header


def _build_encapsulated_file(num_frames: int = 3, include_eot: bool = False) -> bytes:
    """Build a minimal valid encapsulated DICOM byte stream."""
    header = _build_file_meta(num_frames, include_eot=include_eot)
    fragment_sizes = [16] * num_frames
    bot = _build_bot(fragment_sizes)
    fragments = _build_fragments(fragment_sizes)
    pixel_data = _PIXEL_DATA_TAG_EXPLICIT + bot + fragments + _SEQ_DELIM
    return header + pixel_data


# -----------------------------------------------------------------------
# Sanity: the fixture itself round-trips through the parser
# -----------------------------------------------------------------------


def test_fixture_parses_as_encapsulated() -> None:
    """Fixture builder produces bytes the region parser recognises."""
    from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import (
        _find_encapsulated_region,
    )

    data = _build_encapsulated_file(num_frames=3)
    region = _find_encapsulated_region(data)
    assert region is not None
    assert region.bot_length == 3 * 4  # 3 entries, 4 bytes each


def test_number_of_frames_is_readable() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=7)
    assert strategy._read_number_of_frames(data) == 7


def test_eot_offset_found_when_present() -> None:
    strategy = EncapsulatedPixelStrategy()
    with_eot = _build_encapsulated_file(num_frames=3, include_eot=True)
    without_eot = _build_encapsulated_file(num_frames=3, include_eot=False)
    assert strategy._find_eot_offset(with_eot) is not None
    assert strategy._find_eot_offset(without_eot) is None


# -----------------------------------------------------------------------
# Top-level mutate_bytes() contract
# -----------------------------------------------------------------------


def test_mutate_bytes_no_op_on_non_dicom() -> None:
    strategy = EncapsulatedPixelStrategy()
    assert strategy.mutate_bytes(b"not a dicom file") == b"not a dicom file"


def test_mutate_bytes_no_op_on_non_encapsulated() -> None:
    """Pixel-less file returns unchanged and records no mutation."""
    strategy = EncapsulatedPixelStrategy()
    no_pixel = _DICM_PREAMBLE + _build_file_meta(num_frames=1)
    result = strategy.mutate_bytes(no_pixel)
    assert result == no_pixel
    assert strategy._applied_binary_mutations == []


def test_mutate_bytes_records_applied_attack() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=4)
    result = strategy.mutate_bytes(data)
    # Attack must have fired (non-encapsulated case is handled separately).
    assert len(strategy._applied_binary_mutations) == 1
    assert strategy._applied_binary_mutations[0].startswith("_binary_")
    # Result is bytes and (for all 3 BOT-only attacks) has file size that
    # may change. We only require it's bytes.
    assert isinstance(result, bytes)


# -----------------------------------------------------------------------
# BOT attacks
# -----------------------------------------------------------------------


def _region(data: bytes):
    from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import (
        _find_encapsulated_region,
    )

    return _find_encapsulated_region(data)


def test_bot_count_desync_adds_entries() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=3)
    region = _region(data)
    mutated = strategy._binary_bot_count_desync(data, region, None)

    new_region = _region(mutated)
    assert new_region is not None
    # Original BOT had 3 entries (12 bytes); new one has 3+5 = 8 entries (32 bytes).
    assert new_region.bot_length == 8 * 4


def test_bot_misaligned_offsets_shifts_entries_by_3() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=3)
    region = _region(data)
    mutated = strategy._binary_bot_misaligned_offsets(data, region, None)

    new_region = _region(mutated)
    assert new_region is not None
    bot_value_start = new_region.bot_offset + 8
    entries = struct.unpack_from(
        f"<{new_region.bot_length // 4}I", mutated, bot_value_start
    )
    # Real fragment offsets in the fixture are 0, 24, 48 (8-byte item header +
    # 16-byte payload each). Attack adds 3 to each.
    assert entries == (3, 27, 51)


def test_bot_vs_frame_count_mismatch_size_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=4)
    region = _region(data)

    # Force the "way-more" branch (4 * 4 + 1 = 17 entries).
    monkeypatch.setattr(
        "dicom_fuzzer.attacks.multiframe.encapsulated_pixel.random.random", lambda: 0.0
    )
    mutated = strategy._binary_bot_vs_frame_count_mismatch(data, region, None)
    new_region = _region(mutated)
    assert new_region is not None
    assert new_region.bot_length == 17 * 4

    # And the "way-fewer" branch (4 // 4 = 1 entry).
    monkeypatch.setattr(
        "dicom_fuzzer.attacks.multiframe.encapsulated_pixel.random.random", lambda: 1.0
    )
    mutated = strategy._binary_bot_vs_frame_count_mismatch(data, region, None)
    new_region = _region(mutated)
    assert new_region is not None
    assert new_region.bot_length == 1 * 4


# -----------------------------------------------------------------------
# EOT attacks
# -----------------------------------------------------------------------


def test_eot_offset_overflow_patches_one_entry() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=4, include_eot=True)
    region = _region(data)
    eot_offset = strategy._find_eot_offset(data)
    assert eot_offset is not None

    mutated = strategy._binary_eot_offset_overflow(data, region, eot_offset)
    assert len(mutated) == len(data)  # in-place patch, no resize

    # At least one EOT entry must now be UINT64_MAX.
    value_start = eot_offset + 12
    entries = struct.unpack_from("<4Q", mutated, value_start)
    assert 0xFFFFFFFFFFFFFFFF in entries


def test_eot_offset_overflow_no_op_without_eot() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=3, include_eot=False)
    region = _region(data)
    assert strategy._binary_eot_offset_overflow(data, region, None) == data


def test_eot_count_mismatch_changes_eot_length(monkeypatch: pytest.MonkeyPatch) -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=4, include_eot=True)
    region = _region(data)
    eot_offset = strategy._find_eot_offset(data)
    assert eot_offset is not None

    # Pin delta to +3 so the new EOT has 4 + 3 = 7 entries.
    monkeypatch.setattr(
        "dicom_fuzzer.attacks.multiframe.encapsulated_pixel.random.choice",
        lambda seq: 3 if -3 in seq else seq[0],
    )
    mutated = strategy._binary_eot_count_mismatch(data, region, eot_offset)

    # Length field should now encode 7 * 8 = 56 bytes.
    new_length = struct.unpack_from("<I", mutated, eot_offset + 8)[0]
    assert new_length == 7 * 8

    # And the file grew by 3 entries * 8 bytes = 24.
    assert len(mutated) == len(data) + 24


def test_eot_offset_past_eof_sets_all_entries_past_length() -> None:
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=3, include_eot=True)
    region = _region(data)
    eot_offset = strategy._find_eot_offset(data)
    assert eot_offset is not None

    mutated = strategy._binary_eot_offset_past_eof(data, region, eot_offset)
    value_start = eot_offset + 12
    entries = struct.unpack_from("<3Q", mutated, value_start)
    assert all(e > len(mutated) for e in entries)


# -----------------------------------------------------------------------
# Attack selection: EOT attacks only offered when EOT is present
# -----------------------------------------------------------------------


def test_mutate_bytes_skips_eot_attacks_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When EOT is absent, random.choice must only see the 3 BOT attacks."""
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=3, include_eot=False)

    captured: list[list] = []

    def _spy(seq):
        captured.append(list(seq))
        return seq[0]

    monkeypatch.setattr(
        "dicom_fuzzer.attacks.multiframe.encapsulated_pixel.random.choice", _spy
    )
    strategy.mutate_bytes(data)
    assert len(captured) == 1
    assert len(captured[0]) == 3  # 3 BOT candidates only


def test_mutate_bytes_includes_eot_attacks_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When EOT is present, all 6 attacks are candidates."""
    strategy = EncapsulatedPixelStrategy()
    data = _build_encapsulated_file(num_frames=3, include_eot=True)

    captured: list[list] = []

    def _spy(seq):
        captured.append(list(seq))
        return seq[0]

    monkeypatch.setattr(
        "dicom_fuzzer.attacks.multiframe.encapsulated_pixel.random.choice", _spy
    )
    strategy.mutate_bytes(data)
    assert len(captured) == 1
    assert len(captured[0]) == 6
