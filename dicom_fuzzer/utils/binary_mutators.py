"""Binary-level mutation utilities for DICOM file bytes.

Format fuzzers operate primarily on pydicom Datasets, but pydicom
recalculates length fields and sanitises VRs on serialisation. Bugs that
require malformed-on-the-wire values (length wraparound, oversized
declared length, off-by-one truncation) are reachable only through
post-serialisation byte mutation.

This module hosts the shared byte-walker and the length-field corruption
helper so any fuzzer can opt into the attack class with one line. The
walker handles Explicit VR Little Endian only; Implicit VR LE has a
different element layout (no VR field, always 4-byte length) and is
out of scope here.

Public surface:

- :data:`DICM_MAGIC`, :data:`DICM_OFFSET`, :data:`DATA_OFFSET`,
  :data:`LONG_VRS` -- DICOM file-format constants.
- :data:`CORRUPT_LENGTHS_4B`, :data:`CORRUPT_LENGTHS_2B` -- attack
  patterns indexed by length-field width.
- :func:`is_valid_dicom` -- preamble + DICM magic check.
- :func:`parse_dicom_elements` -- enumerate length-corruptable elements.
- :func:`corrupt_random_length_field` -- the actual attack helper.
"""

from __future__ import annotations

import random
import struct
from typing import Final

# DICOM file layout constants ---------------------------------------------

DICM_MAGIC: Final[bytes] = b"DICM"
DICM_OFFSET: Final[int] = 128
DATA_OFFSET: Final[int] = 132  # preamble (128) + "DICM" (4)

# VRs that use a 2-byte reserved field followed by a 4-byte length field.
# All other Explicit VR LE elements use a 2-byte length field directly
# after the VR.
LONG_VRS: Final[frozenset[bytes]] = frozenset(
    {b"OB", b"OD", b"OF", b"OL", b"OW", b"SQ", b"UC", b"UN", b"UR", b"UT"}
)

# Length-corruption attack patterns.
#
# 4-byte slot: undefined-length sentinel (0xFFFFFFFF) flips the parser
# into delimited-item mode where it shouldn't be; signed boundary values
# probe int/uint conversion bugs; 16-bit-in-32-bit-slot values probe
# parsers that read the wrong width.
CORRUPT_LENGTHS_4B: Final[tuple[bytes, ...]] = (
    struct.pack("<I", 0xFFFFFFFF),
    struct.pack("<I", 0x00000000),
    struct.pack("<I", 0x7FFFFFFF),
    struct.pack("<I", 0x80000000),
    struct.pack("<I", 0x0000FFFF),
    struct.pack("<I", 0x00010000),
)

# 2-byte slot: max-uint reads as undefined sentinel for short VRs;
# zero-length where content is expected; signed-overflow boundary.
CORRUPT_LENGTHS_2B: Final[tuple[bytes, ...]] = (
    struct.pack("<H", 0xFFFF),
    struct.pack("<H", 0x0000),
    struct.pack("<H", 0x8000),
)


def is_valid_dicom(file_data: bytes) -> bool:
    """Return True if file_data has a valid DICOM preamble + DICM magic."""
    return (
        len(file_data) >= DATA_OFFSET + 4
        and file_data[DICM_OFFSET:DATA_OFFSET] == DICM_MAGIC
    )


def parse_dicom_elements(
    file_data: bytes, start_offset: int
) -> list[tuple[int, int, int, int]]:
    """Walk Explicit VR LE elements and return their byte ranges.

    Returns ``[(elem_start, elem_end, len_field_offset, len_field_size), ...]``.

    Skipped (intentionally not returned to callers, to avoid corrupting
    bytes that would break basic file readability for any target):

    - Group 0002 elements (file meta info; the dataset readers we target
      need this group intact to determine transfer syntax).
    - SQ elements (nested structure; corrupting their length desyncs the
      whole subtree, producing a different attack class that lives in
      sequence_fuzzer).
    - Elements with undefined length (0xFFFFFFFF / 0xFFFF -- already
      sentinel values).
    - Group 0xFFFE item/delimiter tags (not real elements).

    Stops on any parse error and returns whatever was collected so far.

    Args:
        file_data: Complete DICOM file bytes.
        start_offset: Byte offset to begin parsing at (typically
            :data:`DATA_OFFSET`).

    Returns:
        List of (elem_start, elem_end, len_field_offset, len_field_size).

    """
    results: list[tuple[int, int, int, int]] = []
    pos = start_offset
    data_len = len(file_data)

    try:
        while pos + 4 <= data_len:
            elem_start = pos

            # Read group + element (2 bytes each, little-endian)
            group = struct.unpack_from("<H", file_data, pos)[0]
            pos += 2
            pos += 2  # element number -- not needed for candidate selection

            # Skip group 0002 (file meta) -- must remain intact
            if group == 0x0002:
                if pos + 2 > data_len:
                    break
                vr = file_data[pos : pos + 2]
                pos += 2
                if vr in LONG_VRS:
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

            if vr in LONG_VRS:
                pos += 2  # skip reserved
                if pos + 4 > data_len:
                    break
                len_field_offset = pos
                len_field_size = 4
                length = struct.unpack_from("<I", file_data, pos)[0]
                pos += 4
            else:
                if pos + 2 > data_len:
                    break
                len_field_offset = pos
                len_field_size = 2
                length = struct.unpack_from("<H", file_data, pos)[0]
                pos += 2

            # Skip undefined-length elements and SQ
            if length == 0xFFFFFFFF or (len_field_size == 2 and length == 0xFFFF):
                break
            if vr == b"SQ":
                pos += length
                continue

            elem_end = pos + length
            if elem_end > data_len:
                break

            results.append((elem_start, elem_end, len_field_offset, len_field_size))
            pos = elem_end

    except struct.error:
        pass

    return results


def corrupt_random_length_field(
    file_data: bytes,
    *,
    rng: random.Random | None = None,
) -> bytes:
    """Pick a random Explicit VR LE element and rewrite its length field.

    The chosen pattern is selected from :data:`CORRUPT_LENGTHS_4B` or
    :data:`CORRUPT_LENGTHS_2B` depending on the element's length-field
    width. Length-preserving overall: only the length-field bytes
    change, so total file size and all other elements stay intact.

    Args:
        file_data: Complete DICOM file bytes.
        rng: Optional seeded :class:`random.Random` for deterministic
            tests. Defaults to the module-global random state.

    Returns:
        File bytes with one length field patched, or ``file_data``
        unchanged if validation fails (no DICM magic, no parseable
        elements, or any walking error).

    """
    if not is_valid_dicom(file_data):
        return file_data
    elements = parse_dicom_elements(file_data, DATA_OFFSET)
    if not elements:
        return file_data

    chooser = rng if rng is not None else random
    _, _, len_offset, len_size = chooser.choice(elements)

    if len_size == 4:
        corrupt = chooser.choice(CORRUPT_LENGTHS_4B)
    else:
        corrupt = chooser.choice(CORRUPT_LENGTHS_2B)

    result = bytearray(file_data)
    result[len_offset : len_offset + len_size] = corrupt
    return bytes(result)


__all__ = [
    "CORRUPT_LENGTHS_2B",
    "CORRUPT_LENGTHS_4B",
    "DATA_OFFSET",
    "DICM_MAGIC",
    "DICM_OFFSET",
    "LONG_VRS",
    "corrupt_random_length_field",
    "is_valid_dicom",
    "parse_dicom_elements",
]
