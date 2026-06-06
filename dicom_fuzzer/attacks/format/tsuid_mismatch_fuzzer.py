"""TSUID Mismatch Fuzzer - Declared-vs-actual Transfer Syntax conflict.

Category: generic

Attacks the parser-state interaction between the declared Transfer
Syntax UID and the on-disk PixelData bytes. When a parser selects its
pixel-data decoder from the TSUID but the actual PixelData bytes were
written for a different transfer syntax, sizing math, termination
conditions, and codec-state transitions can all go wrong.

The minimum trigger for the Hermes CWE-770 memory-amplification
finding (>4 GB allocation from a 6 KB file) is exactly this pattern:
declared Explicit VR Little Endian + encapsulated JPEG 2000 PixelData
bytes + Rows = 0. Each tag mutation alone is harmless; the
interaction is what's lethal.

Dataset-level attacks (mutate):
- Swap TSUID to Explicit VR Little Endian while preserving encapsulated
  PixelData bytes (the BD-style mismatch)
- Swap TSUID to Implicit VR Little Endian (alternate uncompressed target)
- Above + set Rows = 0 (the proven Hermes CWE-770 trigger)

Binary-level attacks (mutate_bytes):
- Post-serialization swap of (0002,0010) TSUID to Explicit VR Big
  Endian after pydicom has already serialised the dataset in LE.
  Total byte-order disagreement on every numeric value -- pydicom
  cannot express this from the dataset level because it re-serialises
  according to the declared TSUID.

Reference: artifacts/findings/cwe770_memory_amplification/disclosure/
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Uncompressed transfer syntaxes -- safe to declare without actually
# re-encoding the bytes, which is precisely the point.
_TSUID_EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"
_TSUID_IMPLICIT_VR_LE = "1.2.840.10008.1.2"
_TSUID_EXPLICIT_VR_BE = "1.2.840.10008.1.2.2"

# Transfer syntaxes considered uncompressed for the purposes of
# "is the current TSUID worth swapping?". Files already in one of
# these have no encapsulated payload to leave behind, so the
# mismatch attack is a no-op on them.
_UNCOMPRESSED_TSUIDS = frozenset(
    {
        "1.2.840.10008.1.2",  # Implicit VR Little Endian
        "1.2.840.10008.1.2.1",  # Explicit VR Little Endian
        "1.2.840.10008.1.2.2",  # Explicit VR Big Endian
    }
)

# Long VRs in File Meta Information that use the 4-byte length encoding
# with 2 reserved bytes between VR and length.
_LONG_VRS = frozenset({b"OB", b"OW", b"OF", b"SQ", b"UT", b"UN"})

_DATA_OFFSET = 132  # 128-byte preamble + 4-byte DICM magic


class TSUIDMismatchFuzzer(FormatFuzzerBase):
    """Create a declared-vs-actual transfer syntax mismatch.

    Operates on files with an encapsulated transfer syntax (JPEG,
    JPEG 2000, JPEG-LS, RLE, etc.) by rewriting the TSUID to an
    uncompressed value while leaving the encapsulated PixelData bytes
    untouched. The result is a structurally valid DICOM file whose
    declared pixel-data layout disagrees with its actual contents.
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "tsuid_mismatch"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Skip files that don't have an encapsulated TSUID to mismatch."""
        file_meta = getattr(dataset, "file_meta", None)
        if file_meta is None:
            return False
        ts = getattr(file_meta, "TransferSyntaxUID", None)
        if ts is None:
            return False
        return str(ts) not in _UNCOMPRESSED_TSUIDS

    def mutate(self, dataset: Dataset) -> Dataset:
        """Pick one variant at random and apply it to the dataset."""
        variants = [
            self._swap_to_explicit_vr_le,
            self._swap_to_implicit_vr_le,
            self._swap_with_rows_zero,
        ]
        chosen = random.choice(variants)
        self.last_variant = chosen.__name__
        try:
            return chosen(dataset)
        except Exception as e:
            logger.debug("tsuid_mismatch variant %s failed: %s", chosen.__name__, e)
            return dataset

    def _swap_to_explicit_vr_le(self, dataset: Dataset) -> Dataset:
        dataset.file_meta.TransferSyntaxUID = _TSUID_EXPLICIT_VR_LE
        return dataset

    def _swap_to_implicit_vr_le(self, dataset: Dataset) -> Dataset:
        dataset.file_meta.TransferSyntaxUID = _TSUID_IMPLICIT_VR_LE
        return dataset

    def _swap_with_rows_zero(self, dataset: Dataset) -> Dataset:
        # The proven Hermes CWE-770 trigger. TSUID flip selects the
        # uncompressed reader; Rows=0 poisons its sizing math.
        dataset.file_meta.TransferSyntaxUID = _TSUID_EXPLICIT_VR_LE
        if "Rows" in dataset:
            dataset.Rows = 0
        return dataset

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Post-serialization swap of (0002,0010) to Big Endian.

        pydicom serialises the dataset according to whatever TSUID the
        ``file_meta`` declares at write time. If we change the TSUID
        before write, pydicom obligingly re-encodes element headers and
        numeric values for the new syntax -- defeating the attack. The
        only way to declare BE while leaving the dataset bytes in LE is
        to rewrite the TSUID value *after* serialization.

        Result: every US/UL/SS/SL/OW value in the dataset has the
        opposite byte order from what the declared TSUID demands.
        Element lengths read as wildly wrong values on the first
        numeric tag, causing a guaranteed parser desync.

        File Meta Information is always Explicit VR Little Endian, so
        we walk the (0002,*) region looking for (0002,0010) and
        overwrite its UI value bytes. The new value is padded/truncated
        to the existing field length so we do not shift later FMI
        offsets.

        Returns ``file_data`` unchanged on any structural mismatch.
        """
        self._applied_binary_mutations = []
        result = self._swap_tsuid_to_big_endian(file_data)
        if result is not file_data:
            self._applied_binary_mutations.append("_swap_tsuid_to_big_endian")
        return result

    def _swap_tsuid_to_big_endian(self, file_data: bytes) -> bytes:
        """Find (0002,0010) in the FMI and overwrite its UI value with BE TSUID.

        Returns ``file_data`` unchanged on bounds-check failure or if
        the TransferSyntaxUID element is not found.
        """
        if len(file_data) < _DATA_OFFSET + 8 or file_data[128:132] != b"DICM":
            return file_data

        pos = _DATA_OFFSET
        end = len(file_data)
        while pos + 8 <= end:
            group = struct.unpack_from("<H", file_data, pos)[0]
            if group != 0x0002:
                # Walked past File Meta Information without finding (0002,0010).
                return file_data
            element = struct.unpack_from("<H", file_data, pos + 2)[0]
            vr = bytes(file_data[pos + 4 : pos + 6])
            if vr in _LONG_VRS:
                if pos + 12 > end:
                    return file_data
                length = struct.unpack_from("<I", file_data, pos + 8)[0]
                value_start = pos + 12
            else:
                length = struct.unpack_from("<H", file_data, pos + 6)[0]
                value_start = pos + 8
            value_end = value_start + length
            if value_end > end:
                return file_data
            if element == 0x0010:  # TransferSyntaxUID
                if length == 0:
                    return file_data
                # Pad with NUL to match existing field length; truncate if
                # current value field is shorter than the new UID string.
                be_uid = _TSUID_EXPLICIT_VR_BE.encode("ascii")
                if len(be_uid) >= length:
                    new_value = be_uid[:length]
                else:
                    # UI must be even-length per PS3.5; pad with NUL bytes.
                    pad_len = length - len(be_uid)
                    new_value = be_uid + (b"\x00" * pad_len)
                out = bytearray(file_data)
                out[value_start:value_end] = new_value
                return bytes(out)
            pos = value_end
        return file_data
