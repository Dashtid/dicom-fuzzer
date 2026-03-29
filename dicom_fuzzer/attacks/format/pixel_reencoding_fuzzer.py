"""Pixel Re-encoding Fuzzer — RLE Lossless re-encoding with targeted mutations.

Category: generic

Attacks:
- Re-encode uncompressed pixel data as valid DICOM RLE Lossless, then flip
  one byte in the segment data to trigger codec fault paths
- Re-encode as valid RLE but corrupt the segment-count field in the 64-byte
  header so the decoder walks past the actual segment data
- Re-encode as valid RLE but declare a JPEG transfer syntax, routing the
  RLE byte stream through the JPEG codec dispatcher
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset
from pydicom.encaps import encapsulate
from pydicom.tag import Tag
from pydicom.uid import (
    JPEGBaseline8Bit,
    RLELossless,
)

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Transfer syntaxes with uncompressed (native) pixel data.
# Only these can be re-encoded without an external codec.
_UNCOMPRESSED_SYNTAXES: frozenset[str] = frozenset(
    {
        "1.2.840.10008.1.2",  # Implicit VR Little Endian
        "1.2.840.10008.1.2.1",  # Explicit VR Little Endian
        "1.2.840.10008.1.2.2",  # Explicit VR Big Endian (retired)
    }
)

_PIXEL_DATA_TAG = Tag(0x7FE0, 0x0010)


# ---------------------------------------------------------------------------
# Pure-Python RLE Lossless helpers (DICOM PS3.5 Annex G)
# ---------------------------------------------------------------------------


def _packbits_encode(data: bytes) -> bytes:
    """Apply PackBits compression to a byte string.

    PackBits encoding (DICOM RLE Lossless segment format):
    - Run of N identical bytes  → emit (257 - N) & 0xFF, then the byte
    - Literal run of N bytes    → emit N - 1, then the N bytes

    Args:
        data: Raw byte string to compress.

    Returns:
        PackBits-compressed bytes.

    """
    result = bytearray()
    i = 0
    n = len(data)
    while i < n:
        # Detect run of identical bytes (max 128)
        run_end = i + 1
        while run_end < n and data[run_end] == data[i] and (run_end - i) < 128:
            run_end += 1
        run_len = run_end - i
        if run_len >= 2:
            result.append((257 - run_len) & 0xFF)
            result.append(data[i])
            i = run_end
        else:
            # Collect literal bytes until a run starts (max 128)
            lit_end = i + 1
            while lit_end < n and (lit_end - i) < 128:
                if lit_end + 1 < n and data[lit_end] == data[lit_end + 1]:
                    break
                lit_end += 1
            lit_len = lit_end - i
            result.append(lit_len - 1)
            result.extend(data[i:lit_end])
            i = lit_end
    return bytes(result)


def _encode_rle_frame(
    pixel_bytes: bytes,
    bits_alloc: int,
    samples_per_pixel: int,
) -> bytes:
    """Encode a single uncompressed pixel frame as DICOM RLE Lossless.

    Splits the pixel bytes into byte-planes (one PackBits segment per byte of
    sample, most-significant byte first for multi-byte samples), then
    assembles the 64-byte RLE header followed by the segment data.

    Args:
        pixel_bytes: Raw, uncompressed pixel data for one frame.
        bits_alloc: BitsAllocated (8 or 16 are typical).
        samples_per_pixel: Number of samples per pixel (1 for grayscale, 3 for RGB).

    Returns:
        Encoded RLE frame bytes (header + segments), ready for encapsulate().

    """
    bytes_per_sample = max(1, bits_alloc // 8)
    n_segments = bytes_per_sample * samples_per_pixel
    n_pixels = len(pixel_bytes) // (bytes_per_sample * samples_per_pixel)

    segments: list[bytes] = []
    for sample_idx in range(samples_per_pixel):
        # MSB first within each sample (high byte before low byte)
        for byte_idx in range(bytes_per_sample - 1, -1, -1):
            plane = bytearray(n_pixels)
            for px in range(n_pixels):
                src = px * samples_per_pixel * bytes_per_sample
                src += sample_idx * bytes_per_sample + byte_idx
                if src < len(pixel_bytes):
                    plane[px] = pixel_bytes[src]
            segments.append(_packbits_encode(bytes(plane)))

    # Build 64-byte header: 4-byte count + 15 x 4-byte offsets
    header = bytearray(64)
    struct.pack_into("<I", header, 0, min(n_segments, 15))
    offset = 64  # First segment byte offset from start of header
    for i, seg in enumerate(segments[:15]):
        struct.pack_into("<I", header, 4 + i * 4, offset)
        seg_len = len(seg)
        offset += seg_len + (seg_len % 2)  # pad each segment to even length

    # Assemble: header + segments (each padded to even length)
    result = bytes(header)
    for seg in segments:
        result += seg
        if len(seg) % 2 == 1:
            result += b"\x00"
    return result


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------


class PixelReencodingFuzzer(FormatFuzzerBase):
    """Re-encodes uncompressed pixel data as DICOM RLE Lossless then mutates.

    Unlike CompressedPixelFuzzer (which uses entirely synthetic frames), this
    fuzzer starts with the dataset's actual pixel values so that the resulting
    byte stream exercises real codec decoding paths before hitting the corruption.

    Only operates on datasets with an uncompressed transfer syntax; skips
    datasets that are already encapsulated (CompressedPixelFuzzer covers those).
    """

    def __init__(self) -> None:
        """Initialize the pixel re-encoding fuzzer."""
        super().__init__()
        self.mutation_strategies = [
            self._reencode_valid_then_flip,  # [STRUCTURAL] valid RLE + 1-byte flip in segment data → codec fault
            self._reencode_corrupt_segment_count,  # [STRUCTURAL] valid RLE + wrong segment count → walker reads past data
            self._reencode_wrong_syntax,  # [STRUCTURAL] valid RLE + JPEG TS declaration → codec dispatch confusion
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "pixel_reencoding"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True only for uncompressed datasets with pixel data present."""
        if _PIXEL_DATA_TAG not in dataset:
            return False
        if not (
            hasattr(dataset, "Rows")
            and hasattr(dataset, "Columns")
            and hasattr(dataset, "BitsAllocated")
        ):
            return False
        ts = str(
            getattr(
                getattr(dataset, "file_meta", None),
                "TransferSyntaxUID",
                "1.2.840.10008.1.2.1",
            )
        )
        return ts in _UNCOMPRESSED_SYNTAXES

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply one pixel re-encoding mutation.

        Args:
            dataset: The DICOM dataset to mutate.

        Returns:
            Mutated dataset with re-encoded and corrupted pixel data.

        """
        strategy = random.choice(self.mutation_strategies)
        self.last_variant = strategy.__name__
        try:
            dataset = strategy(dataset)
        except Exception as e:
            logger.debug("Pixel re-encoding mutation failed: %s", e)
        return dataset

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_pixel_bytes(self, dataset: Dataset) -> bytes | None:
        """Return raw pixel bytes from dataset, or None if unavailable."""
        try:
            elem = dataset[_PIXEL_DATA_TAG]
            value = elem.value
            return bytes(value) if value else None
        except (KeyError, AttributeError, TypeError):
            return None

    def _make_rle_frame(self, dataset: Dataset) -> bytes | None:
        """Build a valid DICOM RLE frame from the dataset's pixel data."""
        raw = self._extract_pixel_bytes(dataset)
        if not raw:
            return None
        bits_alloc = int(getattr(dataset, "BitsAllocated", 8))
        samples = int(getattr(dataset, "SamplesPerPixel", 1))
        return _encode_rle_frame(raw, bits_alloc, samples)

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    def _reencode_valid_then_flip(self, dataset: Dataset) -> Dataset:
        """Re-encode as valid RLE Lossless, then flip one byte in segment data.

        The 64-byte RLE header is left intact so the decoder can locate
        segments. One byte inside the segment data is XOR'd, which causes the
        codec to produce garbage pixel values or a fault during IDCT/RLE
        decoding rather than being caught at the structural level.
        """
        rle_frame = self._make_rle_frame(dataset)
        if rle_frame is None:
            return dataset

        frame_ba = bytearray(rle_frame)
        # Only flip bytes in segment data (after the 64-byte header)
        if len(frame_ba) > 65:
            flip_pos = random.randint(64, len(frame_ba) - 1)
            frame_ba[flip_pos] ^= random.randint(1, 0xFF)

        encapsulated = encapsulate([bytes(frame_ba)])
        dataset.add_new(_PIXEL_DATA_TAG, "OB", encapsulated)
        if hasattr(dataset, "file_meta"):
            dataset.file_meta.TransferSyntaxUID = RLELossless
        return dataset

    def _reencode_corrupt_segment_count(self, dataset: Dataset) -> Dataset:
        """Re-encode as valid RLE, then overwrite the segment count field.

        Bytes 0-3 of the RLE header declare the number of segments. Setting
        this to an inflated value causes the decoder to read segment offsets
        and data that do not exist, triggering out-of-bounds reads.
        """
        rle_frame = self._make_rle_frame(dataset)
        if rle_frame is None:
            return dataset

        frame_ba = bytearray(rle_frame)
        # Overwrite segment count with a value far above the actual count
        bogus_count = random.randint(10, 255)
        struct.pack_into("<I", frame_ba, 0, bogus_count)

        encapsulated = encapsulate([bytes(frame_ba)])
        dataset.add_new(_PIXEL_DATA_TAG, "OB", encapsulated)
        if hasattr(dataset, "file_meta"):
            dataset.file_meta.TransferSyntaxUID = RLELossless
        return dataset

    def _reencode_wrong_syntax(self, dataset: Dataset) -> Dataset:
        """Re-encode as valid RLE, then declare JPEG as the transfer syntax.

        The pixel data contains a syntactically valid DICOM RLE frame, but the
        file declares JPEGBaseline8Bit. A viewer that dispatches based solely on
        the transfer syntax UID will route the RLE bytes through its JPEG
        decoder, hitting unexpected byte patterns (RLE header bytes are not
        valid JPEG markers).
        """
        rle_frame = self._make_rle_frame(dataset)
        if rle_frame is None:
            return dataset

        encapsulated = encapsulate([rle_frame])
        dataset.add_new(_PIXEL_DATA_TAG, "OB", encapsulated)
        if hasattr(dataset, "file_meta"):
            dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit
        return dataset
