"""Compressed Pixel Data Fuzzer - JPEG/JPEG2000/RLE Encapsulation Mutations.

Category: generic

Dataset-level attacks:
- JPEG marker corruption and dimension manipulation
- JPEG 2000 codestream corruption
- RLE segment corruption
- Fragment offset table corruption
- Encapsulation structure violations (missing delimiters, wrong tags, nesting)
- Malformed frame injection and frame count mismatch

Binary-level attacks (mutate_bytes):
- Ultra-short fragment (CVE-2025-11266)
- Remove sequence delimiter (fo-dicom #1339)
- Delimiter embedded in fragment content (pydicom #1140)
- Zero-length final fragment (fo-dicom #1586)
- Orphan delimiter at EOF (fo-dicom #1958)
- Fragment offset underflow (CVE-2025-11266 arithmetic)
"""

from __future__ import annotations

import random
import struct
from typing import NamedTuple

from pydicom.dataset import Dataset
from pydicom.encaps import encapsulate
from pydicom.tag import Tag
from pydicom.uid import (
    JPEG2000Lossless,
    JPEGBaseline8Bit,
    JPEGLSLossless,
    RLELossless,
)

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# JPEG markers
JPEG_SOI = b"\xff\xd8"  # Start of Image
JPEG_EOI = b"\xff\xd9"  # End of Image
JPEG_SOF0 = b"\xff\xc0"  # Baseline DCT
JPEG_DHT = b"\xff\xc4"  # Define Huffman Table
JPEG_APP0 = b"\xff\xe0"  # JFIF marker

# JPEG 2000 markers
JP2_SOC = b"\xff\x4f"  # Start of codestream
JP2_SIZ = b"\xff\x51"  # Image and tile size
JP2_COD = b"\xff\x52"  # Coding style default
JP2_EOC = b"\xff\xd9"  # End of codestream

# JPEG-LS markers
JPLS_SOF55 = b"\xff\xf7"  # JPEG-LS Start of Frame
JPLS_LSE = b"\xff\xf8"  # JPEG-LS Preset Parameters
JPLS_SOS = b"\xff\xda"  # Start of Scan (shared with JPEG)

# DICOM encapsulated pixel data binary constants
_PIXEL_DATA_TAG = b"\xe0\x7f\x10\x00"  # (7FE0,0010) little-endian
_ITEM_TAG = b"\xfe\xff\x00\xe0"  # (FFFE,E000) Item
_SEQ_DELIM = b"\xfe\xff\xdd\xe0"  # (FFFE,E0DD) Sequence Delimitation
_ITEM_DELIM = b"\xfe\xff\x0d\xe0"  # (FFFE,E00D) Item Delimitation
_UNDEFINED_LENGTH = b"\xff\xff\xff\xff"
_DICM_MAGIC = b"DICM"
_DICM_OFFSET = 128
_DATA_OFFSET = 132  # preamble (128) + "DICM" (4)


class EncapsRegion(NamedTuple):
    """Byte-offset map of an encapsulated Pixel Data element."""

    bot_offset: int  # offset of first Item tag (BOT)
    bot_length: int  # BOT item value length (may be 0)
    first_fragment_offset: int  # offset of first data fragment Item tag
    seq_delim_offset: int  # offset of Sequence Delimitation tag, or -1


def _find_encapsulated_region(file_data: bytes) -> EncapsRegion | None:
    """Locate the encapsulated Pixel Data region in raw DICOM bytes.

    Scans for the Pixel Data tag (7FE0,0010) with undefined length,
    handling both Explicit VR (OB/OW + reserved + 4-byte length = 12 bytes
    header) and Implicit VR (4-byte length = 8 bytes header).

    Returns an ``EncapsRegion`` describing the BOT and fragment layout,
    or ``None`` if no encapsulated pixel data is found.
    """
    # Find the last occurrence of the Pixel Data tag (main dataset, not nested)
    idx = file_data.rfind(_PIXEL_DATA_TAG)
    if idx < 0:
        return None

    pos = idx + 4  # past the 4-byte tag

    # Determine Explicit VR vs Implicit VR.
    # In Explicit VR the next 2 bytes are a VR string (e.g. "OB", "OW").
    if pos + 2 <= len(file_data) and file_data[pos : pos + 2] in (b"OB", b"OW"):
        # Explicit VR long-form: VR(2) + reserved(2) + length(4)
        pos += 2 + 2  # skip VR + reserved
    # else: Implicit VR: length(4) immediately follows the tag

    if pos + 4 > len(file_data):
        return None
    length_bytes = file_data[pos : pos + 4]
    if length_bytes != _UNDEFINED_LENGTH:
        return None  # definite-length pixel data -- not encapsulated
    pos += 4  # past the undefined-length field

    # pos now points to the first Item tag (BOT).
    if pos + 8 > len(file_data):
        return None
    if file_data[pos : pos + 4] != _ITEM_TAG:
        return None  # expected BOT Item tag

    bot_offset = pos
    bot_length = struct.unpack_from("<I", file_data, pos + 4)[0]
    first_fragment_offset = bot_offset + 8 + bot_length

    # Scan forward for the Sequence Delimitation Item.
    seq_delim_offset = file_data.find(_SEQ_DELIM, first_fragment_offset)

    return EncapsRegion(
        bot_offset=bot_offset,
        bot_length=bot_length,
        first_fragment_offset=first_fragment_offset,
        seq_delim_offset=seq_delim_offset,
    )


class CompressedPixelFuzzer(FormatFuzzerBase):
    """Fuzzes compressed/encapsulated pixel data.

    Targets the encoding-specific aspects of compressed images
    and the DICOM encapsulation layer that wraps them.
    """

    def __init__(self) -> None:
        """Initialize the compressed pixel fuzzer."""
        super().__init__()
        self.mutation_strategies = [
            self._corrupt_jpeg_markers,  # [STRUCTURAL] marker corruption → infinite loop / buffer overflow in codec
            self._corrupt_jpeg_dimensions,  # [STRUCTURAL] SOF vs DICOM Rows/Columns mismatch → allocation error
            self._corrupt_jpeg2000_codestream,  # [STRUCTURAL] SIZ/COD marker corruption → codestream parser crash
            self._corrupt_rle_segments,  # [STRUCTURAL] wrong segment counts/offsets → out-of-bounds reads
            self._corrupt_fragment_offsets,  # [STRUCTURAL] invalid Basic Offset Table → random memory access
            self._corrupt_encapsulation_structure,  # [STRUCTURAL] wrong Item/Delimiter tags break encapsulation parser
            self._inject_malformed_frame,  # [STRUCTURAL] bad frame among valid frames — per-frame allocator
            self._frame_count_mismatch,  # [STRUCTURAL] declared frames vs actual encapsulated frames — allocation mismatch
            self._corrupt_jpegls_codestream,  # [STRUCTURAL] JPEG-LS decoder memory corruption (CVE-2025-2357)
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "compressed_pixel"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply compressed pixel data mutations.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with compressed pixel corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)
        self.last_variant = ",".join(s.__name__ for s in selected)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("Compressed pixel mutation failed: %s", e)

        return dataset

    def _corrupt_jpeg_markers(self, dataset: Dataset) -> Dataset:
        """Corrupt JPEG markers in compressed pixel data.

        JPEG parsers rely on markers (0xFF followed by marker type).
        Corrupted markers can cause:
        - Infinite loops looking for EOI
        - Buffer overflows reading marker lengths
        - Crashes on unexpected marker sequences
        """
        attack = random.choice(
            [
                "missing_eoi",
                "duplicate_soi",
                "invalid_marker",
                "marker_length_overflow",
                "truncated_marker",
            ]
        )

        try:
            frames: list[bytes] = []

            if attack == "missing_eoi":
                # Create JPEG without End of Image marker
                fake_jpeg = JPEG_SOI + JPEG_APP0 + b"\x00\x10JFIF\x00" + b"\x00" * 100
                frames = [fake_jpeg]  # Missing EOI

            elif attack == "duplicate_soi":
                # Multiple Start of Image markers
                fake_jpeg = JPEG_SOI + JPEG_SOI + JPEG_SOI + JPEG_EOI
                frames = [fake_jpeg]

            elif attack == "invalid_marker":
                # Invalid marker bytes
                fake_jpeg = JPEG_SOI + b"\xff\x01" + b"\x00" * 50 + JPEG_EOI
                frames = [fake_jpeg]

            elif attack == "marker_length_overflow":
                # Marker with length field causing overflow
                # Length field is 2 bytes, big endian
                fake_jpeg = (
                    JPEG_SOI
                    + JPEG_APP0
                    + b"\xff\xff"  # Length = 65535
                    + b"X" * 100  # Not enough data
                    + JPEG_EOI
                )
                frames = [fake_jpeg]

            elif attack == "truncated_marker":
                # Truncated at marker
                fake_jpeg = JPEG_SOI + JPEG_DHT + b"\x00"  # Length incomplete
                frames = [fake_jpeg]

            # Encapsulate and set as pixel data
            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            # Set transfer syntax to JPEG
            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug("JPEG marker corruption failed: %s", e)

        return dataset

    def _corrupt_jpeg_dimensions(self, dataset: Dataset) -> Dataset:
        """Corrupt JPEG frame dimensions in SOF marker.

        The SOF marker contains image dimensions. Mismatches between
        JPEG dimensions and DICOM Rows/Columns can cause crashes.
        """
        try:
            # Create JPEG with dimensions that don't match DICOM headers
            height = random.choice([0, 1, 65535, 32768])
            width = random.choice([0, 1, 65535, 32768])

            # SOF0 marker structure: FF C0 LL LL PP HH HH WW WW
            # LL = length, PP = precision, HH = height, WW = width
            sof_data = struct.pack(">BHHHB", 8, height, width, 3, 0x11)
            sof_marker = JPEG_SOF0 + struct.pack(">H", len(sof_data) + 2) + sof_data

            fake_jpeg = JPEG_SOI + sof_marker + JPEG_EOI
            frames = [fake_jpeg]

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            # Set mismatched DICOM dimensions
            dataset.Rows = random.choice([100, 512, 1024])
            dataset.Columns = random.choice([100, 512, 1024])

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug("JPEG dimension corruption failed: %s", e)

        return dataset

    def _corrupt_jpeg2000_codestream(self, dataset: Dataset) -> Dataset:
        """Corrupt JPEG 2000 codestream markers.

        JPEG2000 has complex marker syntax. Common attack vectors:
        - SIZ marker dimension overflow
        - Invalid tile dimensions
        - Corrupted COD marker
        """
        attack = random.choice(
            [
                "invalid_siz_dimensions",
                "missing_eoc",
                "corrupted_cod",
            ]
        )

        try:
            frames: list[bytes] = []

            if attack == "invalid_siz_dimensions":
                # SIZ marker with extreme dimensions
                siz_data = struct.pack(
                    ">HHIIIIIIIHB",
                    0,  # Rsiz (capabilities)
                    0xFFFF,  # Xsiz (width) - max value
                    0xFFFF,  # Ysiz (height) - max value
                    0,  # XOsiz
                    0,  # YOsiz
                    256,  # XTsiz (tile width)
                    256,  # YTsiz (tile height)
                    0,  # XTOsiz
                    0,  # YTOsiz
                    1,  # Csiz (components)
                    8,  # component params
                )
                fake_jp2 = (
                    JP2_SOC + JP2_SIZ + struct.pack(">H", len(siz_data) + 2) + siz_data
                )
                frames = [fake_jp2]

            elif attack == "missing_eoc":
                # Missing End of Codestream
                fake_jp2 = JP2_SOC + b"\x00" * 100
                frames = [fake_jp2]

            elif attack == "corrupted_cod":
                # Invalid COD marker
                fake_jp2 = JP2_SOC + JP2_COD + b"\x00\x05\xff\xff\xff" + JP2_EOC
                frames = [fake_jp2]

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEG2000Lossless

        except Exception as e:
            logger.debug("JPEG2000 corruption failed: %s", e)

        return dataset

    def _corrupt_rle_segments(self, dataset: Dataset) -> Dataset:
        """Corrupt RLE segment structure.

        RLE Lossless uses segments for each component. Segment count
        and offsets are common sources of vulnerabilities.
        """
        attack = random.choice(
            [
                "wrong_segment_count",
                "invalid_segment_offset",
                "empty_segments",
                "overlapping_segments",
            ]
        )

        try:
            frames: list[bytes] = []

            if attack == "wrong_segment_count":
                # RLE header claims more segments than present
                # Header: 4-byte segment count + 15 segment offsets (4 bytes each)
                header = struct.pack("<I", 10)  # Claims 10 segments
                header += struct.pack("<I", 64) * 15  # But only one offset
                rle_data = header + b"\x00" * 100  # Minimal data
                frames = [rle_data]

            elif attack == "invalid_segment_offset":
                # Segment offset points beyond data
                header = struct.pack("<I", 1)  # 1 segment
                header += struct.pack("<I", 0xFFFFFFFF)  # Invalid offset
                header += struct.pack("<I", 0) * 14
                rle_data = header + b"\x00" * 50
                frames = [rle_data]

            elif attack == "empty_segments":
                # Zero-length segments
                header = struct.pack("<I", 3)  # 3 segments
                header += struct.pack("<I", 64) * 3  # All at same offset
                header += struct.pack("<I", 0) * 12
                rle_data = header + b""  # No actual data
                frames = [rle_data]

            elif attack == "overlapping_segments":
                # Segments that overlap in memory
                header = struct.pack("<I", 2)
                header += struct.pack("<I", 64)  # First segment
                header += struct.pack("<I", 70)  # Overlaps with first
                header += struct.pack("<I", 0) * 13
                rle_data = header + b"\x00" * 100
                frames = [rle_data]

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = RLELossless

        except Exception as e:
            logger.debug("RLE corruption failed: %s", e)

        return dataset

    def _corrupt_jpegls_codestream(self, dataset: Dataset) -> Dataset:
        """Create malformed JPEG-LS codestream data with LS transfer syntax.

        DCMTK CVE-2025-2357 (CWE-119). Memory corruption in the dcmjpls
        JPEG-LS decoder when processing crafted JPEG-LS codestream markers.
        JPEG-LS uses SOF-55 (0xFF 0xF7) for frame header and LSE (0xFF 0xF8)
        for preset parameters, with the same SOI/EOI/SOS markers as JPEG.
        """
        attack = random.choice(
            [
                "truncated_sof55",
                "invalid_lse_params",
                "missing_sos",
                "extreme_dimensions",
            ]
        )

        try:
            if attack == "truncated_sof55":
                # SOF-55 marker with truncated length -- decoder reads past buffer
                fake_jpls = (
                    JPEG_SOI
                    + JPLS_SOF55
                    + b"\x00\x03"  # length=3 (too short for SOF55 which needs >= 11)
                    + b"\x08"  # precision
                    + JPEG_EOI
                )

            elif attack == "invalid_lse_params":
                # LSE marker with garbage preset parameters
                sof55_data = struct.pack(">BHHBB", 8, 64, 64, 1, 1)  # valid SOF-55
                fake_jpls = (
                    JPEG_SOI
                    + JPLS_SOF55
                    + struct.pack(">H", len(sof55_data) + 2)
                    + sof55_data
                    + JPLS_LSE
                    + b"\x00\x04"  # length=4 (too short)
                    + b"\xff\xff"  # garbage preset ID
                    + JPEG_EOI
                )

            elif attack == "missing_sos":
                # Valid SOF-55 but no SOS marker -- decoder expects scan data
                sof55_data = struct.pack(">BHHBB", 8, 64, 64, 1, 1)
                fake_jpls = (
                    JPEG_SOI
                    + JPLS_SOF55
                    + struct.pack(">H", len(sof55_data) + 2)
                    + sof55_data
                    + JPEG_EOI  # EOI without SOS
                )

            elif attack == "extreme_dimensions":
                # SOF-55 with extreme dimensions -> integer overflow in allocation
                sof55_data = struct.pack(">BHHBB", 16, 65535, 65535, 3, 1)
                fake_jpls = (
                    JPEG_SOI
                    + JPLS_SOF55
                    + struct.pack(">H", len(sof55_data) + 2)
                    + sof55_data
                    + b"\x00" * 100  # garbage scan data
                    + JPEG_EOI
                )

            else:
                return dataset

            encapsulated = encapsulate([fake_jpls])
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)
            dataset.NumberOfFrames = 1

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGLSLossless

        except Exception as e:
            logger.debug("JPEG-LS corruption failed: %s", e)

        return dataset

    def _corrupt_fragment_offsets(self, dataset: Dataset) -> Dataset:
        """Corrupt the Basic Offset Table (BOT) for encapsulated data.

        The BOT maps frame numbers to byte offsets. Corrupted offsets
        can cause out-of-bounds reads.
        """
        try:
            # Create frames with invalid offset table
            frames = [JPEG_SOI + b"\x00" * 100 + JPEG_EOI] * 3

            # Manually build encapsulated data with bad BOT
            # Item tag (FFFE,E000), then length, then offsets
            bot_offsets = struct.pack("<III", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
            bot_item = (
                b"\xfe\xff\x00\xe0" + struct.pack("<I", len(bot_offsets)) + bot_offsets
            )

            # Add frame items
            frame_items = b""
            for frame in frames:
                frame_items += (
                    b"\xfe\xff\x00\xe0" + struct.pack("<I", len(frame)) + frame
                )

            # Sequence delimiter
            delimiter = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"

            encapsulated = bot_item + frame_items + delimiter
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug("Fragment offset corruption failed: %s", e)

        return dataset

    def _corrupt_encapsulation_structure(self, dataset: Dataset) -> Dataset:
        """Corrupt the DICOM encapsulation structure itself.

        Encapsulated data uses Item tags (FFFE,E000) and delimiters.
        Malformed structure tests parser robustness.
        """
        attack = random.choice(
            [
                "missing_delimiter",
                "wrong_item_tag",
                "nested_encapsulation",
                "zero_length_fragment",
            ]
        )

        try:
            encapsulated = b""

            if attack == "missing_delimiter":
                # Encapsulated data without SequenceDelimiter
                frame = JPEG_SOI + b"\x00" * 50 + JPEG_EOI
                bot_item = b"\xfe\xff\x00\xe0\x00\x00\x00\x00"  # Empty BOT
                frame_item = b"\xfe\xff\x00\xe0" + struct.pack("<I", len(frame)) + frame
                # No delimiter!
                encapsulated = bot_item + frame_item

            elif attack == "wrong_item_tag":
                # Use wrong tag instead of Item
                frame = JPEG_SOI + b"\x00" * 50 + JPEG_EOI
                bot_item = b"\xfe\xff\x00\xe0\x00\x00\x00\x00"
                # Wrong tag (not FFFE,E000)
                frame_item = b"\x00\x00\x00\x00" + struct.pack("<I", len(frame)) + frame
                delimiter = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
                encapsulated = bot_item + frame_item + delimiter

            elif attack == "nested_encapsulation":
                # Item containing another item structure
                inner_frame = b"\xfe\xff\x00\xe0\x00\x00\x00\x00"  # Nested item
                bot_item = b"\xfe\xff\x00\xe0\x00\x00\x00\x00"
                frame_item = (
                    b"\xfe\xff\x00\xe0"
                    + struct.pack("<I", len(inner_frame))
                    + inner_frame
                )
                delimiter = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
                encapsulated = bot_item + frame_item + delimiter

            elif attack == "zero_length_fragment":
                # Fragment with zero length
                bot_item = b"\xfe\xff\x00\xe0\x00\x00\x00\x00"
                frame_item = b"\xfe\xff\x00\xe0\x00\x00\x00\x00"  # Zero length
                delimiter = b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"
                encapsulated = bot_item + frame_item + delimiter

            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug("Encapsulation structure corruption failed: %s", e)

        return dataset

    def _inject_malformed_frame(self, dataset: Dataset) -> Dataset:
        """Inject a malformed frame into multi-frame data.

        One bad frame among valid frames tests per-frame error handling.
        """
        try:
            valid_frame = JPEG_SOI + JPEG_EOI
            malformed_frames = [
                b"\x00" * 100,  # No JPEG structure
                JPEG_SOI + b"\xff\x00" * 50,  # Escape sequences only
                b"\xff" * 200,  # All 0xFF (ambiguous markers)
            ]

            frames = [
                valid_frame,
                random.choice(malformed_frames),
                valid_frame,
            ]

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)
            dataset.NumberOfFrames = 3

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug("Malformed frame injection failed: %s", e)

        return dataset

    def _frame_count_mismatch(self, dataset: Dataset) -> Dataset:
        """Create mismatch between NumberOfFrames and actual fragments.

        NumberOfFrames metadata may not match actual encapsulated frames,
        causing buffer overflows or infinite loops.
        """
        try:
            frame = JPEG_SOI + b"\x00" * 50 + JPEG_EOI

            attack = random.choice(
                [
                    "more_frames_claimed",
                    "fewer_frames_claimed",
                    "zero_frames_claimed",
                ]
            )

            if attack == "more_frames_claimed":
                frames = [frame] * 2
                dataset.NumberOfFrames = 100  # Claims 100, has 2

            elif attack == "fewer_frames_claimed":
                frames = [frame] * 10
                dataset.NumberOfFrames = 1  # Claims 1, has 10

            else:  # zero_frames_claimed
                frames = [frame] * 5
                dataset.NumberOfFrames = 0  # Claims 0

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug("Frame count mismatch failed: %s", e)

        return dataset

    # ------------------------------------------------------------------
    # Binary-level encapsulated pixel data attacks
    #
    # These operate on the raw serialized byte stream *after* dcmwrite(),
    # because pydicom normalizes encapsulation structure on write and
    # cannot express the malformations these attacks require.
    # ------------------------------------------------------------------

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Apply binary-level encapsulated pixel data corruptions.

        Locates the encapsulated Pixel Data element in the serialized
        byte stream and selects 1-2 attacks to apply. Returns file_data
        unchanged if no encapsulated pixel data is found or the file
        is not valid DICOM.
        """
        self._applied_binary_mutations = []

        if len(file_data) < _DATA_OFFSET + 4:
            return file_data
        if file_data[_DICM_OFFSET:_DATA_OFFSET] != _DICM_MAGIC:
            return file_data

        region = _find_encapsulated_region(file_data)
        if region is None:
            return file_data

        binary_attacks = [
            self._binary_ultra_short_fragment,
            self._binary_remove_sequence_delimiter,
            self._binary_delimiter_in_fragment,
            self._binary_zero_length_final_fragment,
            self._binary_orphan_delimiter_at_eof,
            self._binary_fragment_offset_underflow,
            self._binary_null_tag_in_fragment,
        ]
        num = random.randint(1, 2)
        selected = random.sample(binary_attacks, num)
        result = file_data
        for attack in selected:
            try:
                result = attack(result, region)
                self._applied_binary_mutations.append(attack.__name__)
            except Exception as e:
                logger.debug("Binary encaps attack %s failed: %s", attack.__name__, e)
        return result

    def _binary_ultra_short_fragment(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Replace the first data fragment with a 0, 1, or 2-byte payload.

        CVE-2025-11266 (GDCM <= 3.0.24). Fragment parsing arithmetic does
        ``buffer[length - 3]`` which underflows when the fragment has fewer
        than 3 bytes, producing an out-of-bounds write.
        """
        frag_off = region.first_fragment_offset
        if frag_off + 8 > len(file_data):
            return file_data
        if file_data[frag_off : frag_off + 4] != _ITEM_TAG:
            return file_data

        orig_length = struct.unpack_from("<I", file_data, frag_off + 4)[0]
        frag_end = frag_off + 8 + orig_length

        # Pick a short payload variant
        short_payloads = [
            b"",  # length = 0
            b"\xff",  # length = 1
            b"\xff\xd8",  # length = 2 (JPEG SOI)
        ]
        payload = random.choice(short_payloads)
        new_frag = _ITEM_TAG + struct.pack("<I", len(payload)) + payload

        return file_data[:frag_off] + new_frag + file_data[frag_end:]

    def _binary_remove_sequence_delimiter(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Strip the Sequence Delimitation Item from the encapsulated data.

        fo-dicom #1339 (fixed 5.1.4). Without the 8-byte terminator
        ``FE FF DD E0 00 00 00 00`` the parser reads past the end of the
        pixel data into subsequent elements or past EOF.
        """
        if region.seq_delim_offset < 0:
            return file_data
        return (
            file_data[: region.seq_delim_offset]
            + file_data[region.seq_delim_offset + 8 :]
        )

    def _binary_delimiter_in_fragment(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Inject Sequence Delimitation tag bytes inside a fragment's value.

        pydicom #1140. Parsers using ``read_undefined_length_value()``
        scan for the ``FE FF DD E0`` byte pattern; if it appears inside
        a fragment's payload the parser prematurely truncates the data.
        """
        frag_off = region.first_fragment_offset
        if frag_off + 8 > len(file_data):
            return file_data
        if file_data[frag_off : frag_off + 4] != _ITEM_TAG:
            return file_data

        orig_length = struct.unpack_from("<I", file_data, frag_off + 4)[0]
        if orig_length < 4:
            return file_data  # too small to inject into

        value_start = frag_off + 8
        value_end = value_start + orig_length
        if value_end > len(file_data):
            return file_data

        # Inject the sequence delimiter tag bytes at a random position
        inject_pos = random.randint(0, orig_length - 1)
        value = file_data[value_start:value_end]
        poisoned = value[:inject_pos] + _SEQ_DELIM + value[inject_pos:]
        new_length = struct.pack("<I", len(poisoned))
        new_frag = _ITEM_TAG + new_length + poisoned

        return file_data[:frag_off] + new_frag + file_data[value_end:]

    def _binary_zero_length_final_fragment(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Insert a zero-length fragment Item just before the Sequence Delimiter.

        fo-dicom #1586. An empty (0-length) fragment causes an empty
        allocation or null-pointer dereference in per-fragment decode loops
        that assume every fragment contains at least some data.
        """
        if region.seq_delim_offset < 0:
            return file_data

        empty_frag = _ITEM_TAG + b"\x00\x00\x00\x00"  # 8 bytes: tag + length=0
        pos = region.seq_delim_offset
        return file_data[:pos] + empty_frag + file_data[pos:]

    def _binary_orphan_delimiter_at_eof(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Append a raw delimiter tag after the entire dataset.

        fo-dicom #1958. Delimiter bytes outside any sequence context cause
        the parser to re-enter the sequence state machine unexpectedly,
        leading to use-after-free or state corruption.
        """
        orphan = random.choice([_SEQ_DELIM, _ITEM_DELIM])
        return file_data + orphan

    def _binary_fragment_offset_underflow(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Set a Basic Offset Table entry to a value larger than the data.

        CVE-2025-11266 arithmetic pattern. When the parser subtracts
        fragment header sizes from the declared offset, the result
        underflows (unsigned), producing a huge buffer index that reads
        or writes out of bounds.
        """
        if region.bot_length < 4:
            return file_data  # empty BOT, nothing to corrupt

        bot_value_start = region.bot_offset + 8  # past Item tag + length
        num_entries = region.bot_length // 4
        entry_idx = random.randrange(num_entries)
        entry_offset = bot_value_start + entry_idx * 4

        if entry_offset + 4 > len(file_data):
            return file_data

        # Value must exceed total encapsulated data size so the parser
        # underflows when subtracting fragment header sizes from it.
        total_size = len(file_data) - region.bot_offset
        overflow_value = random.choice(
            [
                total_size + 0x10000,  # modest overflow
                0x7FFFFFFF,  # half uint32 max
                0xFFFFFFFE,  # near uint32 max
            ]
        )

        result = bytearray(file_data)
        struct.pack_into("<I", result, entry_offset, overflow_value)
        return bytes(result)

    def _binary_null_tag_in_fragment(
        self, file_data: bytes, region: EncapsRegion
    ) -> bytes:
        """Replace the first fragment's Item tag with a null tag (0000,0000).

        fo-dicom #763. Inside encapsulated PixelData the parser scans for
        Item tags ``(FFFE,E000)`` and the Sequence Delimitation Item
        ``(FFFE,E0DD)``. A null tag (0000,0000) is neither, but it has a
        valid 8-byte tag+length header; parsers that don't validate the
        tag value can dereference uninitialized state or throw
        DicomFileException unhandled, taking down the host process.

        Replaces only the 4-byte Item tag at the first fragment's
        position, keeping the original length and payload so the byte
        layout remains parseable up to the corrupted tag.
        """
        frag_off = region.first_fragment_offset
        if frag_off + 8 > len(file_data):
            return file_data
        if file_data[frag_off : frag_off + 4] != _ITEM_TAG:
            return file_data
        result = bytearray(file_data)
        result[frag_off : frag_off + 4] = b"\x00\x00\x00\x00"
        return bytes(result)
