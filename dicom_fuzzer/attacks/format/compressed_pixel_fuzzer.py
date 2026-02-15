"""Compressed Pixel Data Fuzzer - JPEG/JPEG2000/RLE Encapsulation Mutations.

Targets compressed pixel data formats commonly used in medical imaging:
- JPEG Baseline (Transfer Syntax 1.2.840.10008.1.2.4.50)
- JPEG Lossless (Transfer Syntax 1.2.840.10008.1.2.4.70)
- JPEG 2000 (Transfer Syntax 1.2.840.10008.1.2.4.90/91)
- RLE Lossless (Transfer Syntax 1.2.840.10008.1.2.5)

Encapsulated data is wrapped in fragment items. Corrupting the structure
or codec-specific data can trigger vulnerabilities in image decoders.

Common vulnerabilities:
- Buffer overflow in JPEG marker parsing
- Integer overflow in JPEG2000 tile dimensions
- RLE segment count mismatches
- Fragment offset table corruption
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset
from pydicom.encaps import encapsulate
from pydicom.tag import Tag
from pydicom.uid import (
    JPEG2000Lossless,
    JPEGBaseline8Bit,
    RLELossless,
)

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# JPEG markers
JPEG_SOI = b"\xff\xd8"  # Start of Image
JPEG_EOI = b"\xff\xd9"  # End of Image
JPEG_SOF0 = b"\xff\xc0"  # Baseline DCT
JPEG_SOF2 = b"\xff\xc2"  # Progressive DCT
JPEG_DHT = b"\xff\xc4"  # Define Huffman Table
JPEG_DQT = b"\xff\xdb"  # Define Quantization Table
JPEG_SOS = b"\xff\xda"  # Start of Scan
JPEG_APP0 = b"\xff\xe0"  # JFIF marker

# JPEG 2000 markers
JP2_SOC = b"\xff\x4f"  # Start of codestream
JP2_SIZ = b"\xff\x51"  # Image and tile size
JP2_COD = b"\xff\x52"  # Coding style default
JP2_EOC = b"\xff\xd9"  # End of codestream


class CompressedPixelFuzzer(FormatFuzzerBase):
    """Fuzzes compressed/encapsulated pixel data.

    Targets the encoding-specific aspects of compressed images
    and the DICOM encapsulation layer that wraps them.
    """

    def __init__(self) -> None:
        """Initialize the compressed pixel fuzzer."""
        super().__init__()
        self.mutation_strategies = [
            self._corrupt_jpeg_markers,
            self._corrupt_jpeg_dimensions,
            self._corrupt_jpeg2000_codestream,
            self._corrupt_rle_segments,
            self._corrupt_fragment_offsets,
            self._corrupt_encapsulation_structure,
            self._inject_malformed_frame,
            self._frame_count_mismatch,
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

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug(f"Compressed pixel mutation failed: {e}")

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

            else:
                return dataset

            # Encapsulate and set as pixel data
            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            # Set transfer syntax to JPEG
            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug(f"JPEG marker corruption failed: {e}")

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
            logger.debug(f"JPEG dimension corruption failed: {e}")

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

            else:
                return dataset

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEG2000Lossless

        except Exception as e:
            logger.debug(f"JPEG2000 corruption failed: {e}")

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

            else:
                return dataset

            encapsulated = encapsulate(frames)
            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = RLELossless

        except Exception as e:
            logger.debug(f"RLE corruption failed: {e}")

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
            logger.debug(f"Fragment offset corruption failed: {e}")

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

            else:
                return dataset

            dataset.add_new(Tag(0x7FE0, 0x0010), "OB", encapsulated)

            if hasattr(dataset, "file_meta"):
                dataset.file_meta.TransferSyntaxUID = JPEGBaseline8Bit

        except Exception as e:
            logger.debug(f"Encapsulation structure corruption failed: {e}")

        return dataset

    def _inject_malformed_frame(self, dataset: Dataset) -> Dataset:
        """Inject a malformed frame into multi-frame data.

        One bad frame among valid frames tests per-frame error handling.
        """
        try:
            valid_frame = JPEG_SOI + JPEG_EOI
            malformed_frames = [
                b"",  # Empty
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
            logger.debug(f"Malformed frame injection failed: {e}")

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
            logger.debug(f"Frame count mismatch failed: {e}")

        return dataset
