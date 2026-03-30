"""Tests for pixel_reencoding_fuzzer.py.

Verifies that PixelReencodingFuzzer:
- Only operates on uncompressed datasets that have pixel data + dimensions
- Produces valid encapsulated output with the correct transfer syntax
- Each strategy mutates the dataset in the documented way
- The pure-Python PackBits helpers compress and expand correctly
"""

import struct

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import (
    ExplicitVRLittleEndian,
    JPEG2000Lossless,
    JPEGBaseline8Bit,
    RLELossless,
)

from dicom_fuzzer.attacks.format.pixel_reencoding_fuzzer import (
    PixelReencodingFuzzer,
    _encode_rle_frame,
    _packbits_encode,
)

_PIXEL_DATA_TAG = Tag(0x7FE0, 0x0010)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pixel_bytes(
    rows: int = 4, cols: int = 4, bits: int = 8, samples: int = 1
) -> bytes:
    """Return a simple ramp pattern as raw pixel bytes."""
    total = rows * cols * samples * (bits // 8)
    return bytes(i % 256 for i in range(total))


def _make_uncompressed_dataset(
    rows: int = 4,
    cols: int = 4,
    bits: int = 8,
    samples: int = 1,
) -> Dataset:
    """Return a minimal uncompressed Dataset with pixel data."""
    ds = Dataset()
    ds.Rows = rows
    ds.Columns = cols
    ds.BitsAllocated = bits
    ds.SamplesPerPixel = samples
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    pixel_bytes = _make_pixel_bytes(rows, cols, bits, samples)
    ds.add_new(_PIXEL_DATA_TAG, "OB", pixel_bytes)
    return ds


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fuzzer() -> PixelReencodingFuzzer:
    return PixelReencodingFuzzer()


@pytest.fixture
def uncompressed_ds() -> Dataset:
    return _make_uncompressed_dataset()


@pytest.fixture
def compressed_ds() -> Dataset:
    """Dataset with a compressed transfer syntax (should be skipped)."""
    ds = _make_uncompressed_dataset()
    ds.file_meta.TransferSyntaxUID = JPEG2000Lossless
    return ds


@pytest.fixture
def no_pixel_ds() -> Dataset:
    """Dataset with dimensions but no PixelData tag."""
    ds = Dataset()
    ds.Rows = 4
    ds.Columns = 4
    ds.BitsAllocated = 8
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    return ds


# ---------------------------------------------------------------------------
# Initialization and interface
# ---------------------------------------------------------------------------


class TestInit:
    def test_strategy_name(self, fuzzer: PixelReencodingFuzzer) -> None:
        assert fuzzer.strategy_name == "pixel_reencoding"

    def test_three_strategies(self, fuzzer: PixelReencodingFuzzer) -> None:
        assert len(fuzzer.mutation_strategies) == 3
        for s in fuzzer.mutation_strategies:
            assert callable(s)


# ---------------------------------------------------------------------------
# can_mutate guard
# ---------------------------------------------------------------------------


class TestCanMutate:
    def test_uncompressed_returns_true(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        assert fuzzer.can_mutate(uncompressed_ds) is True

    def test_compressed_returns_false(
        self, fuzzer: PixelReencodingFuzzer, compressed_ds: Dataset
    ) -> None:
        assert fuzzer.can_mutate(compressed_ds) is False

    def test_no_pixel_data_returns_false(
        self, fuzzer: PixelReencodingFuzzer, no_pixel_ds: Dataset
    ) -> None:
        assert fuzzer.can_mutate(no_pixel_ds) is False

    def test_missing_rows_returns_false(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        del uncompressed_ds.Rows
        assert fuzzer.can_mutate(uncompressed_ds) is False

    def test_missing_bits_allocated_returns_false(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        del uncompressed_ds.BitsAllocated
        assert fuzzer.can_mutate(uncompressed_ds) is False

    def test_implicit_vr_le_returns_true(self, fuzzer: PixelReencodingFuzzer) -> None:
        ds = _make_uncompressed_dataset()
        ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"  # Implicit VR LE
        assert fuzzer.can_mutate(ds) is True

    def test_no_file_meta_defaults_to_explicit_vr_le(
        self, fuzzer: PixelReencodingFuzzer
    ) -> None:
        """No file_meta → assumed Explicit VR LE (uncompressed) → can mutate."""
        ds = Dataset()
        ds.Rows = 4
        ds.Columns = 4
        ds.BitsAllocated = 8
        ds.add_new(_PIXEL_DATA_TAG, "OB", _make_pixel_bytes())
        assert fuzzer.can_mutate(ds) is True


# ---------------------------------------------------------------------------
# mutate() general contract
# ---------------------------------------------------------------------------


class TestMutateContract:
    def test_returns_dataset(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer.mutate(uncompressed_ds)
        assert isinstance(result, Dataset)

    def test_last_variant_set(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        fuzzer.mutate(uncompressed_ds)
        assert fuzzer.last_variant is not None
        assert len(fuzzer.last_variant) > 0

    def test_pixel_data_present_after_mutate(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer.mutate(uncompressed_ds)
        assert _PIXEL_DATA_TAG in result


# ---------------------------------------------------------------------------
# _reencode_valid_then_flip
# ---------------------------------------------------------------------------


class TestReencodeValidThenFlip:
    def test_sets_rle_transfer_syntax(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer._reencode_valid_then_flip(uncompressed_ds)
        assert result.file_meta.TransferSyntaxUID == RLELossless

    def test_pixel_data_differs_from_original(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        original_pixels = bytes(uncompressed_ds[_PIXEL_DATA_TAG].value)
        result = fuzzer._reencode_valid_then_flip(uncompressed_ds)
        # Re-encoded data is encapsulated — not the same raw bytes
        new_pixels = bytes(result[_PIXEL_DATA_TAG].value)
        assert new_pixels != original_pixels

    def test_pixel_data_is_bytes(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer._reencode_valid_then_flip(uncompressed_ds)
        assert isinstance(result[_PIXEL_DATA_TAG].value, (bytes, bytearray))


# ---------------------------------------------------------------------------
# _reencode_corrupt_segment_count
# ---------------------------------------------------------------------------


class TestReencodeCorruptSegmentCount:
    def test_sets_rle_transfer_syntax(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer._reencode_corrupt_segment_count(uncompressed_ds)
        assert result.file_meta.TransferSyntaxUID == RLELossless

    def test_segment_count_is_inflated(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        """The first 4 bytes of the first encapsulated item encode the segment count."""
        result = fuzzer._reencode_corrupt_segment_count(uncompressed_ds)
        raw = bytes(result[_PIXEL_DATA_TAG].value)
        # DICOM encapsulation: empty BOT item (8 bytes) + item tag+length (8 bytes) + data
        # Skip BOT item (FFFE,E000 + 4-byte zero length) = 8 bytes
        # Skip item tag+length (FFFE,E000 + 4-byte length) = 8 bytes
        # First 4 bytes of item data = RLE segment count
        rle_data_start = 16
        if len(raw) >= rle_data_start + 4:
            count = struct.unpack_from("<I", raw, rle_data_start)[0]
            assert count >= 10  # The strategy sets bogus_count in range [10, 255]


# ---------------------------------------------------------------------------
# _reencode_wrong_syntax
# ---------------------------------------------------------------------------


class TestReencodeWrongSyntax:
    def test_sets_jpeg_transfer_syntax(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer._reencode_wrong_syntax(uncompressed_ds)
        assert result.file_meta.TransferSyntaxUID == JPEGBaseline8Bit

    def test_pixel_data_is_encapsulated(
        self, fuzzer: PixelReencodingFuzzer, uncompressed_ds: Dataset
    ) -> None:
        result = fuzzer._reencode_wrong_syntax(uncompressed_ds)
        raw = bytes(result[_PIXEL_DATA_TAG].value)
        # Encapsulated data starts with an empty BOT item tag (FFFE,E000)
        assert raw[:4] == b"\xfe\xff\x00\xe0"


# ---------------------------------------------------------------------------
# PackBits helper unit tests
# ---------------------------------------------------------------------------


class TestPackbitsEncode:
    def test_literal_run(self) -> None:
        data = bytes(range(8))  # All different
        encoded = _packbits_encode(data)
        # Should start with a literal-run header byte (value = count - 1)
        assert len(encoded) > 0
        assert encoded[0] < 128  # Literal run marker

    def test_run_length(self) -> None:
        data = b"\xab" * 8
        encoded = _packbits_encode(data)
        # Run of 8 identical bytes → 2 bytes: marker + byte
        assert len(encoded) == 2
        # Marker for run of 8: (257 - 8) & 0xFF = 249
        assert encoded[0] == (257 - 8) & 0xFF
        assert encoded[1] == 0xAB

    def test_single_byte(self) -> None:
        data = b"\x00"
        encoded = _packbits_encode(data)
        assert len(encoded) == 2  # Literal-run header + byte
        assert encoded[0] == 0  # 1 literal byte → header = 0

    def test_empty_input(self) -> None:
        assert _packbits_encode(b"") == b""


# ---------------------------------------------------------------------------
# _encode_rle_frame helper unit tests
# ---------------------------------------------------------------------------


class TestEncodeRleFrame:
    def test_header_is_64_bytes(self) -> None:
        pixel_bytes = _make_pixel_bytes(4, 4, 8, 1)
        rle = _encode_rle_frame(pixel_bytes, 8, 1)
        assert len(rle) >= 64

    def test_segment_count_field(self) -> None:
        """8-bit grayscale → 1 segment."""
        pixel_bytes = _make_pixel_bytes(4, 4, 8, 1)
        rle = _encode_rle_frame(pixel_bytes, 8, 1)
        count = struct.unpack_from("<I", rle, 0)[0]
        assert count == 1

    def test_16bit_segment_count(self) -> None:
        """16-bit grayscale → 2 segments (high byte, low byte)."""
        pixel_bytes = _make_pixel_bytes(4, 4, 16, 1)
        rle = _encode_rle_frame(pixel_bytes, 16, 1)
        count = struct.unpack_from("<I", rle, 0)[0]
        assert count == 2

    def test_first_segment_offset_is_64(self) -> None:
        """First segment always starts immediately after the 64-byte header."""
        pixel_bytes = _make_pixel_bytes(4, 4, 8, 1)
        rle = _encode_rle_frame(pixel_bytes, 8, 1)
        offset = struct.unpack_from("<I", rle, 4)[0]
        assert offset == 64
