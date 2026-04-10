"""Tests for compressed_pixel_fuzzer.py - JPEG/JPEG2000/RLE Encapsulation Mutations."""

import io
import random
import struct
from unittest.mock import patch

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.encaps import encapsulate
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian, JPEGBaseline8Bit, generate_uid

from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import (
    _ITEM_DELIM,
    _ITEM_TAG,
    _SEQ_DELIM,
    JPEG_EOI,
    JPEG_SOI,
    CompressedPixelFuzzer,
    EncapsRegion,
    _find_encapsulated_region,
)


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> CompressedPixelFuzzer:
    """Create a CompressedPixelFuzzer instance."""
    return CompressedPixelFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset with file_meta."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Rows = 256
    ds.Columns = 256

    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    return ds


# =============================================================================
# CompressedPixelFuzzer Initialization Tests
# =============================================================================
class TestCompressedPixelFuzzerInit:
    """Tests for CompressedPixelFuzzer initialization."""

    def test_mutation_strategies_defined(self, fuzzer: CompressedPixelFuzzer) -> None:
        """Test that mutation_strategies list is defined."""
        assert hasattr(fuzzer, "mutation_strategies")
        assert isinstance(fuzzer.mutation_strategies, list)
        assert len(fuzzer.mutation_strategies) == 8

    def test_all_strategies_callable(self, fuzzer: CompressedPixelFuzzer) -> None:
        """Test that all strategies are callable methods."""
        for strategy in fuzzer.mutation_strategies:
            assert callable(strategy)


# =============================================================================
# mutate Tests
# =============================================================================
class TestMutateCompressedPixels:
    """Tests for mutate method."""

    def test_returns_dataset(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate returns a Dataset."""
        result = fuzzer.mutate(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_handles_empty_dataset(self, fuzzer: CompressedPixelFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate(ds)
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _corrupt_jpeg_markers Tests
# =============================================================================
class TestCorruptJpegMarkers:
    """Tests for _corrupt_jpeg_markers method."""

    def test_missing_eoi_attack(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test missing EOI attack."""
        with patch.object(random, "choice", return_value="missing_eoi"):
            result = fuzzer._corrupt_jpeg_markers(sample_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x7FE0, 0x0010) in result

    def test_duplicate_soi_attack(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test duplicate SOI attack."""
        with patch.object(random, "choice", return_value="duplicate_soi"):
            result = fuzzer._corrupt_jpeg_markers(sample_dataset)
        assert isinstance(result, Dataset)

    def test_invalid_marker_attack(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test invalid marker attack."""
        with patch.object(random, "choice", return_value="invalid_marker"):
            result = fuzzer._corrupt_jpeg_markers(sample_dataset)
        assert isinstance(result, Dataset)

    def test_marker_length_overflow_attack(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test marker length overflow attack."""
        with patch.object(random, "choice", return_value="marker_length_overflow"):
            result = fuzzer._corrupt_jpeg_markers(sample_dataset)
        assert isinstance(result, Dataset)

    def test_truncated_marker_attack(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test truncated marker attack."""
        with patch.object(random, "choice", return_value="truncated_marker"):
            result = fuzzer._corrupt_jpeg_markers(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _corrupt_jpeg_dimensions Tests
# =============================================================================
class TestCorruptJpegDimensions:
    """Tests for _corrupt_jpeg_dimensions method."""

    def test_creates_dimension_mismatch(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that dimensions are mismatched."""
        result = fuzzer._corrupt_jpeg_dimensions(sample_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x7FE0, 0x0010) in result


# =============================================================================
# _corrupt_jpeg2000_codestream Tests
# =============================================================================
class TestCorruptJpeg2000Codestream:
    """Tests for _corrupt_jpeg2000_codestream method."""

    def test_invalid_siz_dimensions(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test invalid SIZ dimensions attack."""
        with patch.object(random, "choice", return_value="invalid_siz_dimensions"):
            result = fuzzer._corrupt_jpeg2000_codestream(sample_dataset)
        assert isinstance(result, Dataset)

    def test_missing_eoc(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test missing EOC attack."""
        with patch.object(random, "choice", return_value="missing_eoc"):
            result = fuzzer._corrupt_jpeg2000_codestream(sample_dataset)
        assert isinstance(result, Dataset)

    def test_corrupted_cod(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test corrupted COD attack."""
        with patch.object(random, "choice", return_value="corrupted_cod"):
            result = fuzzer._corrupt_jpeg2000_codestream(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _corrupt_rle_segments Tests
# =============================================================================
class TestCorruptRleSegments:
    """Tests for _corrupt_rle_segments method."""

    def test_wrong_segment_count(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test wrong segment count attack."""
        with patch.object(random, "choice", return_value="wrong_segment_count"):
            result = fuzzer._corrupt_rle_segments(sample_dataset)
        assert isinstance(result, Dataset)

    def test_invalid_segment_offset(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test invalid segment offset attack."""
        with patch.object(random, "choice", return_value="invalid_segment_offset"):
            result = fuzzer._corrupt_rle_segments(sample_dataset)
        assert isinstance(result, Dataset)

    def test_empty_segments(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test empty segments attack."""
        with patch.object(random, "choice", return_value="empty_segments"):
            result = fuzzer._corrupt_rle_segments(sample_dataset)
        assert isinstance(result, Dataset)

    def test_overlapping_segments(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test overlapping segments attack."""
        with patch.object(random, "choice", return_value="overlapping_segments"):
            result = fuzzer._corrupt_rle_segments(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _corrupt_fragment_offsets Tests
# =============================================================================
class TestCorruptFragmentOffsets:
    """Tests for _corrupt_fragment_offsets method."""

    def test_creates_bad_offset_table(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test creation of bad offset table."""
        result = fuzzer._corrupt_fragment_offsets(sample_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x7FE0, 0x0010) in result


# =============================================================================
# _corrupt_encapsulation_structure Tests
# =============================================================================
class TestCorruptEncapsulationStructure:
    """Tests for _corrupt_encapsulation_structure method."""

    def test_missing_delimiter(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test missing delimiter attack."""
        with patch.object(random, "choice", return_value="missing_delimiter"):
            result = fuzzer._corrupt_encapsulation_structure(sample_dataset)
        assert isinstance(result, Dataset)

    def test_wrong_item_tag(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test wrong item tag attack."""
        with patch.object(random, "choice", return_value="wrong_item_tag"):
            result = fuzzer._corrupt_encapsulation_structure(sample_dataset)
        assert isinstance(result, Dataset)

    def test_nested_encapsulation(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test nested encapsulation attack."""
        with patch.object(random, "choice", return_value="nested_encapsulation"):
            result = fuzzer._corrupt_encapsulation_structure(sample_dataset)
        assert isinstance(result, Dataset)

    def test_zero_length_fragment(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test zero length fragment attack."""
        with patch.object(random, "choice", return_value="zero_length_fragment"):
            result = fuzzer._corrupt_encapsulation_structure(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _inject_malformed_frame Tests
# =============================================================================
class TestInjectMalformedFrame:
    """Tests for _inject_malformed_frame method."""

    def test_injects_malformed_frame(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test injection of malformed frame."""
        result = fuzzer._inject_malformed_frame(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.NumberOfFrames == 3
        assert Tag(0x7FE0, 0x0010) in result


# =============================================================================
# _frame_count_mismatch Tests
# =============================================================================
class TestFrameCountMismatch:
    """Tests for _frame_count_mismatch method."""

    def test_more_frames_claimed(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test more frames claimed than exist."""
        with patch.object(random, "choice", return_value="more_frames_claimed"):
            result = fuzzer._frame_count_mismatch(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.NumberOfFrames == 100

    def test_fewer_frames_claimed(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test fewer frames claimed than exist."""
        with patch.object(random, "choice", return_value="fewer_frames_claimed"):
            result = fuzzer._frame_count_mismatch(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.NumberOfFrames == 1

    def test_zero_frames_claimed(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test zero frames claimed."""
        with patch.object(random, "choice", return_value="zero_frames_claimed"):
            result = fuzzer._frame_count_mismatch(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.NumberOfFrames == 0


# =============================================================================
# Integration Tests
# =============================================================================
class TestCompressedPixelFuzzerIntegration:
    """Integration tests for CompressedPixelFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_multiple_mutations(
        self, fuzzer: CompressedPixelFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test multiple mutations in sequence."""
        for i in range(5):
            random.seed(i)
            ds = Dataset()
            ds.PatientName = "Test"
            ds.file_meta = FileMetaDataset()
            ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
            result = fuzzer.mutate(ds)
            assert isinstance(result, Dataset)


# =============================================================================
# Binary-level encapsulated pixel data attack tests
# =============================================================================

_FRAME_DATA = JPEG_SOI + b"\x00" * 100 + JPEG_EOI


def _make_encapsulated_dicom_bytes(num_frames: int = 1) -> bytes:
    """Build a minimal valid DICOM file with encapsulated JPEG pixel data."""
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = JPEGBaseline8Bit
    ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.PatientID = "TEST001"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0

    frames = [_FRAME_DATA] * num_frames
    ds.PixelData = encapsulate(frames, has_bot=(num_frames > 1))
    ds.NumberOfFrames = num_frames
    ds["PixelData"].VR = "OB"

    buf = io.BytesIO()
    pydicom.dcmwrite(buf, ds, enforce_file_format=True)
    return buf.getvalue()


class TestFindEncapsulatedRegion:
    """Tests for the _find_encapsulated_region helper."""

    def test_returns_region_for_encapsulated_file(self):
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        assert region is not None
        assert isinstance(region, EncapsRegion)

    def test_returns_none_for_non_dicom(self):
        assert _find_encapsulated_region(b"\x00" * 256) is None

    def test_returns_none_for_no_pixel_data(self):
        ds = Dataset()
        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
        ds.PatientID = "TEST001"
        buf = io.BytesIO()
        pydicom.dcmwrite(buf, ds, enforce_file_format=True)
        assert _find_encapsulated_region(buf.getvalue()) is None

    def test_bot_length_matches_frame_count(self):
        file_data = _make_encapsulated_dicom_bytes(num_frames=3)
        region = _find_encapsulated_region(file_data)
        assert region is not None
        assert region.bot_length == 12  # 3 frames * 4 bytes each

    def test_seq_delim_found(self):
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        assert region is not None
        assert region.seq_delim_offset > 0
        assert (
            file_data[region.seq_delim_offset : region.seq_delim_offset + 4]
            == _SEQ_DELIM
        )

    def test_first_fragment_offset_points_to_item_tag(self):
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        assert region is not None
        assert (
            file_data[region.first_fragment_offset : region.first_fragment_offset + 4]
            == _ITEM_TAG
        )


class TestBinaryUltraShortFragment:
    """Tests for _binary_ultra_short_fragment (CVE-2025-11266)."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_ultra_short_fragment(file_data, region)
        assert isinstance(result, bytes)

    def test_output_shorter_than_input(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_ultra_short_fragment(file_data, region)
        assert len(result) < len(file_data)

    def test_short_fragment_present(self):
        """The mutated file must contain a fragment with length 0, 1, or 2."""
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_ultra_short_fragment(file_data, region)
        frag_off = region.first_fragment_offset
        new_length = struct.unpack_from("<I", result, frag_off + 4)[0]
        assert new_length in (0, 1, 2)

    def test_non_encapsulated_passthrough(self):
        fuzzer = CompressedPixelFuzzer()
        garbage = b"\x00" * 256
        region = EncapsRegion(0, 0, 200, -1)
        assert fuzzer._binary_ultra_short_fragment(garbage, region) is garbage


class TestBinaryRemoveSequenceDelimiter:
    """Tests for _binary_remove_sequence_delimiter (fo-dicom #1339)."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_remove_sequence_delimiter(file_data, region)
        assert isinstance(result, bytes)

    def test_output_8_bytes_shorter(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_remove_sequence_delimiter(file_data, region)
        assert len(result) == len(file_data) - 8

    def test_seq_delim_absent_in_output(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_remove_sequence_delimiter(file_data, region)
        # The 8-byte delimiter should no longer be at its original position
        assert (
            result[region.seq_delim_offset : region.seq_delim_offset + 4] != _SEQ_DELIM
        )

    def test_passthrough_when_no_delimiter(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = b"\x00" * 256
        region = EncapsRegion(0, 0, 50, -1)
        assert fuzzer._binary_remove_sequence_delimiter(file_data, region) is file_data


class TestBinaryDelimiterInFragment:
    """Tests for _binary_delimiter_in_fragment (pydicom #1140)."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_delimiter_in_fragment(file_data, region)
        assert isinstance(result, bytes)

    def test_output_4_bytes_longer(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_delimiter_in_fragment(file_data, region)
        assert len(result) == len(file_data) + 4

    def test_seq_delim_bytes_in_fragment_region(self):
        """The injected delimiter bytes must appear in the fragment value area."""
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_delimiter_in_fragment(file_data, region)
        # The fragment value starts at first_fragment_offset + 8
        frag_value_start = region.first_fragment_offset + 8
        new_length = struct.unpack_from("<I", result, region.first_fragment_offset + 4)[
            0
        ]
        frag_value = result[frag_value_start : frag_value_start + new_length]
        assert _SEQ_DELIM in frag_value

    def test_non_encapsulated_passthrough(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = b"\x00" * 256
        region = EncapsRegion(0, 0, 200, -1)
        assert fuzzer._binary_delimiter_in_fragment(file_data, region) is file_data


class TestBinaryZeroLengthFinalFragment:
    """Tests for _binary_zero_length_final_fragment (fo-dicom #1586)."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_zero_length_final_fragment(file_data, region)
        assert isinstance(result, bytes)

    def test_output_8_bytes_longer(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_zero_length_final_fragment(file_data, region)
        assert len(result) == len(file_data) + 8

    def test_zero_length_item_before_delimiter(self):
        """An 8-byte zero-length Item tag must appear just before the delimiter."""
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_zero_length_final_fragment(file_data, region)
        inserted = result[region.seq_delim_offset : region.seq_delim_offset + 8]
        assert inserted == _ITEM_TAG + b"\x00\x00\x00\x00"

    def test_passthrough_when_no_delimiter(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = b"\x00" * 256
        region = EncapsRegion(0, 0, 50, -1)
        assert fuzzer._binary_zero_length_final_fragment(file_data, region) is file_data


class TestBinaryOrphanDelimiterAtEof:
    """Tests for _binary_orphan_delimiter_at_eof (fo-dicom #1958)."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_orphan_delimiter_at_eof(file_data, region)
        assert isinstance(result, bytes)

    def test_output_4_bytes_longer(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_orphan_delimiter_at_eof(file_data, region)
        assert len(result) == len(file_data) + 4

    def test_trailing_bytes_are_delimiter_tag(self):
        """Last 4 bytes must be either SEQ_DELIM or ITEM_DELIM tag."""
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_orphan_delimiter_at_eof(file_data, region)
        assert result[-4:] in (_SEQ_DELIM, _ITEM_DELIM)


class TestBinaryFragmentOffsetUnderflow:
    """Tests for _binary_fragment_offset_underflow (CVE-2025-11266 arithmetic)."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes(num_frames=3)
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_fragment_offset_underflow(file_data, region)
        assert isinstance(result, bytes)

    def test_length_preserved(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes(num_frames=3)
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_fragment_offset_underflow(file_data, region)
        assert len(result) == len(file_data)

    def test_bot_entry_exceeds_data_size(self):
        """At least one BOT entry must be larger than total encapsulated size."""
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes(num_frames=3)
        region = _find_encapsulated_region(file_data)
        result = fuzzer._binary_fragment_offset_underflow(file_data, region)
        total_size = len(file_data) - region.bot_offset
        bot_start = region.bot_offset + 8
        entries = [
            struct.unpack_from("<I", result, bot_start + i * 4)[0]
            for i in range(region.bot_length // 4)
        ]
        assert any(e > total_size for e in entries)

    def test_passthrough_when_empty_bot(self):
        """Single-frame file with empty BOT must be returned unchanged."""
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes(num_frames=1)
        region = _find_encapsulated_region(file_data)
        assert region is not None
        # Single-frame with has_bot=False -> BOT length=0
        if region.bot_length == 0:
            assert (
                fuzzer._binary_fragment_offset_underflow(file_data, region) is file_data
            )


class TestMutateBytesIntegration:
    """Integration tests for CompressedPixelFuzzer.mutate_bytes."""

    def test_returns_bytes(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        result = fuzzer.mutate_bytes(file_data)
        assert isinstance(result, bytes)

    def test_non_dicom_passthrough(self):
        fuzzer = CompressedPixelFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer.mutate_bytes(garbage) == garbage

    def test_non_encapsulated_passthrough(self):
        """File without encapsulated pixel data must be returned unchanged."""
        ds = Dataset()
        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
        ds.PatientID = "TEST001"
        buf = io.BytesIO()
        pydicom.dcmwrite(buf, ds, enforce_file_format=True)
        file_data = buf.getvalue()
        fuzzer = CompressedPixelFuzzer()
        assert fuzzer.mutate_bytes(file_data) == file_data

    def test_produces_mutation_over_runs(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        changed = any(fuzzer.mutate_bytes(file_data) != file_data for _ in range(30))
        assert changed, "mutate_bytes produced no changes in 30 runs"

    def test_applied_binary_mutations_populated(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        populated = False
        for _ in range(30):
            fuzzer.mutate_bytes(file_data)
            if fuzzer._applied_binary_mutations:
                assert all(isinstance(n, str) for n in fuzzer._applied_binary_mutations)
                populated = True
                break
        assert populated

    def test_applied_binary_mutations_cleared_each_call(self):
        fuzzer = CompressedPixelFuzzer()
        file_data = _make_encapsulated_dicom_bytes()
        fuzzer.mutate_bytes(file_data)
        fuzzer.mutate_bytes(file_data)
        assert len(fuzzer._applied_binary_mutations) <= 2
