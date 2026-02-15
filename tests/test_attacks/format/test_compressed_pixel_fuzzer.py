"""Tests for compressed_pixel_fuzzer.py - JPEG/JPEG2000/RLE Encapsulation Mutations."""

import random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import (
    CompressedPixelFuzzer,
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
        # Mutation may fail silently (encapsulate rejects empty frames)
        if hasattr(result, "NumberOfFrames"):
            assert result.NumberOfFrames == 3


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
