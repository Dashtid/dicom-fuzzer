"""Unit Tests for MultiFrameHandler.

Tests the MultiFrameHandler class and its 8 mutation strategies
for multi-frame DICOM (NumberOfFrames > 1) fuzzing.
"""

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.mutation.multiframe_handler import (
    FrameInfo,
    MultiFrameHandler,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
    create_multiframe_mutator,
)


@pytest.fixture
def sample_multiframe_dataset():
    """Create a sample multi-frame DICOM dataset for testing."""
    ds = Dataset()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2.1"  # Enhanced CT
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.Modality = "CT"
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.NumberOfFrames = 10

    # Create pixel data for 10 frames (simplified)
    frame_size = 512 * 512 * 2  # 16-bit pixels
    ds.PixelData = bytes(frame_size * 10)

    # Create per-frame functional groups
    per_frame_groups = []
    for i in range(10):
        fg = Dataset()

        # Plane Position Sequence
        plane_pos = Dataset()
        plane_pos.ImagePositionPatient = [0.0, 0.0, float(i * 5.0)]
        fg.PlanePositionSequence = Sequence([plane_pos])

        # Plane Orientation Sequence
        plane_orient = Dataset()
        plane_orient.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        fg.PlaneOrientationSequence = Sequence([plane_orient])

        # Frame Content Sequence
        frame_content = Dataset()
        frame_content.FrameAcquisitionDateTime = f"2023010112{i:02d}00.000000"
        frame_content.TemporalPositionIndex = i + 1
        fg.FrameContentSequence = Sequence([frame_content])

        per_frame_groups.append(fg)

    ds.PerFrameFunctionalGroupsSequence = Sequence(per_frame_groups)

    # Create shared functional groups
    sfg = Dataset()
    pixel_measures = Dataset()
    pixel_measures.PixelSpacing = [0.5, 0.5]
    pixel_measures.SliceThickness = 5.0
    sfg.PixelMeasuresSequence = Sequence([pixel_measures])
    ds.SharedFunctionalGroupsSequence = Sequence([sfg])

    # Frame time
    ds.FrameTime = 33.33

    return ds


@pytest.fixture
def single_frame_dataset():
    """Create a single-frame dataset for testing."""
    ds = Dataset()
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.10"
    ds.Modality = "CT"
    ds.Rows = 256
    ds.Columns = 256
    ds.BitsAllocated = 16
    ds.SamplesPerPixel = 1
    # No NumberOfFrames = single frame
    ds.PixelData = bytes(256 * 256 * 2)
    return ds


class TestMultiFrameHandlerInitialization:
    """Test MultiFrameHandler initialization."""

    def test_valid_initialization_default(self):
        """Test valid initialization with defaults."""
        handler = MultiFrameHandler()
        assert handler.severity == "moderate"
        assert handler.seed is None

    def test_valid_initialization_with_severity(self):
        """Test initialization with custom severity."""
        handler = MultiFrameHandler(severity="aggressive")
        assert handler.severity == "aggressive"

    def test_valid_initialization_with_seed(self):
        """Test initialization with random seed."""
        handler = MultiFrameHandler(seed=42)
        assert handler.seed == 42

    def test_invalid_severity_raises_error(self):
        """Test that invalid severity raises error."""
        with pytest.raises(ValueError, match="Invalid severity"):
            MultiFrameHandler(severity="invalid")

    def test_factory_function(self):
        """Test create_multiframe_mutator factory."""
        handler = create_multiframe_mutator(severity="extreme", seed=123)
        assert handler.severity == "extreme"
        assert handler.seed == 123


class TestMultiFrameDetection:
    """Test multi-frame detection methods."""

    def test_is_multiframe_true(self, sample_multiframe_dataset):
        """Test is_multiframe returns True for multi-frame dataset."""
        handler = MultiFrameHandler()
        assert handler.is_multiframe(sample_multiframe_dataset) is True

    def test_is_multiframe_false(self, single_frame_dataset):
        """Test is_multiframe returns False for single-frame dataset."""
        handler = MultiFrameHandler()
        assert handler.is_multiframe(single_frame_dataset) is False

    def test_is_multiframe_no_attribute(self):
        """Test is_multiframe returns False when NumberOfFrames is missing."""
        ds = Dataset()
        handler = MultiFrameHandler()
        assert handler.is_multiframe(ds) is False

    def test_get_frame_count(self, sample_multiframe_dataset):
        """Test get_frame_count returns correct count."""
        handler = MultiFrameHandler()
        assert handler.get_frame_count(sample_multiframe_dataset) == 10

    def test_get_frame_count_single(self, single_frame_dataset):
        """Test get_frame_count returns 1 for single-frame."""
        handler = MultiFrameHandler()
        assert handler.get_frame_count(single_frame_dataset) == 1


class TestFrameInfoExtraction:
    """Test frame info extraction."""

    def test_extract_frame_info(self, sample_multiframe_dataset):
        """Test extracting frame info from multi-frame dataset."""
        handler = MultiFrameHandler()
        frames = handler.extract_frame_info(sample_multiframe_dataset)

        assert len(frames) == 10
        assert all(isinstance(f, FrameInfo) for f in frames)
        assert frames[0].frame_number == 1
        assert frames[9].frame_number == 10

    def test_frame_info_positions(self, sample_multiframe_dataset):
        """Test that frame positions are extracted correctly."""
        handler = MultiFrameHandler()
        frames = handler.extract_frame_info(sample_multiframe_dataset)

        # Check first frame position
        assert frames[0].position == (0.0, 0.0, 0.0)
        # Check last frame position
        assert frames[9].position == (0.0, 0.0, 45.0)

    def test_frame_size_calculation(self, sample_multiframe_dataset):
        """Test frame size calculation."""
        handler = MultiFrameHandler()
        frame_size = handler.calculate_frame_size(sample_multiframe_dataset)
        expected_size = 512 * 512 * 2  # 16-bit = 2 bytes per pixel
        assert frame_size == expected_size


class TestFrameCountMismatchMutation:
    """Test frame count mismatch mutation strategy."""

    def test_frame_count_mismatch_basic(self, sample_multiframe_dataset):
        """Test frame count mismatch mutation."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="frame_count_mismatch",
            mutation_count=1,
        )

        assert len(records) >= 1
        assert all(isinstance(r, MultiFrameMutationRecord) for r in records)
        assert records[0].strategy == "frame_count_mismatch"

    def test_frame_count_mismatch_changes_value(self, sample_multiframe_dataset):
        """Test that mutation actually changes NumberOfFrames."""
        original_frames = sample_multiframe_dataset.NumberOfFrames
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="frame_count_mismatch",
            mutation_count=3,
        )

        # Value should be different from original
        assert dataset.NumberOfFrames != original_frames


class TestFrameTimeCorruptionMutation:
    """Test frame time corruption mutation strategy."""

    def test_frame_time_corruption_basic(self, sample_multiframe_dataset):
        """Test frame time corruption mutation."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="frame_time_corruption",
            mutation_count=1,
        )

        assert len(records) >= 1
        assert records[0].strategy == "frame_time_corruption"


class TestDimensionOverflowMutation:
    """Test dimension overflow mutation strategy."""

    def test_dimension_overflow_basic(self, sample_multiframe_dataset):
        """Test dimension overflow mutation."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="dimension_overflow",
            mutation_count=1,
        )

        assert len(records) >= 1
        assert records[0].strategy == "dimension_overflow"


class TestSharedGroupCorruptionMutation:
    """Test shared functional group corruption mutation."""

    def test_shared_group_corruption_basic(self, sample_multiframe_dataset):
        """Test shared group corruption mutation."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="shared_group_corruption",
            mutation_count=1,
        )

        assert len(records) >= 1
        assert records[0].strategy == "shared_group_corruption"


class TestFunctionalGroupAttackMutation:
    """Test functional group attack mutation."""

    def test_functional_group_attack_basic(self, sample_multiframe_dataset):
        """Test functional group attack mutation."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="functional_group_attack",
            mutation_count=1,
        )

        assert len(records) >= 1
        assert records[0].strategy == "functional_group_attack"


class TestPixelDataTruncationMutation:
    """Test pixel data truncation mutation."""

    def test_pixel_data_truncation_basic(self, sample_multiframe_dataset):
        """Test pixel data truncation mutation."""
        original_size = len(sample_multiframe_dataset.PixelData)
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="pixel_data_truncation",
            mutation_count=1,
        )

        assert len(records) >= 1
        assert records[0].strategy == "pixel_data_truncation"
        # Pixel data should be modified
        assert len(dataset.PixelData) != original_size


class TestRandomStrategySelection:
    """Test random strategy selection."""

    def test_random_strategy_selection(self, sample_multiframe_dataset):
        """Test that random strategy is selected when None."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy=None,
            mutation_count=1,
        )

        assert len(records) >= 1
        # Strategy should be one of the valid strategies
        valid_strategies = [s.value for s in MultiFrameMutationStrategy]
        assert records[0].strategy in valid_strategies


class TestMutationRecordSerialization:
    """Test mutation record serialization."""

    def test_record_to_dict(self, sample_multiframe_dataset):
        """Test that records can be serialized to dict."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy="frame_count_mismatch",
            mutation_count=1,
        )

        assert len(records) >= 1
        record_dict = records[0].to_dict()
        assert isinstance(record_dict, dict)
        assert "strategy" in record_dict
        assert "severity" in record_dict


class TestAllStrategies:
    """Test all mutation strategies are accessible."""

    @pytest.mark.parametrize(
        "strategy",
        [
            "frame_count_mismatch",
            "frame_time_corruption",
            "per_frame_dimension_mismatch",
            "shared_group_corruption",
            "frame_increment_invalid",
            "dimension_overflow",
            "functional_group_attack",
            "pixel_data_truncation",
        ],
    )
    def test_all_strategies_work(self, sample_multiframe_dataset, strategy):
        """Test that all defined strategies can be executed."""
        handler = MultiFrameHandler(seed=42)
        dataset, records = handler.mutate(
            sample_multiframe_dataset,
            strategy=strategy,
            mutation_count=1,
        )

        assert dataset is not None
        # Records may be empty for some edge cases, but no exception should occur


class TestInvalidInput:
    """Test handling of invalid input."""

    def test_invalid_strategy_raises_error(self, sample_multiframe_dataset):
        """Test that invalid strategy raises ValueError."""
        handler = MultiFrameHandler()
        with pytest.raises(ValueError, match="Invalid strategy"):
            handler.mutate(
                sample_multiframe_dataset,
                strategy="invalid_strategy",
                mutation_count=1,
            )

    def test_empty_pixel_data_handling(self):
        """Test handling of dataset without pixel data."""
        ds = Dataset()
        ds.NumberOfFrames = 5
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        # No PixelData

        handler = MultiFrameHandler(seed=42)
        # Should not raise an exception
        dataset, records = handler.mutate(
            ds,
            strategy="frame_count_mismatch",
            mutation_count=1,
        )
        assert dataset is not None
